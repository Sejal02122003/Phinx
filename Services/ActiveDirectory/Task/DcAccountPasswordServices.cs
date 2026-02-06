using Phoenix.Core.Services.Authentication;
// --------------------------------------------------------------------------
// <copyright file="DcAccountPasswordService.cs" company="Phoenix IR Platform">
//     © 2026 Phoenix IR Platform. All rights reserved.
//     AD Task: DC Machine Account Password Reset
//     Full PS parity with Set-DCAccountPassword.ps1 (540 lines)
//
//     Validates ONLINE writable DCs (skips RODCs), opens WMI session,
//     runs two nltest password-change cycles per DC (sc_change_pwd),
//     then restarts Netlogon to pick up the new secret.
//     For non-PDC DCs, chains nltest /sc_reset immediately after password
//     change to repair the secure channel before connectivity is lost.
//     Domains ordered Forest Root -> Child -> Tree Root; PDC first within each.
// </copyright>
// --------------------------------------------------------------------------

using System.Diagnostics;
using System.Globalization;
using System.Management;
using Phoenix.Core.Services.MicrosoftAzure.Models;

namespace Phoenix.Core.Services.ActiveDirectory.Tasks;

public class DcAccountPasswordService : IDcAccountPasswordService
{
    private readonly IPhoenixLogger _logger;
    private readonly IAdAuthenticationService _authService;

    public DcAccountPasswordService(IPhoenixLogger logger, IAdAuthenticationService authService)
    {
        _logger = logger;
        _authService = authService;
    }

    // ==========================================================================
    // Public API
    // ==========================================================================

    public Task<DcAccountPasswordResult> AnalyzeAsync(
        IEnumerable<DomainControllerInfo> dcList,
        IProgress<TaskProgressInfo>? progress = null,
        CancellationToken cancellationToken = default)
    {
        return ProcessAsync(dcList, credentials: null, whatIf: true, progress, cancellationToken);
    }

    public Task<DcAccountPasswordResult> ExecuteAsync(
        IEnumerable<DomainControllerInfo> dcList,
        AdCredentials? credentials = null,
        IProgress<TaskProgressInfo>? progress = null,
        CancellationToken cancellationToken = default)
    {
        return ProcessAsync(dcList, credentials, whatIf: false, progress, cancellationToken);
    }

    // ==========================================================================
    // Core Processing - maps to PS begin{} + process{} + end{}
    // ==========================================================================

    private async Task<DcAccountPasswordResult> ProcessAsync(
        IEnumerable<DomainControllerInfo> dcList,
        AdCredentials? credentials,
        bool whatIf,
        IProgress<TaskProgressInfo>? progress,
        CancellationToken cancellationToken)
    {
        var result = new DcAccountPasswordResult { IsWhatIf = whatIf };
        var sw = Stopwatch.StartNew();

        try
        {
            _logger.LogInfo("DcAccountPassword: Starting operation.");
            // ==================================================================
            // PS L131-136: Input Validation
            // ==================================================================
            var dcArray = dcList.ToArray();
            if (dcArray.Length == 0)
            {
                result.Message = "IsolatedDCList is empty.";
                _logger.LogError("IsolatedDCList is empty.");
                return result;
            }

            // ==================================================================
            // PS L178-193: Validate DC List Entries
            // ==================================================================
            foreach (var dc in dcArray)
            {
                var missing = new List<string>();
                if (string.IsNullOrEmpty(dc.FQDN)) missing.Add("FQDN");
                if (string.IsNullOrEmpty(dc.Domain)) missing.Add("Domain");
                if (string.IsNullOrEmpty(dc.Type)) missing.Add("Type");

                if (missing.Count > 0)
                    _logger.LogWarning("Invalid DC entry for {FQDN}: Missing {Missing}",
                        dc.FQDN, string.Join(", ", missing));
            }

            // ==================================================================
            // PS L195-205: Sort and Group DCs by Domain (FR->CD->TR)
            // ==================================================================
            var domainGroups = dcArray
                .OrderBy(dc => dc.Type switch
                {
                    "Forest Root" => 1,
                    "Child Domain" or "Child" => 2,
                    "Tree Root" or "Tree" => 3,
                    _ => 4
                })
                .GroupBy(dc => dc.Domain, StringComparer.OrdinalIgnoreCase)
                .ToList();

            if (domainGroups.Count == 0)
            {
                result.Message = "No eligible domains to process.";
                _logger.LogWarning("No eligible domains to process.");
                return result;
            }

            _logger.LogInfo(
                "Starting DC machine-account password resets across {Count} domain(s) (WhatIf={WhatIf})",
                domainGroups.Count, whatIf);

            // ==================================================================
            // PS L227-507: Process Each Domain
            // ==================================================================
            foreach (var grp in domainGroups)
            {
                cancellationToken.ThrowIfCancellationRequested();

                var domainName = grp.Key;
                result.DomainsProcessed++;

                // ==============================================================
                // PS L233-242: Filter DCs - online writable only (skip RODCs)
                // ==============================================================
                var domainDcs = grp
                    .Where(dc => dc.Online && !dc.IsRODC)
                    .ToList();

                if (domainDcs.Count == 0)
                {
                    _logger.LogError("No online writable DCs for {Domain}. Skipping.", domainName);
                    result.Errors.Add($"No online writable DCs for {domainName}");
                    continue;
                }

                // ==============================================================
                // PS L244-259: Order DCs (PDC first) + capture PDC FQDN
                // ==============================================================
                var pdcDcs = domainDcs.Where(dc => dc.IsPdcRoleOwner || dc.IsPDC).ToList();
                var nonPdcDcs = domainDcs.Where(dc => !dc.IsPdcRoleOwner && !dc.IsPDC).ToList();
                var orderedDcs = pdcDcs.Concat(nonPdcDcs).ToList();

                var pdcFqdn = pdcDcs.FirstOrDefault()?.FQDN;
                if (string.IsNullOrEmpty(pdcFqdn))
                {
                    _logger.LogError(
                        "No PDC found for {Domain}. Cannot safely reset non-PDC secure channels. Skipping domain.",
                        domainName);
                    result.Errors.Add($"No PDC found for {domainName}");
                    continue;
                }

                _logger.LogInfo(
                    "Starting DC password resets for domain {Domain} ({Count} online DCs, PDC={PDC})",
                    domainName, orderedDcs.Count, pdcFqdn);

                var domainStatuses = new List<DcPasswordStatus>();

                // ==============================================================
                // PS L271-503: Process Each DC
                // ==============================================================
                foreach (var dc in orderedDcs)
                {
                    cancellationToken.ThrowIfCancellationRequested();

                    var dcFqdn = dc.FQDN;
                    if (string.IsNullOrEmpty(dcFqdn)) continue;

                    var isPdc = dc.IsPdcRoleOwner || dc.IsPDC;

                    var dcStatus = new DcPasswordStatus
                    {
                        DcFqdn = dcFqdn,
                        IsPdc = isPdc
                    };
                    domainStatuses.Add(dcStatus);

                    result.DcsProcessed++;

                    // ==========================================================
                    // PS L304-364: Password Reset Cycles (2 cycles x 2 retries)
                    // ==========================================================
                    var okAll = true;

                    for (var cycle = 1; cycle <= 2; cycle++)
                    {
                        cancellationToken.ThrowIfCancellationRequested();

                        // PS L311-329: Build Command Line
                        // PDC: nltest /server:{dc} /sc_change_pwd:{domain}
                        // Non-PDC: chain sc_change_pwd + sc_reset via cmd /c
                        string cmdLine;
                        string cmdDescription;

                        if (isPdc)
                        {
                            cmdLine = $@"nltest /server:{dcFqdn} /sc_change_pwd:{domainName}";
                            cmdDescription = "sc_change_pwd";
                        }
                        else
                        {
                            // Chain commands for non-PDC to prevent trust failure between change and reset
                            cmdLine = $@"cmd /c nltest /server:{dcFqdn} /sc_change_pwd:{domainName} && nltest /server:{dcFqdn} /sc_reset:{domainName}";
                            cmdDescription = "sc_change_pwd + sc_reset";
                        }

                        // PS L332-358: Execute Command with Retry
                        var attempt = 0;
                        var ok = false;

                        while (attempt < 2 && !ok)
                        {
                            attempt++;
                            try
                            {
                                if (whatIf)
                                {
                                    _logger.LogInfo("[WhatIf] Would run {Command} on {DC} (cycle {Cycle}, attempt {Attempt})",
                                        cmdDescription, dcFqdn, cycle, attempt);
                                    ok = true; // Simulate success
                                }
                                else
                                {
                                    var rv = RunRemoteProcess(dcFqdn, cmdLine);
                                    if (rv == 0)
                                    {
                                        ok = true;
                                        if (isPdc)
                                            _logger.LogInfo(
                                                "nltest /sc_change_pwd completed on {DC} (PDC, cycle {Cycle}).",
                                                dcFqdn, cycle);
                                        else
                                            _logger.LogInfo(
                                                "nltest /sc_change_pwd + /sc_reset completed on {DC} (cycle {Cycle}).",
                                                dcFqdn, cycle);
                                        break;
                                    }
                                    else
                                    {
                                        if (attempt == 2)
                                            _logger.LogError(
                                                "nltest failed on {DC} (cycle {Cycle}, ReturnValue={RV}).",
                                                dcFqdn, cycle, rv);
                                        else
                                            await Task.Delay(400, cancellationToken);
                                    }
                                }
                            }
                            catch (Exception ex)
                            {
                                if (attempt == 2)
                                    _logger.LogError(
                                        "Password reset failed for {DC} (cycle {Cycle}): {Error}",
                                        dcFqdn, cycle, ex.Message);
                                else
                                    await Task.Delay(400, cancellationToken);
                            }
                        }

                        if (!ok) { okAll = false; break; }

                        // PS: 5-second delay between cycle 1 and cycle 2
                        if (cycle == 1 && !whatIf)
                            await Task.Delay(5000, cancellationToken);
                    }

                    dcStatus.PasswordReset = okAll;

                    // ==========================================================
                    // PS L367-499: Post-Reset Processing
                    // ==========================================================
                    if (okAll && !whatIf)
                    {
                        _logger.LogInfo("Password reset completed for {DC}", dcFqdn);
                        result.DcsSucceeded++;

                        // PS L377-378: Wait for secure channel stabilization
                        _logger.LogInfo(
                            "Waiting 5 seconds for secure channel stabilization on {DC}...", dcFqdn);
                        await Task.Delay(5000, cancellationToken);

                        // PS L408-479: Restart Netlogon Service via WMI
                        try
                        {
                            RestartNetlogon(dcFqdn);
                            dcStatus.NetlogonRestarted = true;
                            _logger.LogInfo("Netlogon restarted successfully on {DC}.", dcFqdn);
                        }
                        catch (Exception ex)
                        {
                            _logger.LogError("Netlogon restart error on {DC}: {Error}", dcFqdn, ex.Message);
                            dcStatus.Error = $"Netlogon restart failed: {ex.Message}";
                        }

                        // PS L481-498: Verify Secure Channel (nltest /sc_verify)
                        try
                        {
                            var verifyCmdLine = $@"C:\Windows\System32\nltest.exe /sc_verify:{domainName}";
                            var rv = RunRemoteProcess(dcFqdn, verifyCmdLine);
                            if (rv == 0)
                            {
                                dcStatus.SecureChannelVerified = true;
                                _logger.LogInfo(
                                    "Secure channel verification initiated on {DC}.", dcFqdn);
                            }
                        }
                        catch (Exception ex)
                        {
                            _logger.LogWarning(
                                "Secure channel verification failed on {DC}: {Error}", dcFqdn, ex.Message);
                        }
                    }
                    else if (!okAll)
                    {
                        result.DcsFailed++;
                        dcStatus.Error = "Password reset failed";
                    }
                }

                result.DomainDcStatus[domainName] = domainStatuses;
                _logger.LogInfo("Completed domain {Domain}", domainName);
            }

            // ==================================================================
            // PS L512-522: Log Completion Status
            // ==================================================================
            result.Success = result.DcsFailed == 0 && result.Errors.Count == 0;
            result.Message = whatIf
                ? $"DC account password reset simulation complete (WhatIf=True). {result.DcsProcessed} DC(s) analyzed."
                : result.DcsSucceeded > 0
                    ? $"DC account password reset completed for {result.DcsSucceeded} DC(s)."
                    : "No DC account passwords were reset.";
        }
        catch (OperationCanceledException)
        {
            result.Message = "Operation was cancelled.";
        }
        }
        catch (Exception ex)
        {
            result.Message = $"Set-DcAccountPassword error: {ex.Message}";
            result.Errors.Add(ex.Message);
            _logger.LogError($"Set-DcAccountPassword error: {ex.Message}");
        }

        sw.Stop();
        result.Duration = sw.Elapsed;
        _logger.LogTaskExecution("DC Account Password Reset", "AD", true, null, result.Success, result.Errors.Count > 0 ? string.Join("; ", result.Errors) : null);
        return result;
    }

    // ==========================================================================
    // WMI Helpers
    // ==========================================================================

    /// <summary>
    /// Run a process remotely via WMI Win32_Process.Create.
    /// PS: Invoke-CimMethod -ClassName Win32_Process -MethodName Create
    /// Returns the process ReturnValue (0 = success).
    /// </summary>
    private int RunRemoteProcess(string computer, string commandLine)
    {
        var scope = _authService.CreateWmiScope(computer);

        using var processClass = new ManagementClass(scope, new ManagementPath("Win32_Process"), null);
        var inParams = processClass.GetMethodParameters("Create");
        inParams["CommandLine"] = commandLine;

        var outParams = processClass.InvokeMethod("Create", inParams, null);
        return Convert.ToInt32(outParams["ReturnValue"], CultureInfo.InvariantCulture);
    }

    /// <summary>
    /// PS L408-479: Restart Netlogon service via WMI.
    /// Stop (wait up to 20s) -> Start (wait up to 20s).
    /// </summary>
    private void RestartNetlogon(string computer)
    {
        var scope = _authService.CreateWmiScope(computer);

        using var searcher = new ManagementObjectSearcher(scope,
            new ObjectQuery("SELECT * FROM Win32_Service WHERE Name='Netlogon'"));

        var svc = searcher.Get().Cast<ManagementObject>().FirstOrDefault()
            ?? throw new InvalidOperationException($"Netlogon service not found on {computer}");

        // Stop if Running
        svc.Get();
        if (svc["State"]?.ToString() == "Running")
        {
            svc.InvokeMethod("StopService", null);

            // Wait for Stopped (20s timeout)
            var deadline = DateTime.UtcNow.AddSeconds(20);
            while (DateTime.UtcNow < deadline)
            {
                svc.Get();
                if (svc["State"]?.ToString() == "Stopped") break;
                Thread.Sleep(200);
            }

            if (svc["State"]?.ToString() != "Stopped")
            {
                _logger.LogWarning("Netlogon stop timed out on {Computer}", computer);
            }
            else
            {
                _logger.LogInfo("Netlogon stopped on {Computer}.", computer);
            }
        }

        // Start
        svc.Get();
        svc.InvokeMethod("StartService", null);

        // Wait for Running (20s timeout)
        var startDeadline = DateTime.UtcNow.AddSeconds(20);
        while (DateTime.UtcNow < startDeadline)
        {
            svc.Get();
            if (svc["State"]?.ToString() == "Running") break;
            Thread.Sleep(200);
        }

        if (svc["State"]?.ToString() != "Running")
            throw new InvalidOperationException($"Netlogon start timed out on {computer}");
    }
}
