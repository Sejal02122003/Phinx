using Phoenix.Core.Services.Authentication;
// --------------------------------------------------------------------------
// <copyright file="BuiltinAdminPasswordService.cs" company="Phoenix IR Platform">
//     © 2026 Phoenix IR Platform. All rights reserved.
//     AD Task: Built-in Administrator (RID 500) Password Reset
//     Full PS parity with Set-BuiltinAdminPassword.ps1 (376 lines)
//
//     Validates each domain's writable ONLINE DCs (PDC preferred), binds via ADSI
//     to the RID 500 account, and performs a two-cycle password set to satisfy
//     history/policy. Skips a domain if the current logon SID equals that domain's
//     RID 500 SID. Runs WhatIf unless Execute.
// </copyright>
// --------------------------------------------------------------------------

using System.DirectoryServices;
using System.Diagnostics;
using System.Globalization;
using System.Security.Principal;
using Phoenix.Core.Services.MicrosoftAzure.Models;

namespace Phoenix.Core.Services.ActiveDirectory.Tasks;

public class BuiltinAdminPasswordService : IBuiltinAdminPasswordService
{
    private readonly IPhoenixLogger _logger;
    private readonly IAdAuthenticationService _authService;

    public BuiltinAdminPasswordService(IPhoenixLogger logger, IAdAuthenticationService authService)
    {
        _logger = logger;
        _authService = authService;
    }

    // ==========================================================================
    // Public API
    // ==========================================================================

    public Task<BuiltinAdminPasswordResult> AnalyzeAsync(
        IEnumerable<DomainControllerInfo> dcList,
        BuiltinAdminPasswordOptions? options = null,
        IProgress<TaskProgressInfo>? progress = null,
        CancellationToken cancellationToken = default)
    {
        return ProcessAsync(dcList, options ?? new BuiltinAdminPasswordOptions(),
            credentials: null, whatIf: true, progress, cancellationToken);
    }

    public Task<BuiltinAdminPasswordResult> ExecuteAsync(
        IEnumerable<DomainControllerInfo> dcList,
        BuiltinAdminPasswordOptions? options = null,
        AdCredentials? credentials = null,
        IProgress<TaskProgressInfo>? progress = null,
        CancellationToken cancellationToken = default)
    {
        return ProcessAsync(dcList, options ?? new BuiltinAdminPasswordOptions(),
            credentials, whatIf: false, progress, cancellationToken);
    }

    // ==========================================================================
    // Core Processing - maps to PS begin{} + process{} + end{}
    // ==========================================================================

    private async Task<BuiltinAdminPasswordResult> ProcessAsync(
        IEnumerable<DomainControllerInfo> dcList,
        BuiltinAdminPasswordOptions options,
        AdCredentials? credentials,
        bool whatIf,
        IProgress<TaskProgressInfo>? progress,
        CancellationToken cancellationToken)
    {
        var result = new BuiltinAdminPasswordResult { IsWhatIf = whatIf };
        var sw = Stopwatch.StartNew();

        try
        {
            _logger.LogInfo("BuiltinAdminPassword: Starting operation.");
            // ==================================================================
            // PS L132-136: Validate Input
            // ==================================================================
            var dcArray = dcList.ToArray();
            if (dcArray.Length == 0)
            {
                result.Message = "IsolatedDCList is empty.";
                _logger.LogError("IsolatedDCList is empty.");
                return result;
            }

            // ==================================================================
            // PS L155-159: Determine Forest Root FQDN
            // ==================================================================
            var forestRootFqdn = dcArray
                .FirstOrDefault(dc => !string.IsNullOrEmpty(dc.ForestRootFQDN))?.ForestRootFQDN;

            // ==================================================================
            // PS L162-174: Set DC Types
            // ==================================================================
            foreach (var dc in dcArray)
            {
                if (string.IsNullOrEmpty(dc.Type) && !string.IsNullOrEmpty(forestRootFqdn))
                {
                    if (dc.Domain.Equals(forestRootFqdn, StringComparison.OrdinalIgnoreCase))
                        dc.Type = "Forest Root";
                    else if (dc.Domain.EndsWith($".{forestRootFqdn}", StringComparison.OrdinalIgnoreCase))
                        dc.Type = "Child Domain";
                    else
                        dc.Type = "Tree Root";
                }
            }

            // ==================================================================
            // PS L176-184: Validate DC List Entries
            // ==================================================================
            foreach (var dc in dcArray)
            {
                var missing = new List<string>();
                if (string.IsNullOrEmpty(dc.FQDN)) missing.Add("FQDN");
                if (string.IsNullOrEmpty(dc.Domain)) missing.Add("Domain");
                if (string.IsNullOrEmpty(dc.DefaultNamingContext)) missing.Add("DefaultNamingContext");
                if (string.IsNullOrEmpty(dc.DomainSid)) missing.Add("DomainSid");

                if (missing.Count > 0)
                {
                    _logger.LogWarning($"Invalid DC entry for {dc.FQDN}: Missing {string.Join(", ", missing)}",
                        dc.FQDN, string.Join(", ", missing));
                }
            }

            // ==================================================================
            // PS L186-212: Build Domain Groups (group by domain, sort FR->CD->TR, PDC first)
            // ==================================================================
            var domainGroups = dcArray
                .GroupBy(dc => dc.Domain, StringComparer.OrdinalIgnoreCase)
                .Select(grp =>
                {
                    var domainType = grp.First().Type ?? "Unknown";
                    var writableOnline = grp
                        .Where(dc => dc.Online && !dc.IsRODC)
                        .ToList();

                    // PDC first, then others
                    var ordered = writableOnline
                        .OrderByDescending(dc => dc.IsPdcRoleOwner)
                        .ToList();

                    return new
                    {
                        Domain = grp.Key,
                        Type = domainType,
                        DCs = ordered
                    };
                })
                .Where(g => g.DCs.Count > 0)
                .OrderBy(g => g.Type switch
                {
                    "Forest Root" => 1,
                    "Child Domain" or "Child" => 2,
                    "Tree Root" or "Tree" => 3,
                    _ => 4
                })
                .ToList();

            if (domainGroups.Count == 0)
            {
                result.Message = "No eligible domains to process.";
                _logger.LogWarning("No eligible domains to process.");
                return result;
            }
            _logger.LogInfo(
                "Starting Built-in Administrator (RID 500) password resets ({Count} domain(s), WhatIf={WhatIf})",
                domainGroups.Count, whatIf);

            // ==================================================================
            // PS L220-224: Get Current User SID
            // ==================================================================
            string? currentUserSid = null;
            if (options.SkipCurrentUser)
            {
                try
                {
                    currentUserSid = WindowsIdentity.GetCurrent().User?.Value;
                }
                catch (Exception ex)
                {
                    _logger.LogDebug($"BuiltinAdminPasswordService: _ failed: {ex.Message}");
                    // Silently ignore - matches PS behavior
                }
            }

            // ==================================================================
            // PS L226-347: Process Each Domain
            // ==================================================================
            int domainIdx = 0;
            foreach (var dg in domainGroups)
            {
                cancellationToken.ThrowIfCancellationRequested();
                domainIdx++;

                var domainName = dg.Domain;
                var target = dg.DCs[0];
                var targetFqdn = target.FQDN;

            _logger.LogInfo("[{Type}] Domain '{Domain}' -> target DC: {DC}",
                dg.Type, domainName, targetFqdn);

            result.DomainsProcessed++;

            // ==================================================================
            // PS L236-246: Verify DC Synchronization
            // ==================================================================
            try
            {
                using var rootDSE = _authService.CreateDirectoryEntry($"LDAP://{targetFqdn}/RootDSE", credentials);
                var isSynced = rootDSE.Properties["isSynchronized"]?.Value;
                if (isSynced != null && !Convert.ToBoolean(isSynced, CultureInfo.InvariantCulture))
                {
                    _logger.LogWarning("{DC} not synchronized. Skipping domain '{Domain}'.",
                        targetFqdn, domainName);
                    result.DomainsSkipped++;
                    result.Warnings.Add($"{targetFqdn} not synchronized");
                    continue;
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning("Cannot bind RootDSE on {DC}: {Error}. Skipping '{Domain}'.",
                    targetFqdn, ex.Message, domainName);
                result.DomainsSkipped++;
                result.Warnings.Add($"Cannot bind RootDSE on {targetFqdn}: {ex.Message}");
                continue;
            }

            // ==================================================================
            // PS L248-265: Get Built-in Admin Entry (RID 500 via binary SID filter)
            // ==================================================================
            DirectoryEntry? adminEntry = null;
            string? adminSidStr = null;

            try
            {
                var domainSid = target.DomainSid;
                if (string.IsNullOrEmpty(domainSid))
                {
                    _logger.LogError("DomainSid missing for {Domain}. Skipping.", domainName);
                    result.DomainsSkipped++;
                    continue;
                }

                adminEntry = FindBuiltinAdmin(targetFqdn, domainSid,
                    target.DefaultNamingContext ?? "", credentials, out adminSidStr);

                if (adminEntry == null)
                {
                    _logger.LogError("Built-in Administrator (RID 500) not found in '{Domain}'.", domainName);
                    result.DomainsSkipped++;
                    continue;
                }
            }
            catch (Exception ex)
            {
                _logger.LogError("Get-BuiltinAdmin failed in '{Domain}': {Error}", domainName, ex.Message);
                result.DomainsSkipped++;
                continue;
            }

            // ==================================================================
            // PS L267-281: Check If Current User Is Built-in Admin
            // ==================================================================
            if (currentUserSid != null && adminSidStr != null
                && currentUserSid.Equals(adminSidStr, StringComparison.OrdinalIgnoreCase))
            {
                _logger.LogWarning(
                    "Skipping '{Domain}' because the current logged-on user is the domain's built-in Administrator (RID 500).",
                    domainName);
                result.DomainsSkipped++;
                result.Warnings.Add($"Skipped {domainName}: current user is RID 500");
                adminEntry?.Dispose();
                continue;
            }

            // ==================================================================
            // PS L283-337: Password Reset Cycles (2 cycles, 2 retries each)
            // ==================================================================
            var domainSucceeded = true;
            string lastPassword = "";

            for (var cycle = 1; cycle <= 2; cycle++)
            {
                cancellationToken.ThrowIfCancellationRequested();

                // PS L290-308: Generate Password
                string? plain = null;
                try
                {
                    plain = PasswordGenerator.Generate(options.PasswordLength);
                }
                catch (Exception ex)
                {
                    _logger.LogError("Password generation failed for '{Domain}': {Error}",
                        domainName, ex.Message);
                    domainSucceeded = false;
                    break;
                }

                try
                {
                    // PS L311-333: Apply Password Reset
                    if (whatIf)
                    {
                        _logger.LogInfo(
                            "[WhatIf] Would reset built-in admin in '{Domain}' on {DC} (cycle {Cycle}).",
                            domainName, targetFqdn, cycle);
                    }
                    else
                    {
                        var ok = false;
                        for (var attempt = 1; attempt <= 2; attempt++)
                        {
                            try
                            {
                                // PS L319: $adminEntry.psbase.Invoke('SetPassword', $plain)
                                adminEntry!.Invoke("SetPassword", plain);
                                ok = true;
                                break;
                            }
                            catch (Exception ex)
                            {
                                if (attempt == 2)
                                {
                                    _logger.LogError(
                                        "Password reset failed for '{Domain}' on {DC} (cycle {Cycle}): {Error}",
                                        domainName, targetFqdn, cycle, ex.Message);
                                }
                                else
                                {
                                    await Task.Delay(400, cancellationToken);
                                }
                            }
                        }
                    }
                }

                if (!ok)
                {
                    domainSucceeded = false;
                    break;
                }

                // PS L331: 5-second delay between cycle 1 and 2
                if (cycle == 1)
                    await Task.Delay(5000, cancellationToken);

                // PS L332: store last password for return
                lastPassword = plain;
            }
        }
        finally { PasswordGenerator.ClearPassword(ref plain); }
    }

    // ==================================================================
    // PS L339-345: Log Domain Completion
    // ==================================================================
    if (domainSucceeded)
    {
        _logger.LogInfo(
            "Built-in admin password reset completed for '{Domain}' via {DC}.",
            domainName, targetFqdn);
        result.DomainsSucceeded++;

        if (!whatIf && !string.IsNullOrEmpty(lastPassword))
            result.Passwords[domainName] = lastPassword;
    }
    else
    {
        result.Errors.Add($"Password reset failed for domain {domainName}");
    }

    adminEntry?.Dispose();
                progress?.Report(new TaskProgressInfo
                {
                    Status = $"Completed {domainName}",
                    PercentComplete = (int)(domainIdx * 100.0 / domainGroups.Count)
                });
            }
        }

        // ==================================================================
        // PS L349-361: Return Results
        // ==================================================================
        result.Success = result.Errors.Count == 0;
        result.Message = whatIf
            ? $"Simulation complete: no passwords written (WhatIf). {result.DomainsProcessed} domain(s) analyzed."
            : result.Passwords.Count > 0
                ? $"Built-in admin password reset completed for {result.Passwords.Count} domain(s)."
                : "No built-in admin passwords were reset.";
    }
    catch (OperationCanceledException)
    {
        result.Message = "Operation was cancelled.";
    }
    catch (Exception ex)
    {
        result.Message = $"Unexpected error: {ex.Message}";
        result.Errors.Add(ex.Message);
        _logger.LogError($"Unexpected error in BuiltinAdminPasswordService: {ex.Message}");
    }

    sw.Stop();
    result.Duration = sw.Elapsed;
    _logger.LogTaskExecution("Builtin Admin Password Reset", "AD", true, null, result.Success, result.Errors.Count > 0 ? string.Join("; ", result.Errors) : null);
    return result;
}

// ==================================================================
// PS: Get-BuiltinAdmin - find RID 500 account by binary SID filter
// ==================================================================

/// <summary>
/// Finds the built-in Administrator (RID 500) account using a binary SID LDAP filter.
/// PS equivalent: Get-BuiltinAdmin -TargetDns $targetFqdn -DomSid $target.DomainSid
/// Constructs domain SID + RID 500 -> binary filter (\xx\xx...).
/// </summary>
private DirectoryEntry? FindBuiltinAdmin(
    string server,
    string domainSid,
    string defaultNC,
    AdCredentials? credentials,
    out string? adminSidString)
{
    adminSidString = null;

    try
    {
        // Build RID 500 SID: domainSid + "-500"
        var sid = new SecurityIdentifier($"{domainSid}-500");
        var sidBytes = new byte[sid.BinaryLength];
        sid.GetBinaryForm(sidBytes, 0);

        // Build LDAP binary filter: (objectSid=\xx\xx\xx...)
        var hexFilter = string.Join("", sidBytes.Select(b => $"\\{b:X2}"));
        var filter = $"(objectSid={hexFilter})";

        using var searchRoot = _authService.CreateDirectoryEntry($"LDAP://{server}/{defaultNC}", credentials);
        using var searcher = new DirectorySearcher(searchRoot)
        {
            Filter = filter,
            PageSize = 1,
            SearchScope = SearchScope.Subtree
        };
        searcher.PropertiesToLoad.Add("distinguishedName");
        searcher.PropertiesToLoad.Add("objectSid");

        var searchResult = searcher.FindOne();
        if (searchResult == null) return null;

        // Extract SID for comparison
        var sidProp = searchResult.Properties["objectSid"];
        if (sidProp?.Count > 0)
        {
            var resultSid = new SecurityIdentifier((byte[])sidProp[0], 0);
            adminSidString = resultSid.Value;
        }

        var dn = searchResult.Properties["distinguishedName"][0]?.ToString();
        if (string.IsNullOrEmpty(dn)) return null;

        return _authService.CreateDirectoryEntry($"LDAP://{server}/{dn}", credentials);
    }
    catch (Exception ex)
    {
        _logger.LogError("FindBuiltinAdmin failed on {Server}: {Error}", server, ex.Message);
        return null;
    }
}
// ==================================================================
// Helpers
// ==================================================================
}
