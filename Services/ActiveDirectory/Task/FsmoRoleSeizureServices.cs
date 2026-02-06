using Phoenix.Core.Services.Authentication;
// --------------------------------------------------------------------------
// <copyright file="FsmoRoleSeizureService.cs" company="Phoenix IR Platform">
//     © 2026 Phoenix IR Platform. All rights reserved.
//     AD Task 6: Seize FSMO Roles - Full PS parity with Invoke-FSMORoleSeizure.ps1
//     Seizes all 5 FSMO roles to chosen online, writable DCs.
//     If RID Master changes: raises rIDAvailablePool +100000 and invalidates RID pool.
// </copyright>
// --------------------------------------------------------------------------

using System.DirectoryServices;
using Phoenix.Core.Services.MicrosoftAzure.Models;

namespace Phoenix.Core.Services.ActiveDirectory.Tasks;

public class FsmoRoleSeizureService : IFsmoRoleSeizureService
{
    private readonly IPhoenixLogger _logger;
    private readonly IAdAuthenticationService _authService;

    // Static arrays for property loading (CA1861)
    private static readonly string[] FsmoRoleOwnerProperty = { "fSMORoleOwner" };
    private static readonly string[] RidAvailablePoolProperty = { "rIDAvailablePool" };
    private static readonly string[] ObjectSidProperty = { "objectSid" };

    public FsmoRoleSeizureService(IPhoenixLogger logger, IAdAuthenticationService authService)
    {
        _logger = logger;
        _authService = authService;
    }

    // --------------------------------------------------------------------------
    // Public API – AnalyzeAsync (WhatIf) and ExecuteAsync
    // --------------------------------------------------------------------------

    public Task<FsmoSeizureResult> AnalyzeAsync(
        IEnumerable<DomainControllerInfo> dcList,
        FsmoSeizureOptions? options = null,
        IProgress<TaskProgressInfo>? progress = null,
        CancellationToken cancellationToken = default)
    {
        return ProcessAsync(dcList, options ?? new FsmoSeizureOptions(), credentials: null,
            whatIf: true, progress, cancellationToken);
    }

    public Task<FsmoSeizureResult> ExecuteAsync(
        IEnumerable<DomainControllerInfo> dcList,
        FsmoSeizureOptions? options = null,
        AdCredentials? credentials = null,
        IProgress<TaskProgressInfo>? progress = null,
        CancellationToken cancellationToken = default)
    {
        return ProcessAsync(dcList, options ?? new FsmoSeizureOptions(), credentials,
            whatIf: false, progress, cancellationToken);
    }

    // --------------------------------------------------------------------------
    // Core Processing – PS parity: process { } block
    // --------------------------------------------------------------------------

    private async Task<FsmoSeizureResult> ProcessAsync(
        IEnumerable<DomainControllerInfo> dcList,
        FsmoSeizureOptions options,
        AdCredentials? credentials,
        bool whatIf,
        IProgress<TaskProgressInfo>? progress,
        CancellationToken cancellationToken)
    {
        var result = new FsmoSeizureResult();

        try
        {
            _logger.LogInfo("FsmoRoleSeizure: Starting operation.");
            // --------------------------------------------------------------------------
            // PS parity: Validate DC list entries
            // --------------------------------------------------------------------------
            var list = dcList.ToList();
            if (list.Count == 0)
            {
                result.Message = "IsolatedDCList is empty.";
                _logger.LogError("IsolatedDCList is empty");
                return result;
            }

            foreach (var dc in list)
            {
                var missing = new List<string>();
                if (string.IsNullOrWhiteSpace(dc.FQDN)) missing.Add("FQDN");
                if (string.IsNullOrWhiteSpace(dc.Domain)) missing.Add("Domain");
                if (string.IsNullOrWhiteSpace(dc.Type)) missing.Add("Type");
                if (string.IsNullOrWhiteSpace(dc.DefaultNamingContext)) missing.Add("DefaultNamingContext");
                if (string.IsNullOrWhiteSpace(dc.ConfigurationNamingContext)) missing.Add("ConfigurationNamingContext");
                if (missing.Count > 0)
                    throw new InvalidOperationException(
                        $"Invalid IsolatedDCList entry for {dc.FQDN}: Missing {string.Join(", ", missing)}");
            }

            // --------------------------------------------------------------------------
            // PS parity: Sort by domain type (Forest Root -> Child -> Tree Root)
            // then group by Domain
            // --------------------------------------------------------------------------
            var sorted = list.OrderBy(dc => dc.Type switch
            {
                "Forest Root" => 1,
                "Child Domain" => 2,
                "Tree Root" => 3,
                _ => 4
            }).ToList();

            var domainGroups = sorted
                .GroupBy(dc => dc.Domain, StringComparer.OrdinalIgnoreCase)
                .ToList();

            if (domainGroups.Count == 0)
            {
                result.Message = "No eligible domains to process.";
                _logger.LogWarning("No eligible domains to process");
                return result;
            }

            _logger.LogInfo(
                "Starting FSMO role seizures across {Count} domain(s) (WhatIf={WhatIf})",
                domainGroups.Count, whatIf);

            progress?.Report(new TaskProgressInfo
            {
                Status = $"Processing {domainGroups.Count} domain(s)...",
                PercentComplete = 0
            });

            int domainIdx = 0;

            // --------------------------------------------------------------------------
            // PS parity: Process each domain group
            // --------------------------------------------------------------------------
            foreach (var grp in domainGroups)
            {
                cancellationToken.ThrowIfCancellationRequested();

                var domainName = grp.Key;
                result.DomainsProcessed++;

                // ==========================================================================
                // PS parity: Filter online writable DCs (skip RODCs)
                // ==========================================================================
                var domainDcs = grp.Where(dc => dc.Online).ToList();
                if (domainDcs.Any(dc => dc.IsRODC))
                    domainDcs = domainDcs.Where(dc => !dc.IsRODC).ToList();

                if (domainDcs.Count == 0)
                {
                    _logger.LogError("No online writable DCs for {Domain}. Skipping.", domainName);
                    result.Errors.Add($"No online writable DCs for {domainName}.");
                    continue;
                }

                // ==========================================================================
                // PS parity: Order DCs – PDC first
                // ==========================================================================
                var orderedDcs = domainDcs
                    .OrderByDescending(dc => dc.IsPdcRoleOwner)
                    .ToList();

                // ==========================================================================
                // PS parity: Target DC = first in ordered list
                // ==========================================================================
                var target = orderedDcs[0];
                var fqdn = target.FQDN;
                var domainNC = target.DefaultNamingContext!;
                var configNC = target.ConfigurationNamingContext!;
                var isForestRoot = string.Equals(target.Type, "Forest Root", StringComparison.OrdinalIgnoreCase);

                // ==========================================================================
                // PS parity: Resolve ServerReferenceBL
                // Prefer from inventory, else resolve from RootDSE.serverName
                // ==========================================================================
                string? serverRefBL = null;

                if (!string.IsNullOrWhiteSpace(target.ServerReferenceBL))
                {
                    // PS: Normalize whitespace in case the string was line-wrapped
                    serverRefBL = System.Text.RegularExpressions.Regex
                        .Replace(target.ServerReferenceBL.Trim(), @"\s+", " ");
                    _logger.LogInfo("Using ServerReferenceBL from inventory for {FQDN}", fqdn);
                }
                else
                {
                    try
                    {
                        using var rootDse = _authService.CreateDirectoryEntry($"LDAP://{fqdn}/RootDSE", credentials);
                        serverRefBL = rootDse.Properties["serverName"]?.Value?.ToString()?.Trim();
                        _logger.LogInfo("Resolved ServerReferenceBL from RootDSE for {FQDN}", fqdn);
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError($"Unable to read RootDSE.serverName on {fqdn}: {ex.Message}");
                        result.Errors.Add($"Unable to read RootDSE.serverName on {fqdn}: {ex.Message}");
                        continue;
                    }
                }

                if (string.IsNullOrWhiteSpace(serverRefBL))
                {
                    _logger.LogError("serverName / ServerReferenceBL not available for {FQDN}. Skipping {Domain}.",
                        fqdn, domainName);
                    result.Errors.Add($"serverName / ServerReferenceBL not available for {fqdn}. Skipping {domainName}.");
                    continue;
                }

                _logger.LogInfo(
                    "Starting FSMO processing for domain {Domain} via {FQDN} ({Count} online DCs)",
                    domainName, fqdn, orderedDcs.Count);

                // ==========================================================================
                // PS parity: Define FSMO role paths
                // 3 domain roles always + 2 forest roles for Forest Root
                // ==========================================================================
                var roles = new List<(FsmoRole Role, string Name, string Path)>
                {
                    (FsmoRole.PdcEmulator, "PDC Emulator", $"LDAP://{fqdn}/{domainNC}"),
                    (FsmoRole.RidMaster, "RID Master", $"LDAP://{fqdn}/CN=RID Manager$,CN=System,{domainNC}"),
                    (FsmoRole.InfrastructureMaster, "Infrastructure Master", $"LDAP://{fqdn}/CN=Infrastructure,{domainNC}")
                };

                if (isForestRoot && options.IncludeForestRoles)
                {
                    roles.Add((FsmoRole.SchemaMaster, "Schema Master", $"LDAP://{fqdn}/CN=Schema,{configNC}"));
                    roles.Add((FsmoRole.DomainNamingMaster, "Domain Naming Master", $"LDAP://{fqdn}/CN=Partitions,{configNC}"));
                }

                // ==========================================================================
                // PS parity: Process each FSMO role
                // ==========================================================================
                var roleStatuses = new List<FsmoRoleStatus>();
                var anyChanged = false;
                var ridChanged = false;

                foreach (var (role, roleName, path) in roles)
                {
                    cancellationToken.ThrowIfCancellationRequested();

                    var status = new FsmoRoleStatus
                    {
                        Role = role,
                        RoleName = roleName
                    };

                    try
                    {
                        // PS parity: Bind to role object
                        using var de = _authService.CreateDirectoryEntry(path, credentials);
                        if (de == null)
                        {
                            status.Error = $"Bind failed: {path}";
                            _logger.LogError("Bind failed: {Path} ({Role})", path, roleName);
                            result.RolesFailed++;
                            roleStatuses.Add(status);
                            continue;
                        }

                        // PS parity: Read current fSMORoleOwner
                        string? current = null;
                        try
                        {
                            de.RefreshCache(FsmoRoleOwnerProperty);
                            if (de.Properties.Contains("fSMORoleOwner") &&
                                de.Properties["fSMORoleOwner"].Count > 0)
                            {
                                current = de.Properties["fSMORoleOwner"][0]?.ToString()?.Trim();
                                _logger.LogInfo("{Role} current owner: {Owner}", roleName, current ?? "Unknown");
                            }
                        }
                        catch (Exception ex)
                        {
                            status.Error = $"Read fSMORoleOwner failed: {ex.Message}";
                            _logger.LogError($"Read fSMORoleOwner failed on {path} ({roleName}): {ex.Message}");
                            result.RolesFailed++;
                            roleStatuses.Add(status);
                            continue;
                        }

                        status.PreviousOwner = current;

                        // PS parity: Check if already owned
                        if (!string.IsNullOrEmpty(current) &&
                            string.Equals(current, serverRefBL, StringComparison.OrdinalIgnoreCase))
                        {
                            status.AlreadyOwned = true;
                            result.RolesAlreadyOwned++;
                            _logger.LogInfo("{Role} already owned by {FQDN}, skipping.", roleName, fqdn);
                            roleStatuses.Add(status);
                            continue;
                        }

                        // PS parity: Seize role
                        if (whatIf)
                        {
                            // WhatIf mode - simulate
                            status.WasSeized = true;
                            status.NewOwner = serverRefBL;
                            result.RolesSeized++;
                            anyChanged = true;
                            if (role == FsmoRole.RidMaster) ridChanged = true;
                            _logger.LogInfo("[WhatIf] Would seize {Role} to {FQDN}", roleName, fqdn);
                        }
                        else
                        {
                            try
                            {
                                // PS parity: ADSI simple string assignment
                                de.Properties["fSMORoleOwner"].Value = serverRefBL;
                                de.CommitChanges();

                                status.WasSeized = true;
                                status.NewOwner = serverRefBL;
                                result.RolesSeized++;
                                anyChanged = true;
                                if (role == FsmoRole.RidMaster) ridChanged = true;
                                _logger.LogInfo("Seized {Role} to {FQDN}", roleName, fqdn);
                            }
                            catch (Exception ex)
                            {
                                status.Error = $"Seize {roleName} failed: {ex.Message}";
                                result.RolesFailed++;
                                _logger.LogError($"Seize {roleName} failed on {fqdn}: {ex.Message}");
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        status.Error = ex.Message;
                        result.RolesFailed++;
                        _logger.LogError($"Error processing {roleName} on {fqdn}: {ex.Message}");
                    }

                    roleStatuses.Add(status);
                }

                result.DomainRoles[domainName] = roleStatuses;

                // ==========================================================================
                // PS parity: Update RID Manager owner if any role changed
                // ==========================================================================
                if (anyChanged && !whatIf)
                {
                    try
                    {
                        var ridPath = $"LDAP://{fqdn}/CN=RID Manager$,CN=System,{domainNC}";
                        using var ridDE = _authService.CreateDirectoryEntry(ridPath, credentials);
                        ridDE.RefreshCache();
                        ridDE.Properties["fSMORoleOwner"].Value = serverRefBL;
                        ridDE.CommitChanges();
                        _logger.LogInfo("RID Manager owner updated for {FQDN}", fqdn);
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError($"RID Manager owner update failed on {fqdn}: {ex.Message}");
                        result.Errors.Add($"RID Manager owner update failed on {fqdn}: {ex.Message}");
                    }
                }
                else if (!anyChanged)
                {
                    _logger.LogInfo("No FSMO role changes required for {FQDN}.", fqdn);
                }

                // ==========================================================================
                // PS parity: RID Maintenance – only if RID Master changed
                // Uses ADSI directly (no remote execution needed)
                // ==========================================================================
                if (ridChanged && options.PerformRidMaintenance)
                {
                    if (whatIf)
                    {
                        _logger.LogInfo(
                            "Skipping RID maintenance for {Domain} (WhatIf=True; RID change simulated).",
                            domainName);
                    }
                    else
                    {
                        await PerformRidMaintenanceAsync(fqdn, domainNC, credentials, options.RidPoolIncrease, result);
                    }
                }
                else if (!ridChanged)
                {
                    _logger.LogInfo(
                        "Skipping RID maintenance for {Domain} (RID Master did not change).", domainName);
                }

                _logger.LogInfo("Completed domain {Domain}", domainName);

                domainIdx++;
                progress?.Report(new TaskProgressInfo
                {
                    Status = $"Completed {domainName}",
                    PercentComplete = (int)(domainIdx * 100.0 / domainGroups.Count)
                });
            }

            result.Success = result.RolesFailed == 0 && result.Errors.Count == 0;
            result.Message = whatIf
                ? $"Analysis complete: {result.RolesSeized} role(s) would be seized, " +
                  $"{result.RolesAlreadyOwned} already owned, {result.RolesFailed} failed across " +
                  $"{result.DomainsProcessed} domain(s)."
                : $"Seizure complete: {result.RolesSeized} role(s) seized, " +
                  $"{result.RolesAlreadyOwned} already owned, {result.RolesFailed} failed across " +
                  $"{result.DomainsProcessed} domain(s)." +
                  (result.RidMaintenancePerformed ? " RID maintenance performed." : "");
        }
        catch (OperationCanceledException)
        {
            result.Message = "FSMO role seizure was cancelled.";
            _logger.LogWarning("FSMO role seizure was cancelled");
        }
        catch (Exception ex)
        {
            result.Message = $"Seize FSMO Roles failed: {ex.Message}";
            result.Errors.Add(result.Message);
            _logger.LogError($"Seize FSMO Roles failed: {ex.Message}");
        }

        _logger.LogTaskExecution("FSMO Role Seizure", "AD", true, null, result.Success, result.Errors.Count > 0 ? string.Join("; ", result.Errors) : null);
        return result;
    }

    // --------------------------------------------------------------------------
    // PS parity: RID Maintenance (+rIDAvailablePool and invalidateRidPool)
    // Maps to PS lines 348-435
    // --------------------------------------------------------------------------

    private async Task PerformRidMaintenanceAsync(
        string fqdn,
        string domainNC,
        AdCredentials? credentials,
        int increase,
        FsmoSeizureResult result)
    {
        _logger.LogInfo(
            "Starting RID maintenance for domain ({Increase} & invalidate) on {FQDN}",
            increase, fqdn);

        try
        {
            // --------------------------------------------------------------------------
            // PS parity: Bind to RID Manager
            // --------------------------------------------------------------------------
            var ridPath = $"LDAP://{fqdn}/CN=RID Manager$,CN=System,{domainNC}";
            _logger.LogInfo("Binding to RID Manager: {Path}", ridPath);
            using var ridObject = _authService.CreateDirectoryEntry(ridPath, credentials);

            // --------------------------------------------------------------------------
            // PS parity: Read current rIDAvailablePool
            // --------------------------------------------------------------------------
            _logger.LogInfo("Reading current rIDAvailablePool value");
            using var ridSearcher = new DirectorySearcher(ridObject);
            ridSearcher.PropertiesToLoad.Add("rIDAvailablePool");
            var searchResult = ridSearcher.FindOne();

            if (searchResult == null ||
                !searchResult.Properties.Contains("rIDAvailablePool") ||
                searchResult.Properties["rIDAvailablePool"].Count == 0)
            {
                throw new InvalidOperationException("Failed to retrieve rIDAvailablePool attribute");
            }

            var currentRidPool = Convert.ToInt64(searchResult.Properties["rIDAvailablePool"][0], System.Globalization.CultureInfo.InvariantCulture);
            _logger.LogInfo("Current rIDAvailablePool: {Value}", currentRidPool);

            // --------------------------------------------------------------------------
            // PS parity: Calculate and update new RID pool
            // --------------------------------------------------------------------------
            var newRidPool = currentRidPool + increase;
            _logger.LogInfo("New rIDAvailablePool: {Value} (increase of {Increase})", newRidPool, increase);

            _logger.LogInfo("Updating rIDAvailablePool attribute");
            ridObject.Properties["rIDAvailablePool"].Value = newRidPool.ToString(System.Globalization.CultureInfo.InvariantCulture);
            ridObject.CommitChanges();
            _logger.LogInfo("Successfully raised RID pool from {Old} to {New}", currentRidPool, newRidPool);

            // --------------------------------------------------------------------------
            // PS parity: Verify RID pool update
            // --------------------------------------------------------------------------
            _logger.LogInfo("Verifying RID pool update");
            ridObject.RefreshCache(RidAvailablePoolProperty);
            using var verifySearcher = new DirectorySearcher(ridObject);
            verifySearcher.PropertiesToLoad.Add("rIDAvailablePool");
            var verifyResult = verifySearcher.FindOne();
            var verifiedValue = Convert.ToInt64(verifyResult?.Properties["rIDAvailablePool"]?[0], System.Globalization.CultureInfo.InvariantCulture);

            if (verifiedValue != newRidPool)
            {
                throw new InvalidOperationException(
                    $"Verification failed! Expected {newRidPool} but got {verifiedValue}");
            }

            _logger.LogInfo("Verified: rIDAvailablePool = {Value}", verifiedValue);

            // --------------------------------------------------------------------------
            // PS parity: Invalidate RID pool
            // Get domain SID, bind to RootDSE, write invalidateRidPool
            // --------------------------------------------------------------------------
            _logger.LogInfo("Invalidating RID pool on {FQDN}", fqdn);

            // Get domain SID
            var domainRootPath = $"LDAP://{fqdn}/{domainNC}";
            using var domainObject = _authService.CreateDirectoryEntry(domainRootPath, credentials);
            domainObject.RefreshCache(ObjectSidProperty);
            var domainSidBytes = domainObject.Properties["objectSid"]?.Value as byte[];

            if (domainSidBytes == null || domainSidBytes.Length == 0)
            {
                throw new InvalidOperationException("Failed to retrieve domain SID");
            }

            // Bind to RootDSE and invalidate
            var rootDSePath = $"LDAP://{fqdn}/RootDSE";
            using var rootDse = _authService.CreateDirectoryEntry(rootDSePath, credentials);
            rootDse.UsePropertyCache = false;
            rootDse.Properties["invalidateRidPool"].Value = domainSidBytes;
            rootDse.CommitChanges();
            _logger.LogInfo("Successfully invalidated RID pool");

            result.RidMaintenancePerformed = true;
            _logger.LogInfo("Completed RID maintenance");
        }
        catch (Exception ex)
        {
            _logger.LogError($"RID maintenance failed: {ex.Message}");
            result.Errors.Add($"RID maintenance failed: {ex.Message}");
        }

        await Task.CompletedTask;
    }

    // --------------------------------------------------------------------------
    // PS parity: _GetDE helper – ADSI bind with optional credentials
    //   Maps to PS function _GetDE
    //   PS: New-Object DirectoryEntry($Path, $Credential.UserName,
    //       $Credential.GetNetworkCredential().Password)
    // --------------------------------------------------------------------------
}
