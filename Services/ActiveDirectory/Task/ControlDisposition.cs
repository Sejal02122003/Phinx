using Phoenix.Core.Services.Authentication;
// --------------------------------------------------------------------------
// <copyright file="ControlDispositionService.cs" company="Phoenix IR Platform">
//     © 2026 Phoenix IR Platform. All rights reserved.
//     AD Task 12: Control Disposition - Strengthens the administrative
//     control plane by normalizing privileged account configurations.
//     Full 6-phase PS parity with Invoke-ControlDisposition.ps1.
// </copyright>
// --------------------------------------------------------------------------

using System.Collections.Concurrent;
using System.Diagnostics;
using System.DirectoryServices;
using System.DirectoryServices.Protocols;
using System.Net;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text.RegularExpressions;
using Phoenix.Core.Services.MicrosoftAzure.Models;

namespace Phoenix.Core.Services.ActiveDirectory.Tasks;

public class ControlDispositionService : IControlDispositionService
{
    private readonly IPhoenixLogger _logger;
    private readonly IAdAuthenticationService _authService;

    // Static arrays for property loading (CA1861)
    private static readonly string[] PrivilegedAccountProperties = { "distinguishedName", "sAMAccountName", "objectClass", "objectSid" };
    private static readonly string[] UserAccountControlProperty = { "userAccountControl" };
    private static readonly string[] MemberOfProperty = { "memberOf" };
    private static readonly string[] GmsaProperties = { "name", "distinguishedName", "servicePrincipalName", "msDS-GroupMSAMembership" };
    private static readonly string[] AdminCountUserProperties = { "distinguishedName", "sAMAccountName" };

    public ControlDispositionService(IPhoenixLogger logger, IAdAuthenticationService authService)
    {
        _logger = logger;
        _authService = authService;
    }

    public Task<ControlDispositionResult> AnalyzeAsync(
        IEnumerable<DomainControllerInfo> dcList,
        ControlDispositionOptions? options = null,
        IProgress<TaskProgressInfo>? progress = null,
        CancellationToken cancellationToken = default)
    {
        return ExecuteInternalAsync(dcList, options ?? new(), null, false, progress, cancellationToken);
    }

    public Task<ControlDispositionResult> ExecuteAsync(
        IEnumerable<DomainControllerInfo> dcList,
        ControlDispositionOptions? options = null,
        AdCredentials? credentials = null,
        IProgress<TaskProgressInfo>? progress = null,
        CancellationToken cancellationToken = default)
    {
        return ExecuteInternalAsync(dcList, options ?? new(), credentials, true, progress, cancellationToken);
    }

    private async Task<ControlDispositionResult> ExecuteInternalAsync(
        IEnumerable<DomainControllerInfo> dcList,
        ControlDispositionOptions options,
        AdCredentials? credentials,
        bool execute,
        IProgress<TaskProgressInfo>? progress,
        CancellationToken cancellationToken)
    {
        var result = new ControlDispositionResult { IsWhatIf = !execute };
        var sw = Stopwatch.StartNew();

        try
        {
            _logger.LogInfo("ControlDisposition: Starting operation.");
            var dcArray = dcList.ToArray();
            var targetDc = dcArray.FirstOrDefault(dc => dc.Online && !dc.IsRODC);
            if (targetDc == null)
            {
                result.Message = "No online writable DC found";
                result.Errors.Add(result.Message);
                return result;
            }

            var currentUserSid = GetCurrentUserSid();
            var breakGlassRegex = new Regex(options.BreakGlassPattern, RegexOptions.IgnoreCase);

            progress?.Report(new TaskProgressInfo { Status = "Finding privileged accounts...", PercentComplete = 10 });

            // Find privileged accounts (adminCount=1)
            var accounts = await Task.Run(() =>
                FindPrivilegedAccounts(targetDc, credentials, cancellationToken));

            _logger.LogInfo("Found {Count} privileged accounts", accounts.Count);

            var processed = 0;
            var accountsDisabled = 0;
            var passwordsReset = 0;
            var groupMembershipsRemoved = 0;
            var accountStatuses = new ConcurrentBag<AccountDispositionStatus>();

            var parallelOptions = new ParallelOptions
            {
                MaxDegreeOfParallelism = options.MaxParallelism,
                CancellationToken = cancellationToken
            };

            await Parallel.ForEachAsync(accounts, parallelOptions, async (account, ct) =>
            {
                var status = new AccountDispositionStatus
                {
                    DistinguishedName = account.Dn,
                    SamAccountName = account.SamAccountName,
                    ObjectClass = account.ObjectClass
                };

                // Check protections
                var isProtected = false;
                string? skipReason = null;

                if (account.Sid == currentUserSid)
                {
                    isProtected = true;
                    skipReason = "Current user";
                }
                else if (breakGlassRegex.IsMatch(account.SamAccountName))
                {
                    isProtected = true;
                    skipReason = "Break glass account";
                }
                else if (options.ProtectedAccounts.Contains(account.SamAccountName, StringComparer.OrdinalIgnoreCase))
                {
                    isProtected = true;
                    skipReason = "In protected list";
                }

                status.IsProtected = isProtected;

                if (isProtected)
                {
                    _logger.LogInfo("Skipping protected account {Account}: {Reason}", account.SamAccountName, skipReason ?? "Unknown");
                }
                else if (execute)
                {
                    try
                    {
                        // Disable account
                        if (options.DisableAccounts && account.ObjectClass == "user")
                        {
                            await Task.Run(() => DisableAccount(targetDc.FQDN, account.Dn, credentials, ct));
                            status.WasDisabled = true;
                            Interlocked.Increment(ref accountsDisabled);
                        }

                        // Reset password
                        if (options.ResetPasswords && account.ObjectClass == "user")
                        {
                            string? password = null;
                            try
                            {
                                password = GeneratePassword(24);
                                await Task.Run(() => ResetPassword(targetDc.FQDN, account.Dn, password, credentials, ct));
                                status.PasswordWasReset = true;
                                Interlocked.Increment(ref passwordsReset);
                            }
                            finally { PasswordGenerator.ClearPassword(ref password); }
                        }

                        // Remove group memberships
                        if (options.RemoveGroupMemberships)
                        {
                            var removed = await Task.Run(() =>
                                RemoveGroupMemberships(targetDc.FQDN, account.Dn, credentials, ct));
                            status.GroupsRemoved = removed;
                            Interlocked.Add(ref groupMembershipsRemoved, removed);
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError($"ControlDisposition: {ex.Message}");
                        status.Error = ex.Message;
                        result.Errors.Add($"Failed on {account.SamAccountName}: {ex.Message}");
                    }
                }
                else
                {
                    // WhatIf mode
                    if (options.DisableAccounts && account.ObjectClass == "user")
                    {
                        status.WasDisabled = true;
                        Interlocked.Increment(ref accountsDisabled);
                    }
                    if (options.ResetPasswords && account.ObjectClass == "user")
                    {
                        status.PasswordWasReset = true;
                        Interlocked.Increment(ref passwordsReset);
                    }
                }

                accountStatuses.Add(status);
                result.AccountsProcessed++;

                var current = Interlocked.Increment(ref processed);
                if (current % 10 == 0)
                {
                    progress?.Report(new TaskProgressInfo
                    {
                        Status = $"Processing accounts... ({current}/{accounts.Count})",
                        PercentComplete = 10 + (current * 80 / accounts.Count),
                        ItemsProcessed = current,
                        TotalItems = accounts.Count
                    });
                }
            });

            result.AccountStatuses = accountStatuses.ToList();
            result.AccountsDisabled = accountsDisabled;
            result.PasswordsReset = passwordsReset;
            result.GroupMembershipsRemoved = groupMembershipsRemoved;

            // Phase 4: Container ACL Reset (PS parity)
            if (options.ResetContainerAcls)
            {
                ExecutePhase4ContainerAclReset(dcArray, credentials, execute, result, progress);
            }

            // Phase 5: Orphan Admin Account Cleanup (PS parity)
            if (options.CleanOrphanAdminCounts)
            {
                // Build excluded DN set from protected accounts
                var excludedDns = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                foreach (var acct in result.AccountStatuses.Where(a => a.IsProtected))
                {
                    excludedDns.Add(acct.DistinguishedName);
                }

                ExecutePhase5OrphanAdminCleanup(dcArray, credentials, execute, excludedDns, result, progress);
            }
            // Phase 6: Trigger SDProp (PS parity)
            if (options.TriggerSdProp)
            {
                ExecutePhase6TriggerSdProp(dcArray, credentials, execute, result, progress);
            }

            result.Success = result.Errors.Count == 0;
            result.Message = execute
                ? $"Processed {result.AccountsProcessed} accounts: {accountsDisabled} disabled, {passwordsReset} passwords reset, {groupMembershipsRemoved} group memberships removed, {result.ContainerAclsReset} container ACLs reset, {result.OrphanAdminCountCleared} adminCount cleared"
                : $"WhatIf: Would process {result.AccountsProcessed} accounts, {result.ContainerAclsNeedingReset} container ACLs need reset";
        }
        catch (Exception ex)
        {
            _logger.LogError($"ControlDisposition: {ex.Message}");
            result.Message = $"Operation failed: {ex.Message}";
            result.Errors.Add(ex.ToString());
        }

        sw.Stop();
        result.Duration = sw.Elapsed;
        progress?.Report(new TaskProgressInfo { PercentComplete = 100, Status = result.Message });
        _logger.LogTaskExecution("Control Disposition", "AD", true, null, result.Success, result.ErrorMessage);
        return result;
    }

    private record AccountInfo(string Dn, string SamAccountName, string ObjectClass, string? Sid);

    private List<AccountInfo> FindPrivilegedAccounts(DomainControllerInfo dc, AdCredentials? credentials)
    {
        var accounts = new List<AccountInfo>();
        var path = $"LDAP://{dc.FQDN}/{dc.DefaultNamingContext}";

        using var entry = _authService.CreateDirectoryEntry(path, credentials);
        using var searcher = new DirectorySearcher(entry)
        {
            Filter = "(adminCount=1)",
            SearchScope = System.DirectoryServices.SearchScope.Subtree,
            PageSize = 1000
        };
        searcher.PropertiesToLoad.AddRange(PrivilegedAccountProperties);

        using var results = searcher.FindAll();
        foreach (SearchResult r in results)
        {
            var dn = r.Properties["distinguishedName"][0]?.ToString() ?? "";
            var sam = r.Properties["sAMAccountName"][0]?.ToString() ?? "";
            var objClass = r.Properties["objectClass"].Cast<string>().LastOrDefault() ?? "unknown";
            string? sid = null;
            if (r.Properties["objectSid"].Count > 0 && r.Properties["objectSid"][0] is byte[] sidBytes)
            {
                sid = new SecurityIdentifier(sidBytes, 0).Value;
            }
            accounts.Add(new AccountInfo(dn, sam, objClass, sid));
        }

        return accounts;
    }

    private void DisableAccount(string dcfqdn, string dn, AdCredentials? credentials)
    {
        var path = $"LDAP://{dcfqdn}/{dn}";
        using var entry = _authService.CreateDirectoryEntry(path, credentials);
        entry.RefreshCache(UserAccountControlProperty);

        var uacValue = entry.Properties["userAccountControl"].Value;
        var uac = uacValue is int intValue ? intValue : 0;
        uac |= 0x2; // ADS_UF_ACCOUNTDISABLE
        entry.Properties["userAccountControl"].Value = uac;
        entry.CommitChanges();
    }

    private void ResetPassword(string dcfqdn, string dn, string password, AdCredentials? credentials)
    {
        var path = $"LDAP://{dcfqdn}/{dn}";
        using var entry = _authService.CreateDirectoryEntry(path, credentials);
        entry.Invoke("SetPassword", password);
        entry.CommitChanges();
    }

    private int RemoveGroupMemberships(string dcfqdn, string accountDn, AdCredentials? credentials)
    {
        var removed = 0;
        var path = $"LDAP://{dcfqdn}/{accountDn}";
        using var entry = _authService.CreateDirectoryEntry(path, credentials);
        entry.RefreshCache(MemberOfProperty);

        if (entry.Properties["memberOf"].Count == 0)
            return 0;

        var groups = entry.Properties["memberOf"].Cast<string>().ToList();
        foreach (var groupDn in groups)
        {
            {
                try
                {
                    // Skip Domain Users (primary group)
                    if (groupDn.Contains("CN=Domain Users,", StringComparison.OrdinalIgnoreCase))
                        continue;

                    var groupPath = $"LDAP://{dcfqdn}/{groupDn}";
                    using var groupEntry = _authService.CreateDirectoryEntry(groupPath, credentials);
                    groupEntry.Properties["member"].Remove(accountDn);
                    groupEntry.CommitChanges();
                    removed++;
                }
                catch (Exception ex)
                {
                    _logger.LogWarning("Failed to remove {Account} from {Group}: {Error}",
                        accountDn, groupDn, ex.Message);
                }
            }
        }

        return removed;
    }

    private string? GetCurrentUserSid()
    {
        try { return WindowsIdentity.GetCurrent().User?.Value; }
        catch (Exception ex)
        {
            _logger.LogDebug($"ControlDispositionService: operation failed: {ex.Message}");
            return null;
        }
    }

    private static string GeneratePassword(int length) => PasswordGenerator.Generate(length);

    #region Phase 4 - Container ACL Reset (PS parity: Compare-SddlToClean + Reset-ObjectAcl)

    /// <summary>
    /// Executes Phase 4: Container ACL Reset across all domains.
    /// Matches PS Phase 4 - iterates DomainControllers, DomainRoot, AdminSDHolder per domain,
    /// compares current SDDL against baselines using ACE-signature-set comparison, and resets
    /// non-matching containers.
    /// </summary>
    private void ExecutePhase4ContainerAclReset(
        DomainControllerInfo[] dcArray,
        AdCredentials? credentials,
        bool execute,
        ControlDispositionResult result,
        IProgress<TaskProgressInfo>? progress)
    {
        _logger.LogInfo("Phase 4: Container ACL Reset");
        progress?.Report(new TaskProgressInfo { Status = "Phase 4: Container ACL Reset...", PercentComplete = 60 });

        // Group DCs by domain to process each domain's containers
        var domains = dcArray
            .Where(dc => dc.Online && !dc.IsRODC)
            .GroupBy(dc => dc.Domain)
            .Select(g => g.First())
            .ToList();

        foreach (var dc in domains)
        {
            if (string.IsNullOrEmpty(dc.DomainSid) || string.IsNullOrEmpty(dc.ForestRootSid))
            {
                _logger.LogWarning("Skipping {Domain} - missing SID(s)", dc.Domain);
                continue;
            }

            // Determine domain type for baseline lookup (matches PS $domain.Type)
            var domainType = dc.Type ?? "Forest Root";

            // Three containers per domain (matches PS Phase 4 $containers array)
            var containers = new[]
            {
                new { DN = dc.DefaultNamingContext ?? string.Empty, Name = "Domain Root", BaselineKey = "DomainRoot" },
                new { DN = $"OU=Domain Controllers,{dc.DefaultNamingContext}", Name = "Domain Controllers", BaselineKey = "DomainControllers" },
                new { DN = $"CN=AdminSDHolder,CN=System,{dc.DefaultNamingContext}", Name = "Admin SD Holder", BaselineKey = "AdminSDHolder" }
            };

            foreach (var container in containers.OrderBy(c => c.Name))
            {
                try
                {
                    var path = $"LDAP://{dc.FQDN}/{container.DN}";
                    using var entry = _authService.CreateDirectoryEntry(path, credentials);

                    // Get current SDDL (matches PS: $ADObject.psbase.ObjectSecurity.GetSecurityDescriptorSddlForm)
                    var objectSecurity = entry.ObjectSecurity as ActiveDirectorySecurity;
                    if (objectSecurity == null)
                    {
                        _logger.LogWarning("[{Domain}] Container {Name} not found or inaccessible", dc.Domain, container.Name);
                        result.Errors.Add($"Container {dc.Domain}\\{container.Name} not found");
                        continue;
                    }

                    var currentSddl = objectSecurity.GetSecurityDescriptorSddlForm(AccessControlSections.Access);
                    var currentInheritanceBlocked = objectSecurity.AreAccessRulesProtected;

                    // Resolve baseline SDDL (matches PS: Get-CleanSDDL)
                    var baseline = GetBaselineSddl(domainType, container.BaselineKey, dc.ForestRootSid, dc.DomainSid);
                    if (baseline == null)
                    {
                        result.Errors.Add($"No baseline for {domainType}/{container.BaselineKey}");
                        continue;
                    }

                    // ACE-signature-set comparison (matches PS: Get-DaclSignatureSet + Compare-SddlToClean)
                    var (curProt, curSigs) = GetDaclSignatureSet(currentSddl);
                    var (baseProt, baseSigs) = GetDaclSignatureSet(baseline.Value.Sddl);

                    if (curProt == "ERROR" || baseProt == "ERROR")
                    {
                        _logger.LogWarning("[{Domain}\\{Name}] Error parsing SDDL", dc.Domain, container.Name);
                        result.Errors.Add($"Error parsing SDDL for {dc.Domain}\\{container.Name}");
                        result.ContainerComparisons.Add(new ContainerComparisonInfo
                        {
                            Domain = dc.Domain, DomainType = domainType, Container = container.Name,
                            NeedsChange = true, DaclMatch = false, Error = "Parser error"
                        });
                        continue;
                    }

                    // Compare signature sets (matches PS: Compare-Object -ReferenceObject $sigsCur -DifferenceObject $sigsBase)
                    var baselineOnly = baseSigs.Except(curSigs).Count();   // Adds needed
                    var currentOnly = curSigs.Except(baseSigs).Count();    // Removes needed
                    var daclMatch = baselineOnly == 0 && currentOnly == 0;
                    var protMatch = curProt == baseProt;
                    var inheritanceMatch = currentInheritanceBlocked == baseline.Value.InheritanceBlocked;
                    var needsChange = !daclMatch || !protMatch || !inheritanceMatch;

                    result.ContainerComparisons.Add(new ContainerComparisonInfo
                    {
                        Domain = dc.Domain, DomainType = domainType, Container = container.Name,
                        DaclMatch = daclMatch, ProtectionMatch = protMatch, InheritanceMatch = inheritanceMatch,
                        NeedsChange = needsChange, Adds = baselineOnly, Removes = currentOnly
                    });

                    if (!needsChange)
                    {
                        _logger.LogInfo("[{Domain}\\{Name}] Matches baseline", dc.Domain, container.Name);
                        continue;
                    }

                    if (!execute)
                    {
                        var inhStatus = inheritanceMatch ? "inheritance OK" : "inheritance mismatch";
                        _logger.LogInfo("[{Domain}\\{Name}] [WHATIF] Would reset: add {Adds}, remove {Removes}, {InhStatus}",
                            dc.Domain, container.Name, baselineOnly, currentOnly, inhStatus);
                        result.ContainerAclsNeedingReset++;
                        continue;
                    }

                    // Apply reset (matches PS: Reset-ObjectAcl -ADObject ... -AccessOnly)
                    var sd = new ActiveDirectorySecurity();
                    sd.SetSecurityDescriptorSddlForm(baseline.Value.Sddl, AccessControlSections.Access);

                    var allowInheritance = !baseline.Value.InheritanceBlocked;
                    sd.SetAccessRuleProtection(!allowInheritance, true);

                    entry.ObjectSecurity = sd;
                    entry.CommitChanges();

                    result.ContainerAclsResetList.Add($"{dc.Domain}\\{container.Name}");
                    result.ContainerAclsReset++;

                    _logger.LogInfo("[{Domain}\\{Name}] Reset ACL (adds: {Adds}, removes: {Removes})",
                        dc.Domain, container.Name, baselineOnly, currentOnly);
                }
                catch (Exception ex)
                {
                    _logger.LogError($"[{dc.Domain}] Error processing {container.Name}: {ex.Message}");
                    result.Errors.Add($"Error processing {dc.Domain}\\{container.Name}: {ex.Message}");
                }
            }
        }

        _logger.LogInfo("Container ACL Reset Complete");
    }

    #endregion

    #region Phase 5 - Orphan Admin Account Cleanup (PS parity)

    /// <summary>
    /// Executes Phase 5: Orphan Admin Account Cleanup.
    /// Matches PS Phase 5 - finds all user objects with adminCount=1, clears the attribute
    /// and re-enables inheritance for non-protected accounts.
    /// </summary>
    private void ExecutePhase5OrphanAdminCleanup(
        DomainControllerInfo[] dcArray,
        AdCredentials? credentials,
        bool execute,
        HashSet<string> excludedDns,
        ControlDispositionResult result,
        IProgress<TaskProgressInfo>? progress)
    {
        _logger.LogInfo("Phase 5: Orphan Admin Account Cleanup");
        progress?.Report(new TaskProgressInfo { Status = "Phase 5: Orphan Admin Account Cleanup...", PercentComplete = 75 });

        var domains = dcArray
            .Where(dc => dc.Online && !dc.IsRODC)
            .GroupBy(dc => dc.Domain)
            .Select(g => g.First())
            .ToList();

        foreach (var dc in domains)
        {
            try
            {
                var path = $"LDAP://{dc.FQDN}/{dc.DefaultNamingContext}";
                using var rootEntry = _authService.CreateDirectoryEntry(path, credentials);
                using var searcher = new DirectorySearcher(rootEntry)
                {
                    // CRITICAL: Only target user objects with adminCount=1 (matches PS filter)
                    Filter = "(&(objectClass=user)(objectCategory=person)(adminCount=1))",
                    SearchScope = System.DirectoryServices.SearchScope.Subtree,
                    PageSize = 1000
                };
                searcher.PropertiesToLoad.AddRange(AdminCountUserProperties);

                using var results = searcher.FindAll();
                foreach (SearchResult r in results)
                {
                    var dn = r.Properties["distinguishedName"][0]?.ToString() ?? "";
                    var sam = r.Properties["sAMAccountName"][0]?.ToString() ?? "Unknown";

                    if (excludedDns.Contains(dn))
                        continue;

                    var status = new OrphanAdminStatus
                    {
                        DistinguishedName = dn,
                        SamAccountName = sam,
                        Domain = dc.Domain
                    };

                    try
                    {
                        var objPath = $"LDAP://{dc.FQDN}/{dn}";
                        using var objEntry = _authService.CreateDirectoryEntry(objPath, credentials);

                        var objSec = objEntry.ObjectSecurity as ActiveDirectorySecurity;
                        var inheritanceBlocked = objSec?.AreAccessRulesProtected ?? false;
                        var hasAdminCount = objEntry.Properties.Contains("adminCount")
                            && objEntry.Properties["adminCount"].Value is int val && val == 1;

                        if (!hasAdminCount && !inheritanceBlocked)
                            continue;

                        if (!execute)
                        {
                            if (hasAdminCount)
                            {
                                _logger.LogInfo("[WHATIF] [{Domain}] Would clear adminCount for {Sam}", dc.Domain, sam);
                                status.AdminCountCleared = true;
                            }
                            if (inheritanceBlocked)
                            {
                                _logger.LogInfo("[WHATIF] [{Domain}] Would enable inheritance for {Sam}", dc.Domain, sam);
                                status.InheritanceRestored = true;
                            }
                        }
                        else
                        {
                            if (hasAdminCount)
                            {
                                objEntry.Properties["adminCount"].Clear();
                                status.AdminCountCleared = true;
                                result.OrphanAdminCountCleared++;
                                _logger.LogInfo("[{Domain}] Cleared adminCount for {Sam}", dc.Domain, sam);
                            }
                            if (inheritanceBlocked && objSec != null)
                            {
                                objSec.SetAccessRuleProtection(false, true);
                                status.InheritanceRestored = true;
                                result.OrphanInheritanceRestored++;
                                _logger.LogInfo("[{Domain}] Enabled inheritance for {Sam}", dc.Domain, sam);
                            }
                            objEntry.CommitChanges();
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError($"ControlDisposition: {ex.Message}");
                        status.Error = ex.Message;
                        result.Errors.Add($"Failed to process {dn} in {dc.Domain}: {ex.Message}");
                    }

                    result.OrphanAdminStatuses.Add(status);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"[{dc.Domain}] Failed to search adminCount=1: {ex.Message}");
                result.Errors.Add($"Failed to search adminCount=1 in {dc.Domain}: {ex.Message}");
            }
        }

        _logger.LogInfo("Orphan Admin Account Cleanup Complete");
    }

    #endregion

    #region Phase 6 - Trigger SDProp (PS parity)

    /// <summary>
    /// Executes Phase 6: Trigger SDProp.
    /// Matches PS Phase 6 - triggers Security Descriptor Propagator via runProtectAdminGroupsTask
    /// on each domain's PDC when container ACLs or memberships were modified.
    /// </summary>
    private void ExecutePhase6TriggerSdProp(
        DomainControllerInfo[] dcArray,
        AdCredentials? credentials,
        bool execute,
        ControlDispositionResult result,
        IProgress<TaskProgressInfo>? progress)
    {
        // Only trigger if changes were made (matches PS condition)
        if (result.ContainerAclsReset == 0 && result.GroupMembershipsRemoved == 0)
            return;

        _logger.LogInfo("Phase 6: Trigger SDProp");
        progress?.Report(new TaskProgressInfo { Status = "Phase 6: Trigger SDProp...", PercentComplete = 90 });

        if (!execute)
        {
            _logger.LogInfo("[WHATIF] Would trigger SDProp");
            return;
        }

        var domains = dcArray
            .Where(dc => dc.Online && !dc.IsRODC)
            .GroupBy(dc => dc.Domain)
            .Select(g => g.First())
            .ToList();

        foreach (var dc in domains)
        {
            try
            {
                var rootDsePath = $"LDAP://{dc.FQDN}/RootDSE";
                using var rootDse = _authService.CreateDirectoryEntry(rootDsePath, credentials);
                rootDse.Properties["runProtectAdminGroupsTask"].Value = 1;
                rootDse.CommitChanges();

                result.SdPropTriggered = true;
                _logger.LogInfo("[{Domain}] Triggered SDProp", dc.Domain);
            }
            catch (Exception ex)
            {
                _logger.LogError($"[{dc.Domain}] SDProp failed: {ex.Message}");
                result.Errors.Add($"SDProp failed for {dc.Domain}: {ex.Message}");
            }
        }
    }

    #endregion

    #region GetDaclSignatureSet - PS parity: Get-DaclSignatureSet

    /// <summary>
    /// Parses an SDDL string into an ActiveDirectorySecurity descriptor, extracts the
    /// DACL protection flag and builds a canonical HashSet of ACE signatures.
    /// Matches PS function Get-DaclSignatureSet exactly.
    /// </summary>
    /// <param name="sddl">The SDDL string to parse.</param>
    /// <returns>
    /// Tuple of (protection flag "P" or "NP", HashSet of canonical ACE signature strings).
    /// Returns ("ERROR", empty set) on parse failure.
    /// </returns>
    private (string Protection, HashSet<string> Signatures) GetDaclSignatureSet(string sddl)
    {
        try
        {
            var sd = new ActiveDirectorySecurity();
            sd.SetSecurityDescriptorSddlForm(sddl, AccessControlSections.All);

            var prot = sd.AreAccessRulesProtected ? "P" : "NP";
            var sigs = new HashSet<string>(StringComparer.Ordinal);

            var rules = sd.GetAccessRules(true, true, typeof(SecurityIdentifier));
            foreach (ActiveDirectoryAccessRule ace in rules)
            {
                var sig = GetAceSignature(ace);
                if (sig != null)
                {
                    sigs.Add(sig);
                }
            }

            return (prot, sigs);
        }
        catch (Exception ex)
        {
            _logger.LogWarning("Failed to get DACL signature set: {Error}", ex.Message);
            return ("ERROR", new HashSet<string>());
        }
    }

    #endregion

    #region GetAceSignature - PS parity: Get-AceSignature

    /// <summary>
    /// Produces a canonical signature string for a single ActiveDirectoryAccessRule.
    /// Format: "SID|AccessControlType|Rights(int)|InheritanceType(int)|ObjectType|InheritedObjectType"
    /// Matches PS function Get-AceSignature exactly.
    /// </summary>
    /// <param name="ace">The access rule to produce a signature for.</param>
    /// <returns>Canonical signature string, or null if the ACE is not an ActiveDirectoryAccessRule.</returns>
    private static string? GetAceSignature(ActiveDirectoryAccessRule ace)
    {
        var sid = ace.IdentityReference.Value;
        var type = ace.AccessControlType;
        var mask = (int)ace.ActiveDirectoryRights;
        var flags = (int)ace.InheritanceType;
        var ot = ace.ObjectType != Guid.Empty ? ace.ObjectType.ToString("D") : "";
        var iot = ace.InheritedObjectType != Guid.Empty ? ace.InheritedObjectType.ToString("D") : "";
        return $"{sid}|{type}|{mask}|{flags}|{ot}|{iot}";
    }

    #endregion

    #region Static SDDL Baselines - PS parity: $script:BaselineArray

    /// <summary>
    /// Container SDDL baseline record. Matches PS BaselineArray node structure.
    /// </summary>
    private readonly record struct SddlBaseline(string Sddl, bool InheritanceBlocked);

    /// <summary>
    /// Resolves the baseline SDDL for a domain type and container, substituting actual SIDs.
    /// Matches PS function Get-CleanSDDL + Get-BaselineByDomainType + Resolve-BaselineContainer.
    /// </summary>
    private static SddlBaseline? GetBaselineSddl(string domainType, string containerKey, string forestSid, string domainSid)
    {
        if (!s_baselineSddl.TryGetValue(domainType, out var containers))
            return null;
        if (!containers.TryGetValue(containerKey, out var template))
            return null;

        var expanded = template.Sddl
            .Replace("{DomainSid}", domainSid, StringComparison.Ordinal)
            .Replace("{ForestSid}", forestSid, StringComparison.Ordinal);

        return new SddlBaseline(expanded, template.InheritanceBlocked);
    }

    // 9 baselines: 3 domain types x 3 containers - byte-for-byte match with PS BaselineArray
    private static readonly Dictionary<string, Dictionary<string, SddlBaseline>> s_baselineSddl = new(StringComparer.OrdinalIgnoreCase)
    {
        ["Forest Root"] = new(StringComparer.OrdinalIgnoreCase)
        {
            ["DomainControllers"] = new(
                "D:AI(A;;LCRPLORC;;;ED)(A;;LCRPLORC;;;AU)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)(A;;CCLCSWRPWPLOCRSDRCWDWO;;;BA)(A;;CCLCSWRPWPLOCRRDCWDWO;;;{DomainSid}-512)(OA;CIIOID;RP;4c164200-20c0-11d0-a768-00aa006e0529;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;CIIOID;RP;4c164200-20c0-11d0-a768-00aa006e0529;;RU)(OA;OICIID;RP;bf967aba-0de6-11d0-a285-00aa003049e2;;RU)(OA;CIIOID;RP;bf967aba-0de6-11d0-a285-00aa003049e2;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;CIIOID;RP;5f202010-79a5-11d0-9020-00c4fc2d4cf;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;CIIOID;RP;bc0ac240-79a9-11d0-9020-00c4fc2d4cf;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;CIIOID;RP;59ba2f42-79a2-11d0-9020-00c4fc2d3cf;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;CIIOID;RP;bc0ac240-79a9-11d0-9020-00c4fc2d4cf;;RU)(OA;CIIOID;RP;59ba2f42-79a2-11d0-9020-00c4fc2d3cf;;RU)(OA;CIIOID;RP;037088f8-0ae1-11d2-b422-00a0c968f939;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;CIIOID;RP;037088f8-0ae1-11d2-b422-00a0c968f939;;RU)(OA;CIIOID;RP;b7c69e6d-2cc7-11d2-854e-00a0c983f608;;ED)(OA;CIIOID;WP;ea1b7b93-5e48-46d5-bc6c-4df4fda78a35;bf967a86-0de6-11d0-a285-00aa003049e2;PS)(OA;CIIOID;LCRPLORC;;;PS)(OA;CIIOID;LCRPLORC;;bf967a9c-0de6-11d0-a285-00aa003049e2;RU)(OA;CIIOID;LCRPLORC;;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;OICIID;RPWP;3f78c3e5-f79a-46bd-a0b8-9d18116ddc79;;PS)(OA;CIID;RPWP;91e647de-d96f-4b70-9557-d63ff4f3ccd8;;PS)(A;CIID;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;{ForestSid}-519)(A;CIID;LC;;;RU)(A;CIID;CCLCSWRPWPLOCRSDRCWDWO;;;BA)",
                false),
            ["DomainRoot"] = new(
                "D:AI(A;;RP;;;WD)(A;;LCRPLORC;;;ED)(A;;LCRPLORC;;;AU)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)(A;;CCLCSWRPWPLOCRSDRCWDWO;;;BA)(A;;RPRC;;;RU)(A;;LC;;;RU)(A;;CCLCSWRPWPLOCRRDCWDWO;;;{DomainSid}-512)(A;;CI;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;{ForestSid}-519)(OA;;CIIO;SW;9b026da6-0d3c-465c-8bee-5199d7165cba;bf967a86-0de6-11d0-a285-00aa003049e2;CO)(OA;;CR;1131f6ac-9c07-11d1-f79f-00c4fc2dcd2;;ED)(OA;;CR;1131f6ab-9c07-11d1-f79f-00c4fc2dcd2;;ED)(OA;;CR;1131f6aa-9c07-11d1-f79f-00c4fc2dcd2;;ED)(OA;;CR;89e95b76-444d-4c62-991a-0facbeda640c;;ED)(OA;;CIIO;RP;b7c69e6d-2cc7-11d2-854e-00a0c983f608;bf967aba-0de6-11d0-a285-00aa003049e2;ED)(OA;;CR;1131f6ae-9c07-11d1-f79f-00c4fc2dcd2;;ED)(OA;;CIIOID;RP;b7c69e6d-2cc7-11d2-854e-00a0c983f608;bf967a9c-0de6-11d0-a285-00aa003049e2;ED)(OA;;CIIO;RP;b7c69e6d-2cc7-11d2-854e-00a0c983f608;;ED)(OA;;CIIO;RP;b7c69e6d-2cc7-11d2-854e-00a0c983f608;bf967a86-0de6-11d0-a285-00aa003049e2;;ED)(OA;;CIIO;SW;9b026da6-0d3c-465c-8bee-5199d7165cba;;ED)(OA;;CIIO;RP;bf967a86-0de6-11d0-a285-00aa003049e2;;PS)(OA;;RPWPWPCR;91e647de-d96f-4b70-9557-d63ff4f3ccd8;;PS)(OA;;CIIO;WP;ea1b7b93-5e48-46d5-bc6c-4df4fda78a35;bf967a86-0de6-11d0-a285-00aa003049e2;PS)(OA;OICI;RPWP;3f78c3e5-f79a-46bd-a0b8-9d18116ddc79;;PS)(OA;;CR;05c74c5e-4deb-43b4-bd9b-86664c2a7fd5;;AU)(OA;;CR;ccc2dc7d-a6ad-4a7a-8846-c0dae3c53501;;AU)(OA;;CR;280f369c-67c7-438e-ae9b-1d463cf6f541;;AU)(OA;;RP;b8119fd0-04f6-4762-ab7a-4986c76b3f9a;;AU)(OA;;CR;1131f6ae-9c07-11d1-f79f-00c4fc2dcd2;;BA)(OA;;CR;1131f6ad-9c07-11d1-f79f-00c4fc2dcd2;;BA)(OA;;CR;1131f6ac-9c07-11d1-f79f-00c4fc2dcd2;;BA)(OA;;CR;1131f6ab-9c07-11d1-f79f-00c4fc2dcd2;;BA)(OA;;CR;1131f6aa-9c07-11d1-f79f-00c4fc2dcd2;;BA)(OA;;CR;89e95b76-444d-4c62-991a-0facbeda640c;;BA)(OA;;CIIO;LCRPLORC;;bf967a86-0de6-11d0-a285-00aa003049e2;RU)(OA;;CIIO;LCRPLORC;;bf967a9c-0de6-11d0-a285-00aa003049e2;RU)(OA;CIIO;RP;59ba2f42-79a2-11d0-9020-00c4fc2d3cf;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;CIIO;LCRPLORC;;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;;CIIO;RP;b8119fd0-04f6-4762-ab7a-4986c76b3f9a;;RU)(OA;CIIO;RP;037088f8-0ae1-11d2-b422-00a0c968f939;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;CIIO;RP;4c164200-20c0-11d0-a768-00aa006e0529;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;CIIO;RP;5f202010-79a5-11d0-9020-00c4fc2d4cf;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;CIIO;RP;5f202010-79a5-11d0-9020-00c4fc2d4cf;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;;RP;c7407360-20bf-11d0-a768-00aa006e0529;;RU)(OA;CIIO;RP;59ba2f42-79a2-11d0-9020-00c4fc2d3cf;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;CIIO;RP;037088f8-0ae1-11d2-b422-00a0c968f939;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;CIIO;RP;bc0ac240-79a9-11d0-9020-00c4fc2d4cf;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;CIIO;RP;4c164200-20c0-11d0-a768-00aa006e0529;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;;CR;e2a36dc9-ae17-47c3-b58b-be34c55ba633;;S-1-5-32-557)(OA;;CR;1131f6aa-9c07-11d1-f79f-00c4fc2dcd2;;{ForestSid}-498)(OA;;CR;1131f6ad-9c07-11d1-f79f-00c4fc2dcd2;;{DomainSid}-516)(OA;;CR;3e0f7e18-2c7a-4c10-ba82-4d926db99a3e;;{DomainSid}-522)(OA;CI;RPWP;5b47d60f-6090-40b2-9f37-2a4de88f3063;;{DomainSid}-526)(OA;CI;RPWP;5b47d60f-6090-40b2-9f37-2a4de88f3063;;{DomainSid}-527)",
                false),
            ["AdminSDHolder"] = new(
                "D:PAI(A;;LCRPLORC;;;AU)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)(A;;CCLCSWRPWPLOCRSDRCWDWO;;;BA)(A;;CCDCLCSWRPWPDTLOCRRDCWDWO;;;{DomainSid}-512)(A;;CCDCLCSWRPWPDTLOCRRDCWDWO;;;{ForestSid}-519)(OA;;CR;ab721a53-1e2f-11d0-9819-00aa0040529b;;WD)(OA;CI;RPWPCR;91e647de-d96f-4b70-9557-d63ff4f3ccd8;;PS)(OA;;CR;ab721a53-1e2f-11d0-9819-00aa0040529b;;PS)(OA;;RP;037088f8-0ae1-11d2-b422-00a0c968f939;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;;RP;4c164200-20c0-11d0-a768-00aa006e0529;;RU)(OA;;RP;037088f8-0ae1-11d2-b422-00a0c968f939;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;;RP;4c164200-20c0-11d0-a768-00aa006e0529;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;;RP;5f202010-79a5-11d0-9020-00c4fc2d4cf;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;;RP;bc0ac240-79a9-11d0-9020-00c4fc2d4cf;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;;RP;59ba2f42-79a2-11d0-9020-00c4fc2d3cf;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;;RP;bc0ac240-79a9-11d0-9020-00c4fc2d4cf;;RU)(OA;;RP;59ba2f42-79a2-11d0-9020-00c4fc2d3cf;;RU)(OA;;RP;4c164200-20c0-11d0-a768-00aa006e0529;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;;RP;5f202010-79a5-11d0-9020-00c4fc2d4cf;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;;WP;e12b56b1-405a-405a-b7e8-ff8a58d456d2;;S-1-5-32-560)(OA;;RPWP;6db69a1c-9422-11d1-aebd-0000f80367c1;;S-1-5-32-561)(OA;;RPWP;5805bc62-bdc9-4428-a5e2-856a0f4c185e;;S-1-5-32-561)(OA;;RPWP;bf967a7f-0de6-11d0-a285-00aa003049e2;;{DomainSid}-517)",
                true)
        },
        ["Child Domain"] = new(StringComparer.OrdinalIgnoreCase)
        {
            ["DomainControllers"] = new(
                "D:AI(A;;LCRPLORC;;;ED)(A;;LCRPLORC;;;AU)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)(A;;CCLCSWRPWPLOCRSDRCWDWO;;;BA)(A;;CCLCSWRPWPLOCRRDCWDWO;;;{DomainSid}-512)(OA;CIIOID;RP;4c164200-20c0-11d0-a768-00aa006e0529;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;CIIOID;RP;4c164200-20c0-11d0-a768-00aa006e0529;;RU)(OA;OICIID;RP;bf967aba-0de6-11d0-a285-00aa003049e2;;RU)(OA;CIIOID;RP;bf967aba-0de6-11d0-a285-00aa003049e2;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;CIIOID;RP;5f202010-79a5-11d0-9020-00c4fc2d4cf;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;CIIOID;RP;bc0ac240-79a9-11d0-9020-00c4fc2d4cf;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;CIIOID;RP;59ba2f42-79a2-11d0-9020-00c4fc2d3cf;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;CIIOID;RP;bc0ac240-79a9-11d0-9020-00c4fc2d4cf;;RU)(OA;CIIOID;RP;59ba2f42-79a2-11d0-9020-00c4fc2d3cf;;RU)(OA;CIIOID;RP;037088f8-0ae1-11d2-b422-00a0c968f939;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;CIIOID;RP;037088f8-0ae1-11d2-b422-00a0c968f939;;RU)(OA;CIIOID;RP;b7c69e6d-2cc7-11d2-854e-00a0c983f608;;ED)(OA;CIIOID;WP;ea1b7b93-5e48-46d5-bc6c-4df4fda78a35;bf967a86-0de6-11d0-a285-00aa003049e2;PS)(OA;CIIOID;LCRPLORC;;;PS)(OA;CIIOID;LCRPLORC;;bf967a9c-0de6-11d0-a285-00aa003049e2;RU)(OA;CIIOID;LCRPLORC;;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;OICIID;RPWP;3f78c3e5-f79a-46bd-a0b8-9d18116ddc79;;PS)(OA;CIID;RPWP;91e647de-d96f-4b70-9557-d63ff4f3ccd8;;PS)(A;CIID;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;{ForestSid}-519)(A;CIID;LC;;;RU)(A;CIID;CCLCSWRPWPLOCRSDRCWDWO;;;BA)",
                false),
            ["DomainRoot"] = new(
                "D:AI(A;;RP;;;WD)(A;;LCRPLORC;;;ED)(A;;LCRPLORC;;;AU)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)(A;;CCLCSWRPWPLOCRSDRCWDWO;;;BA)(A;;RPRC;;;RU)(A;;LC;;;RU)(A;;CCLCSWRPWPLOCRRDCWDWO;;;{DomainSid}-512)(A;;CI;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;{ForestSid}-519)(OA;;CIIO;SW;9b026da6-0d3c-465c-8bee-5199d7165cba;bf967a86-0de6-11d0-a285-00aa003049e2;CO)(OA;;CR;1131f6ac-9c07-11d1-f79f-00c4fc2dcd2;;ED)(OA;;CR;1131f6ab-9c07-11d1-f79f-00c4fc2dcd2;;ED)(OA;;CR;1131f6aa-9c07-11d1-f79f-00c4fc2dcd2;;ED)(OA;;CR;89e95b76-444d-4c62-991a-0facbeda640c;;ED)(OA;;CIIO;RP;b7c69e6d-2cc7-11d2-854e-00a0c983f608;bf967aba-0de6-11d0-a285-00aa003049e2;ED)(OA;;CR;1131f6ae-9c07-11d1-f79f-00c4fc2dcd2;;ED)(OA;;CIIOID;RP;b7c69e6d-2cc7-11d2-854e-00a0c983f608;bf967a9c-0de6-11d0-a285-00aa003049e2;ED)(OA;;CIIO;RP;b7c69e6d-2cc7-11d2-854e-00a0c983f608;;ED)(OA;;CIIO;RP;b7c69e6d-2cc7-11d2-854e-00a0c983f608;bf967a86-0de6-11d0-a285-00aa003049e2;;ED)(OA;;CIIO;SW;9b026da6-0d3c-465c-8bee-5199d7165cba;;ED)(OA;;CIIO;RP;bf967a86-0de6-11d0-a285-00aa003049e2;;PS)(OA;;RPWPWPCR;91e647de-d96f-4b70-9557-d63ff4f3ccd8;;PS)(OA;;CIIO;WP;ea1b7b93-5e48-46d5-bc6c-4df4fda78a35;bf967a86-0de6-11d0-a285-00aa003049e2;PS)(OA;OICI;RPWP;3f78c3e5-f79a-46bd-a0b8-9d18116ddc79;;PS)(OA;;CR;05c74c5e-4deb-43b4-bd9b-86664c2a7fd5;;AU)(OA;;CR;ccc2dc7d-a6ad-4a7a-8846-c0dae3c53501;;AU)(OA;;CR;280f369c-67c7-438e-ae9b-1d463cf6f541;;AU)(OA;;RP;b8119fd0-04f6-4762-ab7a-4986c76b3f9a;;AU)(OA;;CR;1131f6ae-9c07-11d1-f79f-00c4fc2dcd2;;BA)(OA;;CR;1131f6ad-9c07-11d1-f79f-00c4fc2dcd2;;BA)(OA;;CR;1131f6ac-9c07-11d1-f79f-00c4fc2dcd2;;BA)(OA;;CR;1131f6ab-9c07-11d1-f79f-00c4fc2dcd2;;BA)(OA;;CR;1131f6aa-9c07-11d1-f79f-00c4fc2dcd2;;BA)(OA;;CR;89e95b76-444d-4c62-991a-0facbeda640c;;BA)(OA;;CIIO;LCRPLORC;;bf967a86-0de6-11d0-a285-00aa003049e2;RU)(OA;;CIIO;LCRPLORC;;bf967a9c-0de6-11d0-a285-00aa003049e2;RU)(OA;CIIO;RP;59ba2f42-79a2-11d0-9020-00c4fc2d3cf;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;CIIO;LCRPLORC;;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;;CIIO;RP;b8119fd0-04f6-4762-ab7a-4986c76b3f9a;;RU)(OA;CIIO;RP;037088f8-0ae1-11d2-b422-00a0c968f939;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;CIIO;RP;4c164200-20c0-11d0-a768-00aa006e0529;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;CIIO;RP;5f202010-79a5-11d0-9020-00c4fc2d4cf;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;CIIO;RP;5f202010-79a5-11d0-9020-00c4fc2d4cf;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;;RP;c7407360-20bf-11d0-a768-00aa006e0529;;RU)(OA;CIIO;RP;59ba2f42-79a2-11d0-9020-00c4fc2d3cf;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;CIIO;RP;037088f8-0ae1-11d2-b422-00a0c968f939;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;CIIO;RP;bc0ac240-79a9-11d0-9020-00c4fc2d4cf;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;CIIO;RP;4c164200-20c0-11d0-a768-00aa006e0529;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;;CR;e2a36dc9-ae17-47c3-b58b-be34c55ba633;;S-1-5-32-557)(OA;;CR;1131f6aa-9c07-11d1-f79f-00c4fc2dcd2;;{ForestSid}-498)(OA;;CR;1131f6ad-9c07-11d1-f79f-00c4fc2dcd2;;{DomainSid}-516)(OA;;CR;3e0f7e18-2c7a-4c10-ba82-4d926db99a3e;;{DomainSid}-522)(OA;CI;RPWP;5b47d60f-6090-40b2-9f37-2a4de88f3063;;{DomainSid}-526)(OA;CI;RPWP;5b47d60f-6090-40b2-9f37-2a4de88f3063;;{DomainSid}-527)",
                false),
            ["AdminSDHolder"] = new(
                "D:PAI(A;;LCRPLORC;;;AU)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)(A;;CCLCSWRPWPLOCRSDRCWDWO;;;BA)(A;;CCDCLCSWRPWPDTLOCRRDCWDWO;;;{DomainSid}-512)(A;;CCDCLCSWRPWPDTLOCRRDCWDWO;;;{ForestSid}-519)(OA;;CR;ab721a53-1e2f-11d0-9819-00aa0040529b;;WD)(OA;CI;RPWPCR;91e647de-d96f-4b70-9557-d63ff4f3ccd8;;PS)(OA;;CR;ab721a53-1e2f-11d0-9819-00aa0040529b;;PS)(OA;;RP;037088f8-0ae1-11d2-b422-00a0c968f939;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;;RP;4c164200-20c0-11d0-a768-00aa006e0529;;RU)(OA;;RP;037088f8-0ae1-11d2-b422-00a0c968f939;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;;RP;4c164200-20c0-11d0-a768-00aa006e0529;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;;RP;5f202010-79a5-11d0-9020-00c4fc2d4cf;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;;RP;bc0ac240-79a9-11d0-9020-00c4fc2d4cf;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;;RP;59ba2f42-79a2-11d0-9020-00c4fc2d3cf;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;;RP;bc0ac240-79a9-11d0-9020-00c4fc2d4cf;;RU)(OA;;RP;59ba2f42-79a2-11d0-9020-00c4fc2d3cf;;RU)(OA;;RP;4c164200-20c0-11d0-a768-00aa006e0529;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;;RP;5f202010-79a5-11d0-9020-00c4fc2d4cf;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;;WP;e12b56b1-405a-405a-b7e8-ff8a58d456d2;;S-1-5-32-560)(OA;;RPWP;6db69a1c-9422-11d1-aebd-0000f80367c1;;S-1-5-32-561)(OA;;RPWP;5805bc62-bdc9-4428-a5e2-856a0f4c185e;;S-1-5-32-561)(OA;;RPWP;bf967a7f-0de6-11d0-a285-00aa003049e2;;{DomainSid}-517)",
                true)
        },
        ["Tree Root"] = new(StringComparer.OrdinalIgnoreCase)
        {
            ["DomainControllers"] = new(
                "D:AI(A;;LCRPLORC;;;ED)(A;;LCRPLORC;;;AU)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)(A;;CCLCSWRPWPLOCRSDRCWDWO;;;BA)(A;;CCLCSWRPWPLOCRRDCWDWO;;;{DomainSid}-512)(OA;CIIOID;RP;4c164200-20c0-11d0-a768-00aa006e0529;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;CIIOID;RP;4c164200-20c0-11d0-a768-00aa006e0529;;RU)(OA;OICIID;RP;bf967aba-0de6-11d0-a285-00aa003049e2;;RU)(OA;CIIOID;RP;bf967aba-0de6-11d0-a285-00aa003049e2;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;CIIOID;RP;5f202010-79a5-11d0-9020-00c4fc2d4cf;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;CIIOID;RP;bc0ac240-79a9-11d0-9020-00c4fc2d4cf;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;CIIOID;RP;59ba2f42-79a2-11d0-9020-00c4fc2d3cf;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;CIIOID;RP;bc0ac240-79a9-11d0-9020-00c4fc2d4cf;;RU)(OA;CIIOID;RP;59ba2f42-79a2-11d0-9020-00c4fc2d3cf;;RU)(OA;CIIOID;RP;037088f8-0ae1-11d2-b422-00a0c968f939;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;CIIOID;RP;037088f8-0ae1-11d2-b422-00a0c968f939;;RU)(OA;CIIOID;RP;b7c69e6d-2cc7-11d2-854e-00a0c983f608;;ED)(OA;CIIOID;WP;ea1b7b93-5e48-46d5-bc6c-4df4fda78a35;bf967a86-0de6-11d0-a285-00aa003049e2;PS)(OA;CIIOID;LCRPLORC;;;PS)(OA;CIIOID;LCRPLORC;;bf967a9c-0de6-11d0-a285-00aa003049e2;RU)(OA;CIIOID;LCRPLORC;;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;OICIID;RPWP;3f78c3e5-f79a-46bd-a0b8-9d18116ddc79;;PS)(OA;CIID;RPWP;91e647de-d96f-4b70-9557-d63ff4f3ccd8;;PS)(A;CIID;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;{ForestSid}-519)(A;CIID;LC;;;RU)(A;CIID;CCLCSWRPWPLOCRSDRCWDWO;;;BA)",
                false),
            ["DomainRoot"] = new(
                "D:AI(A;;RP;;;WD)(A;;LCRPLORC;;;ED)(A;;LCRPLORC;;;AU)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)(A;;CCLCSWRPWPLOCRSDRCWDWO;;;BA)(A;;RPRC;;;RU)(A;;LC;;;RU)(A;;CCLCSWRPWPLOCRRDCWDWO;;;{DomainSid}-512)(A;;CI;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;{ForestSid}-519)(OA;;CIIO;SW;9b026da6-0d3c-465c-8bee-5199d7165cba;bf967a86-0de6-11d0-a285-00aa003049e2;CO)(OA;;CR;1131f6ac-9c07-11d1-f79f-00c4fc2dcd2;;ED)(OA;;CR;1131f6ab-9c07-11d1-f79f-00c4fc2dcd2;;ED)(OA;;CR;1131f6aa-9c07-11d1-f79f-00c4fc2dcd2;;ED)(OA;;CR;89e95b76-444d-4c62-991a-0facbeda640c;;ED)(OA;;CIIO;RP;b7c69e6d-2cc7-11d2-854e-00a0c983f608;bf967aba-0de6-11d0-a285-00aa003049e2;ED)(OA;;CR;1131f6ae-9c07-11d1-f79f-00c4fc2dcd2;;ED)(OA;;CIIOID;RP;b7c69e6d-2cc7-11d2-854e-00a0c983f608;bf967a9c-0de6-11d0-a285-00aa003049e2;ED)(OA;;CIIO;RP;b7c69e6d-2cc7-11d2-854e-00a0c983f608;;ED)(OA;;CIIO;RP;b7c69e6d-2cc7-11d2-854e-00a0c983f608;bf967a86-0de6-11d0-a285-00aa003049e2;;ED)(OA;;CIIO;SW;9b026da6-0d3c-465c-8bee-5199d7165cba;;ED)(OA;;CIIO;RP;bf967a86-0de6-11d0-a285-00aa003049e2;;PS)(OA;;RPWPWPCR;91e647de-d96f-4b70-9557-d63ff4f3ccd8;;PS)(OA;;CIIO;WP;ea1b7b93-5e48-46d5-bc6c-4df4fda78a35;bf967a86-0de6-11d0-a285-00aa003049e2;PS)(OA;OICI;RPWP;3f78c3e5-f79a-46bd-a0b8-9d18116ddc79;;PS)(OA;;CR;05c74c5e-4deb-43b4-bd9b-86664c2a7fd5;;AU)(OA;;CR;ccc2dc7d-a6ad-4a7a-8846-c0dae3c53501;;AU)(OA;;CR;280f369c-67c7-438e-ae9b-1d463cf6f541;;AU)(OA;;RP;b8119fd0-04f6-4762-ab7a-4986c76b3f9a;;AU)(OA;;CR;1131f6ae-9c07-11d1-f79f-00c4fc2dcd2;;BA)(OA;;CR;1131f6ad-9c07-11d1-f79f-00c4fc2dcd2;;BA)(OA;;CR;1131f6ac-9c07-11d1-f79f-00c4fc2dcd2;;BA)(OA;;CR;1131f6ab-9c07-11d1-f79f-00c4fc2dcd2;;BA)(OA;;CR;1131f6aa-9c07-11d1-f79f-00c4fc2dcd2;;BA)(OA;;CR;89e95b76-444d-4c62-991a-0facbeda640c;;BA)(OA;;CIIO;LCRPLORC;;bf967a86-0de6-11d0-a285-00aa003049e2;RU)(OA;;CIIO;LCRPLORC;;bf967a9c-0de6-11d0-a285-00aa003049e2;RU)(OA;CIIO;RP;59ba2f42-79a2-11d0-9020-00c4fc2d3cf;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;CIIO;LCRPLORC;;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;;CIIO;RP;b8119fd0-04f6-4762-ab7a-4986c76b3f9a;;RU)(OA;CIIO;RP;037088f8-0ae1-11d2-b422-00a0c968f939;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;CIIO;RP;4c164200-20c0-11d0-a768-00aa006e0529;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;CIIO;RP;5f202010-79a5-11d0-9020-00c4fc2d4cf;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;CIIO;RP;5f202010-79a5-11d0-9020-00c4fc2d4cf;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;;RP;c7407360-20bf-11d0-a768-00aa006e0529;;RU)(OA;CIIO;RP;59ba2f42-79a2-11d0-9020-00c4fc2d3cf;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;CIIO;RP;037088f8-0ae1-11d2-b422-00a0c968f939;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;CIIO;RP;bc0ac240-79a9-11d0-9020-00c4fc2d4cf;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;CIIO;RP;4c164200-20c0-11d0-a768-00aa006e0529;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;;CR;e2a36dc9-ae17-47c3-b58b-be34c55ba633;;S-1-5-32-557)(OA;;CR;1131f6aa-9c07-11d1-f79f-00c4fc2dcd2;;{ForestSid}-498)(OA;;CR;1131f6ad-9c07-11d1-f79f-00c4fc2dcd2;;{DomainSid}-516)(OA;;CR;3e0f7e18-2c7a-4c10-ba82-4d926db99a3e;;{DomainSid}-522)(OA;CI;RPWP;5b47d60f-6090-40b2-9f37-2a4de88f3063;;{DomainSid}-526)(OA;CI;RPWP;5b47d60f-6090-40b2-9f37-2a4de88f3063;;{DomainSid}-527)",
                false),
            ["AdminSDHolder"] = new(
                "D:PAI(A;;LCRPLORC;;;AU)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)(A;;CCLCSWRPWPLOCRSDRCWDWO;;;BA)(A;;CCDCLCSWRPWPDTLOCRRDCWDWO;;;{DomainSid}-512)(A;;CCDCLCSWRPWPDTLOCRRDCWDWO;;;{ForestSid}-519)(OA;;CR;ab721a53-1e2f-11d0-9819-00aa0040529b;;WD)(OA;CI;RPWPCR;91e647de-d96f-4b70-9557-d63ff4f3ccd8;;PS)(OA;;CR;ab721a53-1e2f-11d0-9819-00aa0040529b;;PS)(OA;;RP;037088f8-0ae1-11d2-b422-00a0c968f939;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;;RP;4c164200-20c0-11d0-a768-00aa006e0529;;RU)(OA;;RP;037088f8-0ae1-11d2-b422-00a0c968f939;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;;RP;4c164200-20c0-11d0-a768-00aa006e0529;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;;RP;5f202010-79a5-11d0-9020-00c4fc2d4cf;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;;RP;bc0ac240-79a9-11d0-9020-00c4fc2d4cf;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;;RP;59ba2f42-79a2-11d0-9020-00c4fc2d3cf;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;;RP;bc0ac240-79a9-11d0-9020-00c4fc2d4cf;;RU)(OA;;RP;59ba2f42-79a2-11d0-9020-00c4fc2d3cf;;RU)(OA;;RP;4c164200-20c0-11d0-a768-00aa006e0529;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;;RP;5f202010-79a5-11d0-9020-00c4fc2d4cf;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;;WP;e12b56b1-405a-405a-b7e8-ff8a58d456d2;;S-1-5-32-560)(OA;;RPWP;6db69a1c-9422-11d1-aebd-0000f80367c1;;S-1-5-32-561)(OA;;RPWP;5805bc62-bdc9-4428-a5e2-856a0f4c185e;;S-1-5-32-561)(OA;;RPWP;bf967a7f-0de6-11d0-a285-00aa003049e2;;{DomainSid}-517)",
                true)
        };

    #endregion


}
}
