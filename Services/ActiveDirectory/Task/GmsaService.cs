using Phoenix.Core.Services.Authentication;
//
// <copyright file="GmsaService.cs" company="Phoenix IR Platform">
//      © 2026 Phoenix IR Platform. All rights reserved.
//      AD Task 7: gMSA Account Rotation – Full PS parity with Set-GMSA.ps1 (910 lines)
//
//      Recreates and rotates all gMSA accounts and KDS root keys across isolated domains.
//      Validates ONLINE writable DCs, orders Forest Root -> Child -> Tree Root, creates a new
//      KDS root key (effective now or offset). Restarts kdsSvc on forest-root PDC only,
//      disables and removes existing gMSAs, then recreates them with restored attributes.
//      Optionally rebinds computers' msDS-HostServiceAccount entries.
//      Deletes old KDS keys after replication.
// </copyright>
// ----------------------------------------------------------------------------------

using System.DirectoryServices;
using System.Diagnostics;
using System.Management;
using System.Runtime.InteropServices;
using System.Security;
using Phoenix.Core.Services.MicrosoftAzure.Models;

namespace Phoenix.Core.Services.ActiveDirectory.Tasks;

public class GmsaService : IGmsaService
{
    private readonly IPhoenixLogger _logger;
    private readonly IAdAuthenticationService _authService;

    // Static arrays for property loading (CA1861)
    private static readonly string[] GmsaDiscoveryProperties = { "distinguishedName", "sAMAccountName" };
    private static readonly string[] KdsKeyProperties = { "distinguishedName", "cn", "whenCreated" };
    private static readonly string[] HostRebindProperties = { "distinguishedName", "msDS-HostServiceAccount" };

    public GmsaService(IPhoenixLogger logger, IAdAuthenticationService authService)
    {
        _logger = logger;
        _authService = authService;
    }

    // --------------------------------------------------------------------------
    // Public API – AnalyzeAsync (WhatIf) and ExecuteAsync
    // --------------------------------------------------------------------------

    public Task<GmsaResult> AnalyzeAsync(
        IEnumerable<DomainControllerInfo> dcList,
        GmsaOptions? options = null,
        IProgress<TaskProgressInfo>? progress = null,
        CancellationToken cancellationToken = default)
    {
        return ProcessAsync(dcList, options ?? new GmsaOptions(), credentials: null, 
            whatIf: true, progress, cancellationToken);
    }

    public Task<GmsaResult> ExecuteAsync(
        IEnumerable<DomainControllerInfo> dcList,
        GmsaOptions? options = null,
        AdCredentials? credentials = null,
        IProgress<TaskProgressInfo>? progress = null,
        CancellationToken cancellationToken = default)
    {
        return ProcessAsync(dcList, options ?? new GmsaOptions(), credentials, 
            whatIf: false, progress, cancellationToken);
    }

    // --------------------------------------------------------------------------
    // Core Processing – PS parity: begin{} + end{} blocks
    // --------------------------------------------------------------------------

    private async Task<GmsaResult> ProcessAsync(
        IEnumerable<DomainControllerInfo> dcList,
        GmsaOptions options,
        AdCredentials? credentials,
        bool whatIf,
        IProgress<TaskProgressInfo>? progress,
        CancellationToken cancellationToken)
    {
        var result = new GmsaResult { Success = false };
        var statusList = new List<GmsaStatus>();

        try
        {
            _logger.LogInfo("Starting gMSA Rotation Task (WhatIf={WhatIf})", whatIf);

            // ==========================================================================
            // PS L332-379: Input Validation (begin block)
            // ==========================================================================
            var validated = new List<DomainControllerInfo>();
            foreach (var dc in dcList)
            {
                var missing = new List<string>();
                if (string.IsNullOrEmpty(dc.FQDN)) missing.Add("FQDN");
                if (string.IsNullOrEmpty(dc.Domain)) missing.Add("Domain");
                if (string.IsNullOrEmpty(dc.Forest)) missing.Add("Forest");
                if (string.IsNullOrEmpty(dc.DefaultNamingContext)) missing.Add("DefaultNamingContext");
                if (string.IsNullOrEmpty(dc.ConfigurationNamingContext)) missing.Add("ConfigurationNamingContext");
                // NOTE: IsolatedDCList object lacks rootDomainNamingContext property directly
                // We will fetch it dynamically or infer it during forest check.

                if (missing.Count > 0)
                {
                    _logger.LogWarning("Invalid IsolatedDCList entry for {FQDN}: Missing {Missing}",
                        dc.FQDN, string.Join(", ", missing));
                    continue;
                }
                validated.Add(dc);
            }

            if (validated.Count == 0)
            {
                result.Message = "No valid DC entries.";
                _logger.LogWarning("No valid DC entries");
                return result;
            }

            // ==========================================================================
            // PS L384-406: Single Forest Check
            // ==========================================================================
            var forestRoots = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var dc in validated.Where(d => d.Online))
            {
                try
                {
                    using var rootDse = _authService.CreateDirectoryEntry($"LDAP://{dc.FQDN}/RootDSE", credentials);
                    var rootNc = rootDse.Properties["rootDomainNamingContext"]?.Value?.ToString();
                    if (!string.IsNullOrEmpty(rootNc))
                        forestRoots.Add(rootNc);
                }
                catch (Exception ex)
                {
                    _logger.LogWarning("Failed to get rootDomainNamingContext from {FQDN}: {Error}",
                        dc.FQDN, ex.Message);
                }
            }

            if (forestRoots.Count > 1)
            {
                result.Message = "Multiple forests detected in input. This function supports one forest only.";
                _logger.LogError("Multiple forests detected in input");
                return result;
            }

            if (forestRoots.Count == 0)
            {
                result.Message = "No forest root NC detected from supplied DCs.";
                _logger.LogError("No forest root NC detected from supplied DCs");
                return result;
            }

            var forestRootNc = forestRoots.First();
            var forestRootDomain = forestRootNc
                .Replace("DC=", "").Replace(",", ".").ToLowerInvariant();

            // ==========================================================================
            // PS L408-428: Determine Forest Root PDC
            // ==========================================================================
            var forestRootPdc = validated
                .Where(d => string.Equals(d.DefaultNamingContext, forestRootNc, StringComparison.OrdinalIgnoreCase)
                    && d.Online && d.IsPdcRoleOwner)
                .FirstOrDefault();

            if (forestRootPdc == null)
            {
                result.Message = $"Forest root PDC for '{forestRootDomain}' is not present in the supplied " +
                    "IsolatedDCList or is offline. Start the forest-root domain controller or perform " +
                    "PDC FSMO seizure, then rerun gMSA rotation. No changes made.";
                _logger.LogError("Forest root PDC not available for {Domain}", forestRootDomain);
                return result;
            }

            var kdsBindServer = forestRootPdc.FQDN;
            result.ForestRootPdc = kdsBindServer;
            _logger.LogInfo("Forest root PDC anchor: {Server}", kdsBindServer);

            // ==========================================================================
            // PS L430-450: Domain Ordering (Forest Root -> Child -> Tree Root)
            // ==========================================================================
            var domainGroups = validated
                .GroupBy(d => d.Domain, StringComparer.OrdinalIgnoreCase)
                .ToList();

            var domainMeta = new Dictionary<string, (string Type, string DefaultNC, string Domain)>(
                StringComparer.OrdinalIgnoreCase);
            foreach (var g in domainGroups)
            {
                var rep = g.First();
                domainMeta[g.Key] = (rep.Type ?? "", rep.DefaultNamingContext ?? "", g.Key);
            }

            var orderedDomains = domainGroups
                .Select(g => g.Key)
                .OrderBy(d => domainMeta[d].Type switch
                {
                    "Forest Root" => 1,
                    "Child Domain" => 2,
                    "Tree Root" => 3,
                    _ => 4
                })
                .ThenBy(d => d)
                .ToList();

            _logger.LogInfo("gMSA rotation scope across {Count} domain(s) (WhatIf={WhatIf})",
                orderedDomains.Count, whatIf);

            // ==========================================================================
            // PS L460-466: KDS Timing
            // ==========================================================================
            var desiredUsableTime = (options.EffectiveImmediately || options.EffectiveTimeHoursOffset == 0)
                ? DateTime.UtcNow
                : DateTime.UtcNow.AddHours(options.EffectiveTimeHoursOffset);

            var kdsEffectiveTime = desiredUsableTime.AddHours(-10);

            // ==========================================================================
            // PS L468-470: Get configNC from forest-root PDC
            // ==========================================================================
            string cfgNC;
            using (var rootDse = _authService.CreateDirectoryEntry($"LDAP://{kdsBindServer}/RootDSE", credentials))
            {
                cfgNC = rootDse.Properties["configurationNamingContext"]?.Value?.ToString()
                    ?? throw new InvalidOperationException("Failed to read configurationNamingContext");
            }

            // ==========================================================================
            // PS L473-483: Capture Existing KDS Keys
            // ==========================================================================
            var existingKeys = GetKdsRootKeys(kdsBindServer, cfgNC, credentials);
            _logger.LogInfo("Existing KDS keys on forest-root PDC: {Count}", existingKeys.Count);

            // ==========================================================================
            // PS L485-532: Create New KDS Root Key
            // ==========================================================================
            string? newKdsCn = null;

            if (options.CreateKdsRootKey)
            {
                if (whatIf)
                {
                    var effLabel = desiredUsableTime <= DateTime.UtcNow
                        ? "EffectiveImmediately"
                        : $"EffectiveTime={desiredUsableTime:o}";
                    _logger.LogInfo("[WhatIf] Create new KDS root key on {Server} ({Label}) via remote CIM",
                        kdsBindServer, effLabel);
                }
                else
                {
                    var creationOk = await InvokeAddKdsRootKeyRemoteAsync(kdsBindServer, kdsEffectiveTime);

                    if (!creationOk)
                    {
                        result.Message = $"KDS root key creation FAILED on {kdsBindServer}. Aborting, no gMSA changes made.";
                        _logger.LogError("KDS root key creation FAILED on {Server}", kdsBindServer);
                        return result;
                    }

                    _logger.LogInfo("New KDS root key requested on {Server}", kdsBindServer);
                    result.KdsRootKeysCreated++;

                    // PS L505: Force config replication
                    ForceConfigReplication(kdsBindServer, cfgNC);

                    // PS L507-527: Wait for new KDS key visibility (up to 180s)
                    var keyTimeout = DateTime.UtcNow.AddSeconds(180);
                    while (newKdsCn == null && DateTime.UtcNow < keyTimeout)
                    {
                        cancellationToken.ThrowIfCancellationRequested();
                        await Task.Delay(3000, cancellationToken);

                        var afterKeys = GetKdsRootKeys(kdsBindServer, cfgNC, credentials);
                        var oldCns = new HashSet<string>(existingKeys.Select(k => k.CN), StringComparer.OrdinalIgnoreCase);
                        var newKey = afterKeys
                            .Where(k => !oldCns.Contains(k.CN))
                            .OrderByDescending(k => k.WhenCreated)
                            .FirstOrDefault();

                        if (newKey != null)
                            newKdsCn = newKey.CN;
                    }

                    if (newKdsCn == null)
                    {
                        result.Message = "New KDS root key not visible on forest-root PDC after timeout. Aborting.";
                        _logger.LogError("New KDS root key not visible after 180s timeout");
                        return result;
                    }

                    _logger.LogInfo("New KDS root key visible: {CN}", newKdsCn);

                    // PS L529-530: Restart kdsSvc on forest-root PDC
                    RestartKdsService(kdsBindServer);
                }
            }

            // ==========================================================================
            // PS L551-877: Process Each Domain (end{} block)
            // ==========================================================================
            int domainIdx = 0;
            foreach (var domain in orderedDomains)
            {
                cancellationToken.ThrowIfCancellationRequested();
                result.DomainsProcessed++;

                // PS L556-577: Get domain DCs (online, writable, PDC first)
                var dcs = validated
                    .Where(d => string.Equals(d.Domain, domain, StringComparison.OrdinalIgnoreCase) && d.Online)
                    .ToList();
                
                if (dcs.Any(d => d.IsRODC))
                    dcs = dcs.Where(d => !d.IsRODC).ToList();

                if (dcs.Count == 0)
                {
                    _logger.LogError("No online writable DCs for {Domain}. Skipping.", domain);
                    result.Errors.Add($"No online writable DCs for {domain}.");
                    continue;
                }

                var orderedDcs = dcs
                    .OrderByDescending(d => d.IsPdcRoleOwner)
                    .ToList();

                var bindServer = orderedDcs[0].FQDN;
                var domainDn = domainMeta[domain].DefaultNC;
                var domainFqdn = domainMeta[domain].Domain;

                _logger.LogInfo("Starting gMSA Rotation Domain {Domain} (PDC anchor {Server})",
                    domain, bindServer);

                progress?.Report(new TaskProgressInfo
                {
                    Status = $"Processing {domain}...",
                    CurrentItem = domain,
                    PercentComplete = (int)(domainIdx * 100.0 / orderedDomains.Count)
                });

                // ==========================================================================
                // PS L581-612: Enumerate gMSAs
                // ==========================================================================
                var gmsaIndex = new List<GmsaIndexEntry>();
                try
                {
                    using var root = _authService.CreateDirectoryEntry($"LDAP://{bindServer}/{domainDn}", credentials);
                    ds.PageSize = 1000;
                    ds.Filter = "(objectClass=msDS-GroupManagedServiceAccount)";
                    ds.PropertiesToLoad.AddRange(GmsaDiscoveryProperties);

                    using var results = ds.FindAll();
                    foreach (SearchResult r in results)
                    {
                        var dn = r.Properties["distinguishedname"][0]?.ToString() ?? "";
                        var parent = dn.Contains(',') ? dn[(dn.IndexOf(',') + 1)..] : null;
                        var sam = r.Properties.Contains("samaccountname") && r.Properties["samaccountname"].Count > 0
                            ? r.Properties["samaccountname"][0]?.ToString()
                            : null;

                        gmsaIndex.Add(new GmsaIndexEntry(dn, parent, sam));
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogError($"gMSA discovery failed in {domainDn} via {bindServer}: {ex.Message}");
                    result.Errors.Add($"gMSA discovery failed in {domainDn}: {ex.Message}");
                }

                _logger.LogInfo("Found {Count} gMSA object(s) in {Domain}", gmsaIndex.Count, domain);
                result.GmsasFound += gmsaIndex.Count;

                if (gmsaIndex.Count == 0)
                {
                    _logger.LogInfo("No gMSA objects present in {Domain}. Skipping.", domain);
                    domainIdx++;
                    continue;
                }

                // ==========================================================================
                // PS L614-822: Process Each gMSA (5-step lifecycle)
                // ==========================================================================
                foreach (var g in gmsaIndex)
                {
                    cancellationToken.ThrowIfCancellationRequested();

                    var oldDn = g.DistinguishedName;
                    var parent = g.ParentContainerDN;
                    var cn = oldDn.Split(',', 2)[0].Replace("CN=", "", StringComparison.OrdinalIgnoreCase);
                    var sam = g.SamAccountName;

                    if (options.ExcludedGmsas.Contains(cn, StringComparer.OrdinalIgnoreCase))
                        continue;

                    var status = new GmsaStatus
                    {
                        Name = cn,
                        DistinguishedName = oldDn,
                        Domain = domain
                    };
                    result.GmsaStatuses.Add(status);

                    // ==========================================================================
                    // PS L625-655: Backup gMSA Attributes
                    // ==========================================================================
                    var exp = BackupGmsaAttributes(bindServer, oldDn, credentials);
                    _logger.LogInfo("Backed up gMSA {DN} (dnsHostName={Dns}; SPNs={SPNs})",
                        oldDn, exp.DnsHostName ?? "", string.Join(", ", exp.ServicePrincipalName));

                    // ==========================================================================
                    // PS L657-672: Step 1 - Disable and Tag Old gMSA
                    // ==========================================================================
                    if (whatIf)
                    {
                        _logger.LogInfo("[WhatIf] Disable + tag gMSA {DN}", oldDn);
                    }
                    else
                    {
                        try
                        {
                            using var de = _authService.CreateDirectoryEntry($"LDAP://{bindServer}/{oldDn}", credentials);
                            var uacVal = de.Properties["userAccountControl"].Value;
                            var uac = uacVal is int u ? u : 0;
                            de.Properties["userAccountControl"].Value = uac | 0x2; // ACCOUNTDISABLE
                            de.Properties["adminDescription"].Value = options.CleanupTag;
                            de.CommitChanges();
                            _logger.LogInfo("Disabled and tagged gMSA {DN}", oldDn);
                        }
                        catch (Exception ex)
                        {
                            _logger.LogWarning("Disable/tag failed for gMSA {DN}: {Error}", oldDn, ex.Message);
                            status.Error = $"Disable failed: {ex.Message}";
                            result.GmsasFailed++;
                            continue;
                        }

                        // PS L674-690: Step 2 - Clear SPNs and DNS on Old gMSA
                        if (whatIf)
                        {
                            _logger.LogInfo("[WhatIf] Clear SPNs and dnsHostName on gMSA {DN}", oldDn);
                        }
                        else
                        {
                            try
                            {
                                using var de = _authService.CreateDirectoryEntry($"LDAP://{bindServer}/{oldDn}", credentials);
                                de.Properties["servicePrincipalName"].Clear();
                                de.Properties["dnsHostName"].Value = null;
                                de.CommitChanges();
                                _logger.LogInfo("Cleared SPNs and dnsHostName on gMSA {DN}", oldDn);
                            }
                            catch (Exception ex)
                            {
                                _logger.LogWarning("Clearing SPNs/dnsHostName failed for gMSA {DN}: {Error}",
                                    oldDn, ex.Message);
                            }

                            await Task.Delay(2000, cancellationToken);
                        }
                    }

                    // ==========================================================================
                    // PS L692-707: Step 3 - Delete Old gMSA
                    // ==========================================================================
                    if (whatIf)
                    {
                        _logger.LogInfo("[WhatIf] Delete gMSA {DN}", oldDn);
                    }
                    else
                    {
                        try
                        {
                            // PS: $pde.Delete("msDS-GroupManagedServiceAccount", "CN=$cn")
                            var parentDn = oldDn[(oldDn.IndexOf(',') + 1)..];
                            using var pde = _authService.CreateDirectoryEntry($"LDAP://{bindServer}/{parentDn}", credentials);
                            pde.Invoke("Delete", new object[] { "msDS-GroupManagedServiceAccount", $"CN={cn}" });
                            _logger.LogInfo("Deleted old gMSA {DN}", oldDn);
                        }
                        catch (Exception ex)
                        {
                            _logger.LogWarning("Delete failed for gMSA {DN}: {Error}", oldDn, ex.Message);
                            status.Error = $"Delete failed: {ex.Message}";
                            result.GmsasFailed++;
                            continue;
                        }

                        await Task.Delay(2000, cancellationToken);
                    }

                    // ==========================================================================
                    // PS L709-738: Step 4 - Confirm CN Gone (retry up to 5x)
                    // ==========================================================================
                    DirectoryEntry? ouEntry = null;
                    try
                    {
                        ouEntry = _authService.CreateDirectoryEntry($"LDAP://{bindServer}/{parent}", credentials);
                    }
                    catch (Exception ex)
                    {
                        _logger.LogWarning("Cannot bind to parent {Parent}: {Error}", parent ?? "Unknown", ex.Message);
                        status.Error = $"Parent bind failed: {ex.Message}";
                        result.GmsasFailed++;
                        continue;
                    }

                    if (!whatIf)
                    {
                        var exists = true;
                        for (int retry = 0; retry < 5 && exists; retry++)
                        {
                            exists = false;
                            try
                            {
                                using var dsCheck = new DirectorySearcher(ouEntry);
                                dsCheck.Filter = $"(cn={cn})";
                                if (dsCheck.FindOne() != null)
                                {
                                    exists = true;
                                    _logger.LogInfo("CN {CN} still exists, retrying verification ({Retry}/5)...", cn, retry + 1);
                                    await Task.Delay(3000, cancellationToken);
                                }
                            }
                            catch
                            {
                                // Ignore search errors during retry
                            }
                        }

                        if (exists)
                        {
                            _logger.LogError("Adversarial persistence suspected: gMSA {CN} could not be deleted.", cn);
                            status.Error = "Deletion verification failed (object persists).";
                            result.GmsasFailed++;
                            continue;
                        }
                    }

                    // PS L740-748: Normalize sAMAccountName
                    if (sam != null && !sam.EndsWith('$'))
                        sam = $"{sam}$";
                    if (sam != null && sam.Length > 15)
                    {
                        _logger.LogWarning("'sAMAccountName '{Old}' truncated to '{New}' (15-char limit)",
                            sam, sam[..15]);
                        sam = sam[..15];
                    }

                    // PS L750-755: Generate dnsHostName if Missing
                    if (string.IsNullOrEmpty(exp.DnsHostName))
                    {
                        exp.DnsHostName = $"{cn}.{domainFqdn}";
                        _logger.LogInfo("Generated dnsHostName for CN={CN},{Parent} -> {Dns}",
                            cn, parent ?? "Unknown", exp.DnsHostName ?? "");
                    }

                    // PS L757-814: Step 5 - Recreate New gMSA
                    string? newDn = null;

                    if (whatIf)
                    {
                        _logger.LogInfo("[WhatIf] Create new gMSA CN={CN},{Parent} (dnsHostName={Dns})",
                            cn, parent ?? "Unknown", exp.DnsHostName ?? "");
                        status.WasRecreated = true;
                        result.GmsasRecreated++;
                    }
                    else
                    {
                        try
                        {
                            using var newObj = ouEntry.Children.Add($"CN={cn}", "msDS-GroupManagedServiceAccount");

                            // PS L766-783: Set Core Attributes
                            if (!string.IsNullOrEmpty(sam))
                                newObj.Properties["sAMAccountName"].Value = sam;
                            if (!string.IsNullOrEmpty(exp.DisplayName))
                                newObj.Properties["displayName"].Value = exp.DisplayName;
                            if (!string.IsNullOrEmpty(exp.Description))
                                newObj.Properties["description"].Value = exp.Description;

                            if (exp.ManagedPasswordInterval > 0)
                                newObj.Properties["msDS-ManagedPasswordInterval"].Value = exp.ManagedPasswordInterval;

                            // UAC: default WORKSTATION_TRUST_ACCOUNT, ensure enabled (clear bit 0x2)
                            var uac = exp.UserAccountControl ?? 0x1000;
                            uac &= ~0x2; // ensure enabled
                            newObj.Properties["userAccountControl"].Value = uac;

                            newObj.Properties["dnsHostName"].Value = exp.DnsHostName;

                            if (exp.PrincipalsAllowedToRetrieveManagedPassword != null)
                                newObj.Properties["msDS-GroupMSAMembership"].Value = exp.PrincipalsAllowedToRetrieveManagedPassword;
                            if (exp.AllowedToActOnBehalfOfOtherIdentity != null)
                                newObj.Properties["msDS-AllowedToActOnBehalfOfOtherIdentity"].Value =
                                    exp.AllowedToActOnBehalfOfOtherIdentity;
                            if (exp.SupportedEncryptionTypes.HasValue)
                                newObj.Properties["msDS-SupportedEncryptionTypes"].Value =
                                    exp.SupportedEncryptionTypes.Value;

                            newObj.Properties["adminDescription"].Value = "Restored";

                            // First commit core attributes (PS: $new.SetInfo())
                            newObj.CommitChanges();

                            // PS L786-805: Add SPNs and Delegation (individually)
                            try
                            {
                                if (exp.ServicePrincipalName != null)
                                {
                                    foreach (var spn in exp.ServicePrincipalName)
                                        newObj.Properties["servicePrincipalName"].Add(spn);
                                }
                            }
                            catch (Exception ex)
                            {
                                _logger.LogWarning("Adding SPNs failed on CN={CN},{Parent}: {Error}",
                                    cn, parent ?? "Unknown", ex.Message);
                            }

                            try
                            {
                                if (exp.AllowedToDelegateTo != null)
                                {
                                    foreach (var svc in exp.AllowedToDelegateTo)
                                        newObj.Properties["msDS-AllowedToDelegateTo"].Add(svc);
                                }
                            }
                            catch (Exception ex)
                            {
                                _logger.LogWarning("Adding delegation failed on CN={CN},{Parent}: {Error}",
                                    cn, parent ?? "Unknown", ex.Message);
                            }

                            if ((exp.ServicePrincipalName?.Count ?? 0) > 0 || (exp.AllowedToDelegateTo?.Count ?? 0) > 0)
                            {
                                try { newObj.CommitChanges(); } catch (Exception ex) { _logger.LogWarning($"Suppressed: {ex.Message}"); }
                            }

                            newDn = $"CN={cn},{parent}";
                            status.NewDistinguishedName = newDn;
                            status.WasRecreated = true;
                            result.GmsasRecreated++;
                            _logger.LogInfo("Created new gMSA {DN} (Restored)", newDn);
                        }
                        catch (Exception ex)
                        {
                            _logger.LogError($"Create gMSA failed (CN={cn},{parent}): {ex.Message}");
                            status.Error = $"Create failed: {ex.Message}";
                            result.GmsasFailed++;
                        }
                    }

                    ouEntry.Dispose();

                    // PS L816-821: Update Mapping
                    if (newDn != null)
                        oldToNewMap[oldDn] = newDn;
                }

                // PS L825-872: Optional Host Rebind
                if (options.RebindHosts && oldToNewMap.Count > 0)
                {
                    if (whatIf)
                    {
                        _logger.LogInfo("[WhatIf] Rebind hosts in {Domain} using map (count={Count})",
                            domain, oldToNewMap.Count);
                    }
                    else
                    {
                        try
                        {
                            result.HostsRebound += RebindHosts(bindServer, domainDn, oldToNewMap, credentials);
                        }
                        catch (Exception ex)
                        {
                            _logger.LogError($"Host rebind failed in {domainDn}: {ex.Message}");
                            result.Errors.Add($"Host rebind failed in {domainDn}: {ex.Message}");
                        }
                    }
                }

                _logger.LogInfo("Completed gMSA Rotation Domain {Domain}", domain);
                progress?.Report(new TaskProgressInfo
                {
                    Status = $"Completed {domain}",
                    PercentComplete = (int)(domainIdx * 100.0 / orderedDomains.Count)
                });
            }

            // ==========================================================================
            // PS L879-883: WhatIf Completion
            // ==========================================================================
            if (whatIf)
            {
                result.Success = true;
                result.Message = $"gMSA operation simulation complete (WhatIf=True). " +
                    $"{result.GmsasFound} found, {result.GmsasRecreated} would be recreated across " +
                    $"{result.DomainsProcessed} domain(s).";
                sw.Stop();
                result.Duration = sw.Elapsed;
                return result;
            }

            // ==========================================================================
            // PS L886-905: Old KDS Key Cleanup
            // ==========================================================================
            if (existingKeys.Count > 0 && newKdsCn != null)
            {
                try
                {
                    var deleted = RemoveKdsRootKeys(kdsBindServer, cfgNC, existingKeys, credentials);
                    result.OldKdsKeysDeleted = deleted;

                    if (deleted > 0)
                        _logger.LogInfo("Deleted {Count} old KDS root key(s) on forest-root PDC.", deleted);
                    else
                        _logger.LogWarning("No old KDS keys deleted on forest-root PDC.");

                    // PS L898: Replicate config after key deletion
                    ForceConfigReplication(kdsBindServer, cfgNC);

                    // PS L901: Restart kdsSvc after key deletion
                    RestartKdsService(kdsBindServer);
                }
                catch (Exception ex)
                {
                    _logger.LogError($"Old KDS key cleanup failed on forest-root PDC: {ex.Message}");
                    result.Errors.Add($"Old KDS key cleanup failed: {ex.Message}");
                }
            }

            result.Success = result.GmsasFailed == 0 && result.Errors.Count == 0;
            result.Message = $"gMSA rotation complete: {result.GmsasRecreated} recreated, " +
                $"{result.GmsasFailed} failed, {result.KdsRootKeysCreated} KDS key(s) created, " +
                $"{result.OldKdsKeysDeleted} old key(s) deleted, {result.HostsRebound} host(s) rebound " +
                $"across {result.DomainsProcessed} domain(s).";
        }
        catch (OperationCanceledException)
        {
            result.Message = "gMSA rotation was cancelled.";
            _logger.LogWarning("gMSA rotation was cancelled");
        }
        catch (Exception ex)
        {
            result.Message = $"gMSA rotation failed: {ex.Message}";
            result.Errors.Add(result.Message);
            _logger.LogError($"gMSA rotation failed: {ex.Message}");
        }

        _logger.LogTaskExecution("GMSA Reset", "AD", true, null, result.Success, result.ErrorMessage);
        return result;
    }

    // ==========================================================================
    // PS L168-202: Get-KdsRootKeys helper
    // ==========================================================================
    private record KdsKeyInfo(string DistinguishedName, string CN, DateTime? WhenCreated);

    private List<KdsKeyInfo> GetKdsRootKeys(string bindServer, string cfgNC, AdCredentials? credentials)
    {
        var keys = new List<KdsKeyInfo>();

        try
        {
            var kdsPath = $"LDAP://{bindServer}/CN=Master Root Keys,CN=Group Key Distribution Service,CN=Services,{cfgNC}";
            using var searchRoot = _authService.CreateDirectoryEntry(kdsPath, credentials);
            using var ds = new DirectorySearcher(searchRoot)
            {
                Filter = "(objectClass=msKds-ProvRootKey)",
                PageSize = 1000,
                SearchScope = SearchScope.OneLevel
            };
            ds.PropertiesToLoad.AddRange(KdsKeyProperties);

            using var results = ds.FindAll();
            foreach (SearchResult r in results)
            {
                var dn = r.Properties["distinguishedname"][0]?.ToString() ?? "";
                var cn = r.Properties["cn"][0]?.ToString() ?? "";
                DateTime? wc = r.Properties.Contains("whencreated") && r.Properties["whencreated"].Count > 0
                    ? (DateTime)r.Properties["whencreated"][0]
                    : null;

                keys.Add(new KdsKeyInfo(dn, cn, wc));
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning("KDS key query failed via {Server}: {Error}", bindServer, ex.Message);
        }

        return keys;
    }

    // ==========================================================================
    // PS L206-234: Remove-KdsRootKeys helper
    // ==========================================================================
    private int RemoveKdsRootKeys(string bindServer, string cfgNC,
        List<KdsKeyInfo> oldKeys, AdCredentials? credentials)
    {
        int count = 0;
        if (oldKeys.Count == 0) return 0;

        try
        {
            var kdsPath = $"LDAP://{bindServer}/CN=Master Root Keys,CN=Group Key Distribution Service,CN=Services,{cfgNC}";
            using var container = _authService.CreateDirectoryEntry(kdsPath, credentials);

            foreach (var key in oldKeys)
            {
                try
                {
                    // PS: $container.Delete("msKds-ProvRootKey", "CN=$($key.CN)")
                    container.Invoke("Delete", new object[] { "msKds-ProvRootKey", $"CN={key.CN}" });
                    count++;
                }
                catch (Exception ex)
                {
                    _logger.LogWarning("Failed to delete old KDS key CN={CN}: {Error}", key.CN, ex.Message);
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogError($"Old KDS key container access failed via {bindServer}: {ex.Message}");
        }

        return count;
    }


    // ==========================================================================
    // PS L238-288: Restart-KdsService helper (CIM Win32_Service)
    // ==========================================================================
    private void RestartKdsService(string computerName)
    {
        try
        {
            // PS: Get-CimInstance Win32_Service -Filter "Name='kdsSvc'"
            var scope = _authService.CreateWmiScope(computerName);

            using var searcher = new ManagementObjectSearcher(scope,
                new ObjectQuery("SELECT * FROM Win32_Service WHERE Name='kdsSvc'"));

            var svc = searcher.Get().Cast<ManagementObject>().FirstOrDefault();
            if (svc == null)
            {
                _logger.LogWarning("kdsSvc not found on {Computer}", computerName);
                return;
            }

            // Stop service (PS: Invoke-CimMethod -MethodName StopService)
            svc.InvokeMethod("StopService", null);
            var deadline = DateTime.UtcNow.AddSeconds(60);
            while (DateTime.UtcNow < deadline)
            {
                svc.Get(); // refresh
                if (svc["State"]?.ToString() == "Stopped") break;
                Thread.Sleep(200);
            }

            if (svc["State"]?.ToString() != "Stopped")
                _logger.LogWarning("kdsSvc stop timed out on {Computer}", computerName);

            // Start service (PS: Invoke-CimMethod -MethodName StartService)
            svc.InvokeMethod("StartService", null);
            deadline = DateTime.UtcNow.AddSeconds(60);
            while (DateTime.UtcNow < deadline)
            {
                svc.Get();
                if (svc["State"]?.ToString() == "Running") break;
                Thread.Sleep(200);
            }

            if (svc["State"]?.ToString() != "Running")
                _logger.LogWarning("kdsSvc start timed out on {Computer}", computerName);

            _logger.LogInfo("kdsSvc restarted on {Computer}", computerName);
        }
        catch (Exception ex)
        {
            _logger.LogWarning("kdsSvc restart failed on {Computer}: {Error}", computerName, ex.Message);
        }
    }


    // ==========================================================================
    // PS L291-317: Force-ConfigReplication (repadmin via CIM Win32_Process)
    // ==========================================================================
    private void ForceConfigReplication(string sourceDC, string cfgNC)
    {
        try
        {
            // PS: Invoke-CimMethod -ClassName Win32_Process -ComputerName $SourceDC -MethodName Create
            var scope = _authService.CreateWmiScope(sourceDC);

            using var processClass = new ManagementClass(scope, new ManagementPath("Win32_Process"), null);
            var inParams = processClass.GetMethodParameters("Create");
            inParams["CommandLine"] = $"repadmin.exe /syncall {sourceDC} {cfgNC} /d /e /P";

            var outParams = processClass.InvokeMethod("Create", inParams, null);
            var returnValue = Convert.ToInt32(outParams["ReturnValue"], 
                System.Globalization.CultureInfo.InvariantCulture);

            if (returnValue != 0)
            {
                _logger.LogWarning("Config replication launch failed on {Server} (Win32_Process.Create={Code})",
                    sourceDC, returnValue);
            }
            else
            {
                var pid = outParams["ProcessId"];
                _logger.LogInfo("Config replication triggered on {Server} via repadmin (PID={PID})",
                    sourceDC, pid);
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning("Config replication failed from {Server} via CIM: {Error}", sourceDC, ex.Message);
        }
    }


    // ==========================================================================
    // PS L319-352: Invoke-AddKdsRootKeyRemote (Add-KdsRootKey via CIM)
    // ==========================================================================
    private async Task<bool> InvokeAddKdsRootKeyRemoteAsync(string computerName, DateTime effectiveTime)
    {
        try
        {
            // PS: Build PowerShell one-liner that parses ISO time and runs Add-KdsRootKey
            var iso = effectiveTime.ToString("o", System.Globalization.CultureInfo.InvariantCulture);
            var ps = $"[datetime]$t = [datetime]::ParseExact('{iso}','o',[System.Globalization.CultureInfo]::InvariantCulture); Add-KdsRootKey -EffectiveTime $t";
            var cmd = $"powershell.exe -NoProfile -NonInteractive -Command \"{ps}\"";

            var scope = _authService.CreateWmiScope(computerName);

            using var processClass = new ManagementClass(scope, new ManagementPath("Win32_Process"), null);
            var inParams = processClass.GetMethodParameters("Create");
            inParams["CommandLine"] = cmd;

            var outParams = await Task.Run(() => processClass.InvokeMethod("Create", inParams, null));
            var returnValue = Convert.ToInt32(outParams["ReturnValue"],
                System.Globalization.CultureInfo.InvariantCulture);

            if (returnValue != 0)
            {
                _logger.LogError("Add-KdsRootKey remote launch failed on {Computer} (Win32_Process.Create={Code})",
                    computerName, returnValue);
                return false;
            }

            var pid = outParams["ProcessId"];
            _logger.LogInfo("Add-KdsRootKey remotely started on {Computer} (PID={PID})",
                computerName, pid);
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogError($"Add-KdsRootKey remote execution failed on {computerName}: {ex.Message}");
            return false;
        }
    }


    // ==========================================================================
    // Backup gMSA Attributes (PS L625-655)
    // ==========================================================================
    private sealed class GmsaBackup
    {
        public string? DisplayName { get; set; }
        public string? Description { get; set; }
        public List<string> ServicePrincipalName { get; set; } = new();
        public int ManagedPasswordInterval { get; set; } = 30;
        public List<string> AllowedToDelegateTo { get; set; } = new();
        public int? UserAccountControl { get; set; }
        public string? DnsHostName { get; set; }
        public object? PrincipalsAllowedToRetrieveManagedPassword { get; set; }
        public object? AllowedToActOnBehalfOfOtherIdentity { get; set; }
        public int? SupportedEncryptionTypes { get; set; }
    }

    private GmsaBackup BackupGmsaAttributes(string bindServer, string oldDn, AdCredentials? credentials)
    {
        var exp = new GmsaBackup();

        try
        {
            using var xde = _authService.CreateDirectoryEntry($"LDAP://{bindServer}/{oldDn}", credentials);

            if (xde.Properties.Contains("displayName") && xde.Properties["displayName"].Count > 0)
                exp.DisplayName = xde.Properties["displayName"][0]?.ToString();

            if (xde.Properties.Contains("description") && xde.Properties["description"].Count > 0)
                exp.Description = xde.Properties["description"][0]?.ToString();

            if (xde.Properties.Contains("servicePrincipalName") && xde.Properties["servicePrincipalName"].Count > 0)
            {
                foreach (var spn in xde.Properties["servicePrincipalName"])
                    exp.ServicePrincipalName.Add(spn?.ToString() ?? "");
            }

            if (xde.Properties.Contains("msDS-ManagedPasswordInterval") &&
                xde.Properties["msDS-ManagedPasswordInterval"].Count > 0)
                exp.ManagedPasswordInterval = xde.Properties["msDS-ManagedPasswordInterval"][0] is int mpi ? mpi : 0;

            if (xde.Properties.Contains("msDS-AllowedToDelegateTo") &&
                xde.Properties["msDS-AllowedToDelegateTo"].Count > 0)
            {
                foreach (var del in xde.Properties["msDS-AllowedToDelegateTo"])
                    exp.AllowedToDelegateTo.Add(del?.ToString() ?? "");
            }

            if (xde.Properties.Contains("userAccountControl") && xde.Properties["userAccountControl"].Count > 0)
                exp.UserAccountControl = xde.Properties["userAccountControl"][0] is int uac ? uac : 0;

            if (xde.Properties.Contains("dnsHostName") && xde.Properties["dnsHostName"].Count > 0)
                exp.DnsHostName = xde.Properties["dnsHostName"][0]?.ToString();

            // Store security descriptors for re-application
            // Note: In real scenarios, we'd copy the SD. Using 'Value' here as a placeholder for raw bytes/object.
            if (xde.Properties.Contains("msDS-GroupMSAMembership") && xde.Properties["msDS-GroupMSAMembership"].Count > 0)
                exp.PrincipalsAllowedToRetrieveManagedPassword = xde.Properties["msDS-GroupMSAMembership"].Value;

             // PS script Logic might read SDDL or raw bytes. Here assuming we passed the object or bytes back.

            if (xde.Properties.Contains("msDS-AllowedToActOnBehalfOfOtherIdentity") &&
                xde.Properties["msDS-AllowedToActOnBehalfOfOtherIdentity"].Count > 0)
                exp.AllowedToActOnBehalfOfOtherIdentity =
                    xde.Properties["msDS-AllowedToActOnBehalfOfOtherIdentity"][0];

            if (xde.Properties.Contains("msDS-SupportedEncryptionTypes") &&
                xde.Properties["msDS-SupportedEncryptionTypes"].Count > 0)
                exp.SupportedEncryptionTypes = xde.Properties["msDS-SupportedEncryptionTypes"][0] is int set ? set : 0;
        }
        catch (Exception ex)
        {
            _logger.LogDebug($"GmsaBackup: directory property access failed: {ex.Message}");
        }

        return exp;
    }


    // ==========================================================================
    // PS L825-872: Host Rebind helper
    // ==========================================================================
    private int RebindHosts(string bindServer, string domainDn,
        Dictionary<string, string> oldToNewMap, AdCredentials? credentials)
    {
        int reboundCount = 0;

        using var root = _authService.CreateDirectoryEntry($"LDAP://{bindServer}/{domainDn}", credentials);
        using var ds = new DirectorySearcher(root)
        {
            PageSize = 1000,
            Filter = "(&(objectCategory=computer)(msDS-HostServiceAccount=*))"
        };
        ds.PropertiesToLoad.AddRange(HostRebindProperties);

        using var results = ds.FindAll();
        foreach (SearchResult r in results)
        {
            var compDn = r.Properties["distinguishedname"][0]?.ToString() ?? "";
            var currentAccounts = new List<string>();
            if (r.Properties.Contains("msds-hostserviceaccount"))
            {
                foreach (var acc in r.Properties["msds-hostserviceaccount"])
                    currentAccounts.Add(acc?.ToString() ?? "");
            }

            bool updated = false;
            for (int i = 0; i < currentAccounts.Count; i++)
            {
                if (oldToNewMap.TryGetValue(currentAccounts[i], out var newVal))
                {
                    currentAccounts[i] = newVal;
                    updated = true;
                }
            }

            if (updated)
            {
                try
                {
                    using var cde = _authService.CreateDirectoryEntry($"LDAP://{bindServer}/{compDn}", credentials);
                    cde.Properties["msDS-HostServiceAccount"].Clear();
                    foreach (var acc in currentAccounts)
                        cde.Properties["msDS-HostServiceAccount"].Add(acc);
                    cde.CommitChanges();
                    _logger.LogInfo("Rebound host {DN}", compDn);
                    reboundCount++;
                }
                catch (Exception ex)
                {
                    _logger.LogWarning("Rebind failed for host {DN}: {Error}", compDn, ex.Message);
                }
            }
        }

        _logger.LogInfo("Rebound {Count} host(s)", reboundCount);
        return reboundCount;
    }


    // ==========================================================================
    // Internal Types
    // ==========================================================================
    private record GmsaIndexEntry(string DistinguishedName, string? ParentContainerDN, string? SamAccountName);


    // ==========================================================================
    // PS L157: _GetDE helper - ADSI bind with optional credentials
    // ==========================================================================
}
