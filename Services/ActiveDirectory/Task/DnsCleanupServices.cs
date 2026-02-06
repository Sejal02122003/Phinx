// --------------------------------------------------------------------------
// <copyright file="DnsCleanupService.cs" company="Phoenix IR Platform">
//     © 2026 Phoenix IR Platform. All rights reserved.
//     DNS Cleanup service implementation.
// </copyright>
// --------------------------------------------------------------------------

using System.Collections.Concurrent;
using System.Diagnostics;
using System.DirectoryServices;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Logging;
using Phoenix.Core.Services.MicrosoftAzure.Models;

namespace Phoenix.Core.Services.ActiveDirectory.Tasks;

/// <summary>
/// Service for cleaning orphaned DNS records in AD-integrated DNS.
/// Implements definitive cleanup using expected records comparison.
/// </summary>
public class DnsCleanupService : IDnsCleanupService
{
    private readonly ILogger<DnsCleanupService>? _logger;

    // DNS type codes
    private static readonly Dictionary<string, int> DnsTypeCodes = new(StringComparer.OrdinalIgnoreCase)
    {
        ["A"] = 1, ["NS"] = 2, ["CNAME"] = 5, ["SOA"] = 6,
        ["PTR"] = 12, ["MX"] = 15, ["TXT"] = 16, ["AAAA"] = 28, ["SRV"] = 33
    };

    private static readonly Dictionary<int, string> DnsTypeNames = new()
    {
        [1] = "A", [2] = "NS", [5] = "CNAME", [6] = "SOA",
        [12] = "PTR", [15] = "MX", [16] = "TXT", [28] = "AAAA", [33] = "SRV"
    };

    // Static arrays for property loading (CA1861)
    private static readonly string[] ZoneProperties = { "name", "distinguishedName" };
    private static readonly string[] RecordProperties = { "name", "dnsRecord", "distinguishedName", "dNSTombstoned" };

    public DnsCleanupService(ILogger<DnsCleanupService>? logger = null)
    {
        _logger = logger;
    }

    #region Public Methods

    /// <inheritdoc/>
    public async Task<DnsCleanupResult> AnalyzeAsync(
        IEnumerable<DcInfo> dcList,
        DnsCleanupOptions? options = null,
        IProgress<TaskProgressInfo>? progress = null,
        CancellationToken cancellationToken = default)
    {
        return await ExecuteInternalAsync(dcList, options ?? new(), false, progress, cancellationToken);
    }

    /// <inheritdoc/>
    public async Task<DnsCleanupResult> ExecuteAsync(
        IEnumerable<DcInfo> dcList,
        DnsCleanupOptions? options = null,
        IProgress<TaskProgressInfo>? progress = null,
        CancellationToken cancellationToken = default)
    {
        return await ExecuteInternalAsync(dcList, options ?? new(), true, progress, cancellationToken);
    }

    /// <inheritdoc/>
    public ExpectedDnsRecords BuildExpectedRecords(IEnumerable<DcInfo> dcList, string forestRoot)
    {
        var exp = new ExpectedDnsRecords();
        var forestRootNorm = NormalizeFqdn(forestRoot);

        foreach (var dc in dcList)
        {
            var fqdn = NormalizeFqdn(dc.FQDN);
            var domain = NormalizeFqdn(dc.Domain);
            var hostname = ExtractHostname(fqdn);
            var site = NormalizeHost(dc.Site ?? "Default-First-Site-Name");
            var dnsGuid = NormalizeHost(dc.DnsGuid);
            var domainGuid = NormalizeHost(dc.DomainGuid);

            if (string.IsNullOrEmpty(fqdn) || string.IsNullOrEmpty(domain))
                continue;

            exp.AllowedFqdns.Add(fqdn);
            if (!string.IsNullOrEmpty(hostname))
                exp.AllowedHosts.Add(hostname);

            if (!string.IsNullOrEmpty(dc.NetBIOS))
                exp.AllowedHosts.Add(NormalizeHost(dc.NetBIOS!));

            if (!string.IsNullOrEmpty(dnsGuid) && IsGuid(dnsGuid))
                exp.AllowedGuids.Add(dnsGuid);

            // IP addresses
            if (dc.IPv4Address != null)
                exp.AllowedIps.Add(dc.IPv4Address.ToString());
            if (dc.IPv6Address != null)
                exp.AllowedIps.Add(dc.IPv6Address.ToString());

            var msdcsZone = $"_msdcs.{forestRootNorm}";
            var domainDnsZone = $"DomainDnsZones.{domain}";
            var forestDnsZone = $"ForestDnsZones.{forestRootNorm}";
            var isForestRootDc = domain == forestRootNorm;

            // A / AAAA records
            if (dc.IPv4Address != null && !string.IsNullOrEmpty(hostname))
                exp.A.Add($"{domain}|{hostname}|{dc.IPv4Address}");
            if (dc.IPv6Address != null && !string.IsNullOrEmpty(hostname))
                exp.AAAA.Add($"{domain}|{hostname}|{dc.IPv6Address}");

            // SRV - Domain Zone (base)
            foreach (var owner in new[] { "_ldap._tcp", "_kerberos._tcp", "_kerberos._udp", "_kpasswd._tcp", "_kpasswd._udp" })
            {
                exp.SRV.Add($"{domain}|{owner}|{fqdn}");
            }

            // SRV - Domain Zone (site)
            foreach (var owner in new[] { $"_ldap._tcp.{site}._sites", $"_kerberos._tcp.{site}._sites",
                                          $"_kerberos._udp.{site}._sites", $"_kpasswd._tcp.{site}._sites",
                                          $"_kpasswd._udp.{site}._sites" })
            {
                exp.SRV.Add($"{domain}|{owner}|{fqdn}");
            }

            // SRV - Domain Zone (GC)
            if (dc.IsGC)
            {
                exp.SRV.Add($"{domain}|_gc._tcp|{fqdn}");
                exp.SRV.Add($"{domain}|_gc._tcp.{site}._sites|{fqdn}");
            }

            // SRV - _msdcs Zone (DC locators)
            exp.SRV.Add($"{msdcsZone}|_ldap._tcp.dc|{fqdn}");
            exp.SRV.Add($"{msdcsZone}|_kerberos._tcp.dc|{fqdn}");
            exp.SRV.Add($"{msdcsZone}|_ldap._tcp.{site}._sites.dc|{fqdn}");
            exp.SRV.Add($"{msdcsZone}|_kerberos._tcp.{site}._sites.dc|{fqdn}");

            // SRV - _msdcs Zone (Domain GUID)
            if (!string.IsNullOrEmpty(domainGuid) && IsGuid(domainGuid))
            {
                exp.SRV.Add($"{msdcsZone}|_ldap._tcp.{domainGuid}.domains|{fqdn}");
            }

            // SRV - _msdcs Zone (GC)
            if (dc.IsGC)
            {
                exp.SRV.Add($"{msdcsZone}|_ldap._tcp.gc|{fqdn}");
                exp.SRV.Add($"{msdcsZone}|_gc._tcp.gc|{fqdn}");
                exp.SRV.Add($"{msdcsZone}|_ldap._tcp.{site}._sites.gc|{fqdn}");
                exp.SRV.Add($"{msdcsZone}|_gc._tcp.{site}._sites.gc|{fqdn}");
            }

            // SRV - _msdcs Zone (PDC)
            if (dc.IsPDC)
            {
                exp.SRV.Add($"{msdcsZone}|_ldap._tcp.pdc|{fqdn}");
            }

            // SRV - DomainDnsZones
            exp.SRV.Add($"{domainDnsZone}|_ldap._tcp|{fqdn}");
            exp.SRV.Add($"{domainDnsZone}|_ldap._tcp.{site}._sites|{fqdn}");

            // SRV - ForestDnsZones (forest root DCs only)
            if (isForestRootDc)
            {
                exp.SRV.Add($"{forestDnsZone}|_ldap._tcp|{fqdn}");
                exp.SRV.Add($"{forestDnsZone}|_ldap._tcp.{site}._sites|{fqdn}");
            }

            // CNAME
            if (!string.IsNullOrEmpty(dnsGuid) && IsGuid(dnsGuid))
            {
                exp.CNAME.Add($"{msdcsZone}|{dnsGuid}|{fqdn}");
            }

            // NS Records
            exp.NS.Add($"{domain}|@|{fqdn}");
            exp.NS.Add($"{domainDnsZone}|@|{fqdn}");
            if (isForestRootDc)
            {
                exp.NS.Add($"{msdcsZone}|@|{fqdn}");
                exp.NS.Add($"{forestDnsZone}|@|{fqdn}");
            }

            // PTR Records
            if (dc.IPv4Address != null)
            {
                var octets = dc.IPv4Address.ToString().Split('.');
                if (octets.Length == 4)
                {
                    var reverseZone = $"{octets[2]}.{octets[1]}.{octets[0]}.in-addr.arpa";
                    var ptrOwner = octets[3];
                    exp.PointerRecords.Add($"{reverseZone}|{ptrOwner}|{fqdn}");
                }
            }
        }

        return exp;
    }

    #endregion

    #region Internal Execution

    private async Task<DnsCleanupResult> ExecuteInternalAsync(
        IEnumerable<DcInfo> dcList,
        DnsCleanupOptions options,
        bool execute,
        IProgress<TaskProgressInfo>? progress,
        CancellationToken cancellationToken)
    {
        var result = new DnsCleanupResult { IsWhatIf = !execute };
        var totalStopwatch = Stopwatch.StartNew();
        var dcArray = dcList.ToArray();

        try
        {
            // Determine forest root
            var forestRoot = dcArray.FirstOrDefault(d => d.Type == "Forest Root")?.Domain
                ?? dcArray.FirstOrDefault()?.ForestRootFQDN
                ?? dcArray.FirstOrDefault()?.Domain;

            if (string.IsNullOrEmpty(forestRoot))
            {
                result.Message = "Could not determine forest root domain";
                result.Errors.Add(result.Message);
                return result;
            }

            forestRoot = NormalizeFqdn(forestRoot)!;
            var forestRootDn = GetDomainDn(forestRoot);

            // Get all domains
            var allDomains = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var dc in dcArray)
            {
                var d = NormalizeFqdn(dc.Domain);
                if (!string.IsNullOrEmpty(d))
                    allDomains.Add(d);
            }

            // Phase 1: Build Expected Records
            _logger?.LogInformation("DNS Cleanup: Building expected records for {Count} DCs...", dcArray.Length);
            progress?.Report(new TaskProgressInfo { PercentComplete = 5, Status = "Building expected records..." });

            var buildStopwatch = Stopwatch.StartNew();
            var expectedRecords = BuildExpectedRecords(dcArray, forestRoot);
            buildStopwatch.Stop();

            _logger?.LogInformation("DNS Cleanup: Built expected records in {Ms}ms - SRV={Srv}, CNAME={Cname}, NS={Ns}, A={A}",
                buildStopwatch.ElapsedMilliseconds, expectedRecords.SRV.Count, expectedRecords.CNAME.Count,
                expectedRecords.NS.Count, expectedRecords.A.Count);

            progress?.Report(new TaskProgressInfo { PercentComplete = 10, Status = "Discovering DNS zones..." });

            // Phase 2: Zone Discovery
            cancellationToken.ThrowIfCancellationRequested();
            var zones = await DiscoverZonesAsync(targetDc, forestRoot, forestRootDn, allDomains,
                                                 options.IncludeReverseZones, cancellationToken);
            result.ZonesDiscovered = zones.Count;

            _logger?.LogInformation("DNS Cleanup: Discovered {Count} zones", zones.Count);

            progress?.Report(new TaskProgressInfo { PercentComplete = 20, Status = $"Scanning {zones.Count} zones..." });

            // Phase 3: Parallel Zone Scanning
            var scanStopwatch = Stopwatch.StartNew();
            var targetCodes = GetTargetTypeCodes(options.RecordTypes);
            var allCandidates = new ConcurrentBag<DnsRecordCandidate>();
            var totalRecords = 0;

            var scanOptions = new ParallelOptions
            {
                MaxDegreeOfParallelism = options.MaxThreads,
                CancellationToken = cancellationToken
            };

            var zonesProcessed = 0;
            await Parallel.ForEachAsync(zones, scanOptions, async (zone, ct) =>
            {
                var scanResult = await ScanZoneAsync(zone, targetDc, targetCodes, expectedRecords, excludedFqdns, ct);

                Interlocked.Add(ref totalRecords, scanResult.RecordCount);
                foreach (var candidate in scanResult.Candidates)
                {
                    allCandidates.Add(candidate);
                }

                var processed = Interlocked.Increment(ref zonesProcessed);
                var pct = 20 + (int)((processed / (double)zones.Count) * 40);
                progress?.Report(new TaskProgressInfo
                {
                    PercentComplete = pct,
                    Status = $"Scanned {processed}/{zones.Count} zones",
                    CurrentItem = zone.Name
                });
            });

            scanStopwatch.Stop();
            result.ScanTime = scanStopwatch.Elapsed;
            result.RecordsScanned = totalRecords;
            result.CandidatesFound = allCandidates.Count;
            result.Candidates = allCandidates.OrderBy(c => c.ZoneName)
                .ThenBy(c => c.RecordType)
                .ThenBy(c => c.NodeName)
                .ToList();

            _logger?.LogInformation("DNS Cleanup: Scanned {Records} records, found {Candidates} candidates in {Ms}ms",
                totalRecords, allCandidates.Count, scanStopwatch.ElapsedMilliseconds);

            // Build stats
            result.ByReason = result.Candidates.GroupBy(c => c.Reason)
                .ToDictionary(g => g.Key, g => g.Count());
            result.ByRecordType = result.Candidates.GroupBy(c => c.RecordType)
                .ToDictionary(g => g.Key, g => g.Count());

            // Phase 4: Deletion (if execute mode)
            if (execute && result.Candidates.Count > 0)
            {
                progress?.Report(new TaskProgressInfo { PercentComplete = 65, Status = "Deleting records..." });

                var deleteStopwatch = Stopwatch.StartNew();
                await DeleteRecordsAsync(targetDc, result, options, progress, cancellationToken);
                deleteStopwatch.Stop();
                result.DeleteTime = deleteStopwatch.Elapsed;

                _logger?.LogInformation("DNS Cleanup: Deleted {Deleted}, NotFound {NotFound}, Failed {Failed} in {Ms}ms",
                    result.Deleted, result.NotFound, result.Failed, deleteStopwatch.ElapsedMilliseconds);
            }
            else if (!execute)
            {
                result.Skipped = result.Candidates.Count;
            }

            result.Success = true;
            result.Message = execute
                ? $"Deleted {result.Deleted} records, {result.NotFound} not found, {result.Failed} failed"
                : $"WhatIf: {result.Candidates.Count} records would be deleted";
        }
        catch (OperationCanceledException)
        {
            result.Message = "Operation cancelled";
            result.Errors.Add(result.Message);
        }
        catch (Exception ex)
        {
            result.Message = $"DNS cleanup failed: {ex.Message}";
            result.Errors.Add(ex.ToString());
            _logger?.LogError(ex, "DNS cleanup failed");
        }

        totalStopwatch.Stop();
        result.TotalTime = totalStopwatch.Elapsed;

        progress?.Report(new TaskProgressInfo { PercentComplete = 100, Status = result.Message });
        return result;
    }

    #endregion

    #region Zone Discovery

    private async Task<List<DnsZoneInfo>> DiscoverZonesAsync(
        string server, string forestRoot, string forestRootDn,
        HashSet<string> allDomains, bool includeReverse,
        CancellationToken cancellationToken)
    {
        var zones = new List<DnsZoneInfo>();
        var processedZones = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var domain in allDomains)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var domainDn = GetDomainDn(domain);

            var containers = new List<string>
            {
                $"CN=MicrosoftDNS,DC=DomainDnsZones,{domainDn}"
            };

            if (domain.Equals(forestRoot, StringComparison.OrdinalIgnoreCase))
            {
                containers.Add($"CN=MicrosoftDNS,DC=ForestDnsZones,{forestRootDn}");
            }

            containers.Add($"CN=MicrosoftDNS,CN=System,{domainDn}");

            foreach (var container in containers)
            {
                var containerZones = await Task.Run(() => GetZonesFromContainer(server, container), cancellationToken);
                foreach (var zone in containerZones)
                {
                    var zNorm = NormalizeFqdn(zone.Name);
                    if (string.IsNullOrEmpty(zNorm) || processedZones.Contains(zNorm))
                        continue;

                    var classification = ClassifyZone(zNorm, forestRoot, allDomains, includeReverse);
                    if (classification.Type == DnsZoneType.Skip)
                        continue;

                    zone.Classification = classification.Type;
                    zone.OwnerDomain = classification.Domain;
                    zones.Add(zone);
                    processedZones.Add(zNorm);
                }
            }
        }

        return zones;
    }

    private List<DnsZoneInfo> GetZonesFromContainer(string server, string container)
    {
        var zones = new List<DnsZoneInfo>();

        try
        {
            using var entry = new DirectoryEntry($"LDAP://{server}/{container}");
            using var searcher = new DirectorySearcher(entry)
            {
                Filter = "(objectClass=dnsZone)",
                SearchScope = SearchScope.OneLevel,
                PageSize = 1000
            };
            searcher.PropertiesToLoad.AddRange(ZoneProperties);

            using var results = searcher.FindAll();
            foreach (SearchResult r in results)
            {
                zones.Add(new DnsZoneInfo
                {
                    Name = r.Properties["name"][0]?.ToString() ?? "",
                    DistinguishedName = r.Properties["distinguishedName"][0]?.ToString() ?? "",
                    Container = container
                });
            }
        }
        catch (Exception ex)
        {
            _logger?.LogWarning("Failed to get zones from {Container}: {Error}", container, ex.Message);
        }

        return zones;
    }

    private static (DnsZoneType Type, string? Domain) ClassifyZone(string zoneName, string forestRoot,
                                                                 HashSet<string> allDomains, bool includeReverse)
    {
        var z = NormalizeFqdn(zoneName);
        if (string.IsNullOrEmpty(z))
            return (DnsZoneType.Skip, null);

        if (z.EndsWith(".in-addr.arpa", StringComparison.OrdinalIgnoreCase) ||
            z.EndsWith(".ip6.arpa", StringComparison.OrdinalIgnoreCase))
        {
            return includeReverse ? (DnsZoneType.Reverse, null) : (DnsZoneType.Skip, null);
        }

        if (z.Equals("trustanchors", StringComparison.OrdinalIgnoreCase))
            return (DnsZoneType.Skip, null);

        if (z.Equals($"_msdcs.{forestRoot}", StringComparison.OrdinalIgnoreCase))
            return (DnsZoneType.ForestMsdcs, forestRoot);

        if (z.Equals($"forestdnszones.{forestRoot}", StringComparison.OrdinalIgnoreCase))
            return (DnsZoneType.ForestDnsZones, forestRoot);

        foreach (var dom in allDomains)
        {
            var d = NormalizeFqdn(dom);
            if (string.IsNullOrEmpty(d)) continue;

            if (z.Equals(d, StringComparison.OrdinalIgnoreCase))
                return (DnsZoneType.DomainPrimary, d);

            if (z.Equals($"domaindnszones.{d}", StringComparison.OrdinalIgnoreCase))
                return (DnsZoneType.DomainDnsZones, d);

            if (z.Equals($"_msdcs.{d}", StringComparison.OrdinalIgnoreCase) &&
                !d.Equals(forestRoot, StringComparison.OrdinalIgnoreCase))
            {
                return (DnsZoneType.ChildMsdcs, d);
            }
        }

        return (DnsZoneType.Skip, null);
    }

    #endregion



    #region Zone Scanning

    private record ZoneScanResult(int RecordCount, List<DnsRecordCandidate> Candidates, string? Error);



    private static async Task<ZoneScanResult> ScanZoneAsync(
        DnsZoneInfo zone, string server,
        Dictionary<int, string> targetCodes,
        ExpectedDnsRecords expectedRecords,
        HashSet<string> excludedFqdns,
        CancellationToken cancellationToken)
    {
        var candidates = new List<DnsRecordCandidate>();
        var recordCount = 0;
        var zoneName = NormalizeFqdn(zone.Name)!;

        try
        {
            await Task.Run(() =>
            {
                using var entry = new DirectoryEntry($"LDAP://{server}/{zone.DistinguishedName}");
                using var searcher = new DirectorySearcher(entry)
                {
                    Filter = "(&(objectClass=dnsNode)(!(objectClass=dnsZone)))",
                    SearchScope = SearchScope.OneLevel,
                    PageSize = 1000
                };
                searcher.PropertiesToLoad.AddRange(RecordProperties);

                using var results = searcher.FindAll();
                foreach (SearchResult r in results)
                {
                    cancellationToken.ThrowIfCancellationRequested();

                    var nodeName = r.Properties["name"][0]?.ToString() ?? "";
                    var nodeDn = r.Properties["distinguishedName"][0]?.ToString() ?? "";

                    // Skip tombstoned records
                    if (r.Properties["dNSTombstoned"].Count > 0 && (bool)r.Properties["dNSTombstoned"][0])
                        continue;

                    if (r.Properties["dnsRecord"].Count > 0)
                    {
                        foreach (var rd in r.Properties["dnsRecord"])
                        {
                            var rawData = rd as byte[];
                            if (rawData == null) continue;

                            var parsed = ParseDnsRecord(rawData, nodeName, zone.Name, nodeDn);
                            if (parsed == null || parsed.TypeCode == 0)
                                continue;

                            if (!targetCodes.ContainsKey(parsed.TypeCode))
                                continue;

                            recordCount++;

                            var candidate = EvaluateRecord(parsed, zoneName, zone.Classification,
                                                            expectedRecords, excludedFqdns);
                            if (candidate != null)
                            {
                                candidates.Add(candidate);
                            }
                        }
                    }
                }
            }, cancellationToken);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            return new ZoneScanResult(0, new List<DnsRecordCandidate>(), ex.Message);
        }

        return new ZoneScanResult(recordCount, candidates, null);
    }



    private static DnsRecordCandidate? EvaluateRecord(
        ParsedDnsRecord record, string zoneName, DnsZoneType zoneType,
        ExpectedDnsRecords expected, HashSet<string> excludedFqdns)
    {
        var owner = NormalizeHost(record.NodeName);
        var target = NormalizeFqdn(record.Target);

        // Skip if target is excluded
        if (!string.IsNullOrEmpty(target) && excludedFqdns.Contains(target))
            return null;

        string? reason = null;

        switch (record.TypeCode)
        {
            case 33: // SRV
                if (string.IsNullOrEmpty(target)) break;
                var srvKey = $"{zoneName}|{owner}|{target}";
                if (!expected.SRV.Contains(srvKey) && !expected.AllowedFqdns.Contains(target))
                {
                    reason = "Unexpected SRV target";
                }
                break;

            case 5: // CNAME
                if (string.IsNullOrEmpty(owner) || string.IsNullOrEmpty(target)) break;
                if (zoneName.StartsWith("_msdcs.", StringComparison.OrdinalIgnoreCase) && IsGuid(owner))
                {
                    var cnameKey = $"{zoneName}|{owner}|{target}";
                    if (!expected.CNAME.Contains(cnameKey))
                    {
                        if (!expected.AllowedGuids.Contains(owner))
                            reason = "Unknown GUID CNAME";
                        else if (!expected.AllowedFqdns.Contains(target))
                            reason = "GUID CNAME unknown target";
                    }
                }
                break;

            case 2: // NS
                if (string.IsNullOrEmpty(target)) break;
                var nsKey = $"{zoneName}|{owner}|{target}";
                if (!expected.NS.Contains(nsKey) && !expected.AllowedFqdns.Contains(target))
                {
                    reason = "Unexpected NS target";
                }
                break;

            case 1: // A
                if (string.IsNullOrEmpty(owner) || string.IsNullOrEmpty(record.Target)) break;
                if (!IPAddress.TryParse(record.Target, out var ip4)) break;
                var aKey = $"{zoneName}|{owner}|{ip4}";
                if (!expected.A.Contains(aKey) && expected.AllowedHosts.Contains(owner))
                {
                    if (!expected.AllowedIps.Contains(ip4.ToString()))
                        reason = "DC hostname wrong IP";
                }
                break;

            case 28: // AAAA
                if (string.IsNullOrEmpty(owner) || string.IsNullOrEmpty(record.Target)) break;
                if (!IPAddress.TryParse(record.Target, out var ip6)) break;
                var aaaaKey = $"{zoneName}|{owner}|{ip6}";
                if (!expected.AAAA.Contains(aaaaKey) && expected.AllowedHosts.Contains(owner))
                {
                    if (!expected.AllowedIps.Contains(ip6.ToString()))
                        reason = "DC hostname wrong IPv6";
                }
                break;

            case 12: // PTR
                if (zoneType != DnsZoneType.Reverse) break;
                if (string.IsNullOrEmpty(owner) || string.IsNullOrEmpty(target)) break;
                var ptrKey = $"{zoneName}|{owner}|{target}";
                if (!expected.PointerRecords.Contains(ptrKey) && !expected.AllowedFqdns.Contains(target))
                {
                    reason = "Unexpected PTR target";
                }
                break;
        }

        if (reason == null)
            return null;

        return new DnsRecordCandidate
        {
            ZoneName = zoneName,
            ZoneDn = record.ZoneDn,
            NodeName = record.NodeName,
            Target = target,
            RecordType = record.TypeCode,
            Reason = reason
        };
    }

    #endregion



    #region Record Deletion

    private static async Task DeleteRecordsAsync(
        string server, DnsCleanupResult result,
        DnsCleanupOptions options,
        IProgress<TaskProgressInfo>? progress,
        CancellationToken cancellationToken)
    {
        var batches = result.Candidates
            .Select((c, i) => new { Candidate = c, Index = i })
            .GroupBy(x => x.Index / options.DeleteBatchSize)
            .Select(g => g.Select(x => x.Candidate).ToList())
            .ToList();

        var processed = 0;
        var deleted = 0;
        var notFound = 0;
        var failed = 0;

        foreach (var batch in batches)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var deleteOptions = new ParallelOptions
            {
                MaxDegreeOfParallelism = options.MaxThreads,
                CancellationToken = cancellationToken
            };

            await Parallel.ForEachAsync(batch, deleteOptions, async (candidate, ct) =>
            {
                var deleteResult = await Task.Run(() => DeleteRecord(server, candidate), ct);
                result.DeleteResults.Add(deleteResult);

                switch (deleteResult.Status)
                {
                    case DnsDeleteStatus.Deleted:
                        Interlocked.Increment(ref deleted);
                        break;
                    case DnsDeleteStatus.NotFound:
                        Interlocked.Increment(ref notFound);
                        break;
                    case DnsDeleteStatus.Failed:
                        Interlocked.Increment(ref failed);
                        result.Errors.Add($"Failed to delete {candidate.ZoneName}/{candidate.NodeName}: {deleteResult.Message}");
                        break;
                }
            });

            processed += batch.Count;
            var pct = 65 + (int)((processed / (double)result.Candidates.Count) * 30);
            progress?.Report(new TaskProgressInfo
            {
                PercentComplete = pct,
                Status = $"Deleted {deleted} records...",
                ItemsProcessed = processed,
                TotalItems = result.Candidates.Count
            });
        }

        result.Deleted = deleted;
        result.NotFound = notFound;
        result.Failed = failed;
    }



    private static DnsDeleteResult DeleteRecord(string server, DnsRecordCandidate candidate)
    {
        var result = new DnsDeleteResult { Record = candidate };

        try
        {
            using var entry = new DirectoryEntry($"LDAP://{server}/{candidate.NodeDn}");

            // Verify node exists
            try
            {
                _ = entry.Guid;
            }
            catch
            {
                result.Status = DnsDeleteStatus.NotFound;
                result.Message = "Node not found";
                return result;
            }

            // Find the matching record
            var dnsRecords = entry.Properties["dnsRecord"];
            var found = false;
            var matchIndex = -1;

            for (var i = 0; i < dnsRecords.Count; i++)
            {
                if (dnsRecords[i] is byte[] existingData && BytesEqual(existingData, candidate.RawData))
                {
                    found = true;
                    matchIndex = i;
                    break;
                }
            }

            if (!found)
            {
                result.Status = DnsDeleteStatus.NotFound;
                result.Message = "Record data changed";
                return result;
            }

            // Tombstone or remove record
            if (dnsRecords.Count <= 1)
            {
                // Last record - tombstone the node
                entry.Properties["dNSTombstoned"].Value = true;
                dnsRecords.Clear();
                dnsRecords.Add(CreateTombstoneRecord());
            }
            else
            {
                // Multiple records - remove just this one
                var keep = new List<byte[]>();
                for (var i = 0; i < dnsRecords.Count; i++)
                {
                    if (i != matchIndex && dnsRecords[i] is byte[] data)
                        keep.Add(data);
                }
                dnsRecords.Clear();
                foreach (var rec in keep)
                    dnsRecords.Add(rec);
            }

            entry.CommitChanges();
            result.Status = DnsDeleteStatus.Deleted;
        }
        catch (Exception ex)
        {
            if (ex.Message.Contains("not found", StringComparison.OrdinalIgnoreCase) ||
                ex.Message.Contains("does not exist", StringComparison.OrdinalIgnoreCase) ||
                ex.Message.Contains("no such object", StringComparison.OrdinalIgnoreCase))
            {
                result.Status = DnsDeleteStatus.NotFound;
            }
            else
            {
                result.Status = DnsDeleteStatus.Failed;
            }
            result.Message = ex.Message;
        }

        return result;
    }

    #endregion



    #region DNS Record Parsing

    private record ParsedDnsRecord(
        string NodeName, string ZoneName, string ZoneDn, string NodeDn,
        int TypeCode, string? Target, uint Ttl,
        ushort? Priority, ushort? Weight, ushort? Port,
        byte[] RawData);



    private static ParsedDnsRecord? ParseDnsRecord(byte[] data, string nodeName, string zoneName, string nodeDn)
    {
        if (data == null || data.Length < 24) return null;

        var dataLen = (data[1] << 8) | data[0];
        var typeCode = (data[3] << 8) | data[2];

        // Version, Rank, Flags, etc - skipped

        var ttl = (uint)((data[12] << 24) | (data[13] << 16) | (data[14] << 8) | data[15]);

        var recLen = Math.Min(dataLen, data.Length - 24);
        var recData = new byte[recLen];
        if (recLen > 0)
            Array.Copy(data, 24, recData, 0, recLen);

        string? target = null;
        ushort? priority = null, weight = null, port = null;

        switch (typeCode)
        {
            case 1: // A
                if (recData.Length >= 4)
                {
                    target = $"{recData[0]}.{recData[1]}.{recData[2]}.{recData[3]}";
                }
                break;

            case 28: // AAAA
                if (recData.Length >= 16)
                    target = new IPAddress(recData.Take(16).ToArray()).ToString();
                break;

            case 2: // NS
            case 5: // CNAME
            case 12: // PTR
                target = ParseDnsName(recData, 0);
                break;

            case 33: // SRV
                if (recData.Length >= 6)
                {
                    priority = BitConverter.ToUInt16(recData, 0);
                    weight = BitConverter.ToUInt16(recData, 2);
                    port = BitConverter.ToUInt16(recData, 4);
                    target = ParseDnsName(recData, 6);
                }
                break;
        }

        return new ParsedDnsRecord(nodeName, zoneName, "", nodeDn, typeCode, target, ttl,
            priority, weight, port, data);
    }



    private static string? ParseDnsName(byte[] data, int offset)
    {
        if (data == null || offset >= data.Length)
            return null;

        var labels = new List<string>();
        var pos = offset;

        if (pos >= data.Length) return null;
        var totalLen = data[pos];
        pos++;

        var endPos = Math.Min(pos + totalLen, data.Length);
        while (pos < endPos)
        {
            var labelLen = data[pos];
            pos++;

            if (labelLen == 0) break;
            if (pos + labelLen > data.Length) break;

            labels.Add(Encoding.ASCII.GetString(data, pos, labelLen));
            pos += labelLen;
        }

        return labels.Count == 0 ? null : string.Join(".", labels);
    }

    #endregion



    #region Helpers

    private static string? NormalizeFqdn(string? s)
    {
        if (string.IsNullOrWhiteSpace(s))
            return null;
        return s.Trim().TrimEnd('.').ToLowerInvariant();
    }

    private static string? NormalizeHost(string? s)
    {
        if (string.IsNullOrWhiteSpace(s))
            return null;
        return s.Trim().TrimEnd('.').ToLowerInvariant();
    }

    private static string? ExtractHostname(string? fqdn)
    {
        var n = NormalizeFqdn(fqdn);
        if (string.IsNullOrEmpty(n))
            return null;
        var i = n.IndexOf('.');
        return i > 0 ? n[..i] : n;
    }



    private static bool IsGuid(string? s)
    {
        if (string.IsNullOrWhiteSpace(s))
            return false;
        return Regex.IsMatch(s.Trim(), @"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
            RegexOptions.IgnoreCase);
    }



    private static string GetDomainDn(string fqdn)
    {
        return string.Join(",", fqdn.Split('.').Select(p => $"DC={p}"));
    }

    private static Dictionary<int, string> GetTargetTypeCodes(DnsRecordType recordTypes)
    {
        var codes = new Dictionary<int, string>();

        if (recordTypes.HasFlag(DnsRecordType.A)) codes[1] = "A";
        if (recordTypes.HasFlag(DnsRecordType.NS)) codes[2] = "NS";
        if (recordTypes.HasFlag(DnsRecordType.CNAME)) codes[5] = "CNAME";
        if (recordTypes.HasFlag(DnsRecordType.PtrRecord)) codes[12] = "PTR";
        if (recordTypes.HasFlag(DnsRecordType.AAAA)) codes[28] = "AAAA";
        if (recordTypes.HasFlag(DnsRecordType.SRV)) codes[33] = "SRV";

        return codes;
    }

    private static bool BytesEqual(byte[] a, byte[] b)
    {
        if (a == null && b == null) return true;
        if (a == null || b == null) return false;
        if (a.Length != b.Length) return false;

        for (var i = 0; i < a.Length; i++)
        {
            if (a[i] != b[i]) return false;
        }
        return true;
    }



    private static byte[] CreateTombstoneRecord()
    {
        var r = new byte[24];
        r[4] = 0x05; // Version
        return r;
    }

    #endregion
}

