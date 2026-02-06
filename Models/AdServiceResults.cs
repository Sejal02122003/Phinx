// --------------------------------------------------------------------------
// <copyright file="AdServiceResults.cs" company="Phoenix IR Platform">
//     © 2026 Phoenix IR Platform. All rights reserved.
//     Result types for AD service operations.
// </copyright>
// --------------------------------------------------------------------------

namespace Phoenix.Core.Models;

#region Forest Discovery Results

/// <summary>
/// Result of forest discovery operation - matches Get-ForestInfo output.
/// </summary>
public sealed class ForestDiscoveryResult
{
    public bool Success { get; set; }
    public string? ErrorMessage { get; set; }
    public string ForestName { get; set; } = string.Empty;
    public string ConfigurationNamingContext { get; set; } = string.Empty;
    public int TotalDomainControllers { get; set; }
    public int OnlineDomainControllers { get; set; }
    public List<Services.ActiveDirectory.Tasks.DomainControllerInfo> DomainControllers { get; set; } = new();
}

#endregion

#region AD IOE Scanner Results

/// <summary>
/// Result of AD IOE scan - matches Get-ADIOE output structure.
/// </summary>
public sealed class AdIoeScanResult
{
    public bool Success { get; set; }
    public Guid RunId { get; set; }
    public string? ErrorMessage { get; set; }
    public DateTime StartTime { get; set; }
    public DateTime EndTime { get; set; }
    public int TotalFindings { get; set; }
    public int CriticalCount { get; set; }
    public int WarningCount { get; set; }
    public int InformationalCount { get; set; }
    public List<IoeFinding> Findings { get; set; } = new();

    // Additional properties for comprehensive results
    public List<string> DomainsScanned { get; set; } = new();
    public int DCsScanned { get; set; }
    public Dictionary<string, Services.EvidenceCollection.Tasks.DcScanResult> DCResults { get; set; } = new();
    public Dictionary<string, int> CategoryStats { get; set; } = new();
}

#endregion
