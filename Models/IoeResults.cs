// --------------------------------------------------------------------------
// <copyright file="IoeResult.cs" company="NCS Dojo">
//     © 2026 NCS Dojo. All rights reserved.
//     Faithful C# conversion of PowerShell Phoenix module.
// </copyright>
// --------------------------------------------------------------------------

namespace Phoenix.Core.Models;

/// <summary>
/// Result from Get-ADIOE scan matching PowerShell output.
/// </summary>
public class IoeResult
{
    public bool Success { get; set; }
    public Guid RunId { get; set; } = Guid.NewGuid();
    public DateTime StartTime { get; set; } = DateTime.UtcNow;
    public DateTime? EndTime { get; set; }
    public List<IoeFindingResult> Findings { get; set; } = new();
    public Dictionary<string, int> SummaryByDomain { get; set; } = new();
    public Dictionary<string, int> SummaryBySeverity { get; set; } = new();
    public Dictionary<string, int> SummaryByCategory { get; set; } = new();
    public string? ExportPath { get; set; }
    public string? ErrorMessage { get; set; }
}

/// <summary>
/// Individual IOE finding matching PowerShell output.
/// </summary>
public class IoeFindingResult
{
    public string IoeId { get; set; } = string.Empty;
    public string IoeName { get; set; } = string.Empty;
    public string Category { get; set; } = string.Empty;
    public string Severity { get; set; } = string.Empty;
    public string Domain { get; set; } = string.Empty;
    public string DomainController { get; set; } = string.Empty;
    public string AffectedObjectDn { get; set; } = string.Empty;
    public string SamAccountName { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public string Remediation { get; set; } = string.Empty;
    public string MitreAttackTechnique { get; set; } = string.Empty;
    public DateTime DetectedAt { get; set; } = DateTime.UtcNow;
    public Dictionary<string, object> AdditionalData { get; set; } = new();
}

/// <summary>
/// Azure IOE result matching PowerShell output.
/// </summary>
public class AzureIoeResult
{
    public bool Success { get; set; }
    public Guid RunId { get; set; } = Guid.NewGuid();
    public DateTime StartTime { get; set; } = DateTime.UtcNow;
    public DateTime? EndTime { get; set; }
    public string TenantId { get; set; } = string.Empty;
    public List<AzureIoeFinding> Findings { get; set; } = new();
    public Dictionary<string, int> SummaryBySeverity { get; set; } = new();
    public Dictionary<string, int> SummaryByCategory { get; set; } = new();
    public string? ExportPath { get; set; }
    public string? ErrorMessage { get; set; }
}

/// <summary>
/// Azure IOE finding matching PowerShell output.
/// </summary>
public class AzureIoeFindingResult
{
    public string IoeId { get; set; } = string.Empty;
    public string IoeName { get; set; } = string.Empty;
    public string Category { get; set; } = string.Empty;
    public string Severity { get; set; } = string.Empty;
    public string AffectedObjectId { get; set; } = string.Empty;
    public string AffectedObjectType { get; set; } = string.Empty;
    public string DisplayName { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public string Remediation { get; set; } = string.Empty;
    public DateTime DetectedAt { get; set; } = DateTime.UtcNow;
    public Dictionary<string, object> AdditionalData { get; set; } = new();
}

/// <summary>
/// Progress information for scans.
/// </summary>
public class ScanProgress
{
    public int PercentComplete { get; set; }
    public string Status { get; set; } = string.Empty;
    public string CurrentItem { get; set; } = string.Empty;
    public int ItemsProcessed { get; set; }
    public int TotalItems { get; set; }
}

/// <summary>
/// AD IOE Categories matching PowerShell ValidateSet.
/// </summary>
public enum AdIoeCategory
{
    All,
    Kerberos,
    Delegation,
    Privileged,
    Password,
    Certificate,
    Domain,
    DC,
    GPO,
    Objects
}

/// <summary>
/// Azure IOE Categories matching PowerShell ValidateSet.
/// </summary>
public enum AzureIoeCategory
{
    All,
    Authentication,
    Authorization,
    Privileged,
    PrivAccess,
    MFA,
    Applications,
    Guests,
    GuestUsers,
    Policies,
    Identity
}

/// <summary>
/// Azure IOE finding (internal use by scanner)
/// </summary>
public class AzureIoeFinding
{
    public string IoeId { get; set; } = string.Empty;
    public string IoeName { get; set; } = string.Empty;
    public string Category { get; set; } = string.Empty;
    public string Severity { get; set; } = string.Empty;
    public string Target { get; set; } = string.Empty;
    public string Detail { get; set; } = string.Empty;
    public DateTime DetectedAt { get; set; } = DateTime.UtcNow;
}
