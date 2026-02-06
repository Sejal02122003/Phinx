// --------------------------------------------------------------------------
// <copyright file="IoeEnums.cs" company="NCS Dojo">
//     © 2026 NCS Dojo. All rights reserved.
// </copyright>
// --------------------------------------------------------------------------

namespace Phoenix.Core.Domain.Enums;

/// <summary>
/// Categories for Active Directory Indicators of Exposure.
/// Based on the 119 IOE checks from the original Phoenix implementation.
/// </summary>
public enum IoeCategory
{
    /// <summary>Kerberos attack vectors (15 IOEs).</summary>
    Kerberos,

    /// <summary>Delegation abuse vectors (14 IOEs).</summary>
    Delegation,

    /// <summary>Privileged access concerns (22 IOEs).</summary>
    Privileged,

    /// <summary>Password security issues (15 IOEs).</summary>
    Password,

    /// <summary>Certificate and PKI issues (10 IOEs).</summary>
    Certificate,

    /// <summary>Domain-level configuration issues (12 IOEs).</summary>
    Domain,

    /// <summary>Domain Controller configuration issues (15 IOEs).</summary>
    DomainController,

    /// <summary>Domain Controller configuration issues (alias).</summary>
    DC = DomainController,

    /// <summary>Group Policy Object issues (8 IOEs).</summary>
    GroupPolicy,

    /// <summary>Group Policy Object issues (alias).</summary>
    GPO = GroupPolicy,

    /// <summary>Object-level security issues (8 IOEs).</summary>
    Objects
}

/// <summary>
/// Severity levels for IOE findings.
/// </summary>
public enum IoeSeverity
{
    /// <summary>Informational finding, low risk.</summary>
    Informational = 1,

    /// <summary>Warning level finding, moderate risk.</summary>
    Warning = 2,

    /// <summary>Critical finding, high risk requiring immediate attention.</summary>
    Critical = 3
}

/// <summary>
/// Task execution status.
/// </summary>
public enum OperationStatus
{
    /// <summary>Task has not been started.</summary>
    NotStarted = 0,

    /// <summary>Task is pending execution.</summary>
    Pending = 1,

    /// <summary>Task is currently running.</summary>
    InProgress = 2,

    /// <summary>Task completed successfully.</summary>
    Completed = 3,

    /// <summary>Task failed with errors.</summary>
    Failed = 4,

    /// <summary>Task was cancelled.</summary>
    Cancelled = 5,

    /// <summary>Task completed but with some errors.</summary>
    CompletedWithErrors = 6,

    /// <summary>Task is in simulation (WhatIf) mode.</summary>
    Simulating = 7,

    /// <summary>Task is waiting for user input.</summary>
    WaitingForInput = 8,

    /// <summary>Task was skipped.</summary>
    Skipped = 9
}

/// <summary>
/// Incident response phases.
/// </summary>
public enum IncidentPhase
{
    /// <summary>Initial assessment and discovery.</summary>
    Assessment = 0,

    /// <summary>Threat detection and alerting.</summary>
    Detection = 1,

    /// <summary>Detailed analysis and forensics.</summary>
    contain = 2,

    /// <summary>Eradication of the threat.</summary>
    Eradication = 3,

    /// <summary>Recovery and restoration.</summary>
    Recovery = 4,

    /// <summary>Incident closure and reporting.</summary>
    Review = 5
}

/// <summary>
/// Types of Azure/Entra ID authentication methods.
/// </summary>
public enum AzureAuthMethod
{
    /// <summary>Device code flow for interactive authentication.</summary>
    DeviceCode = 1,

    /// <summary>Client secret for application authentication.</summary>
    ClientSecret = 2,

    /// <summary>Certificate-based authentication.</summary>
    Certificate = 3,

    /// <summary>Resource Owner Password Credentials (legacy, not recommended).</summary>
    Ropc = 4,

    /// <summary>Externally provided access token.</summary>
    ExternalToken = 5,

    /// <summary>Managed Identity (Azure-hosted scenarios).</summary>
    ManagedIdentity = 6
}

/// <summary>
/// Azure resource types for authentication scopes.
/// </summary>
public enum AzureResourceType
{
    /// <summary>Microsoft Graph API.</summary>
    Graph = 1,

    /// <summary>Azure Resource Manager (ARM).</summary>
    AzureResourceManager = 2,

    /// <summary>Exchange Online.</summary>
    Exchange = 3,

    /// <summary>SharePoint Online.</summary>
    SharePoint = 4,

    /// <summary>Key Vault.</summary>
    KeyVault = 5
}

/// <summary>
/// FSMO (Flexible Single Master Operation) roles.
/// </summary>
[Flags]
public enum FsmoRoles
{
    /// <summary>No FSMO roles.</summary>
    None = 0,

    /// <summary>Schema Master role.</summary>
    SchemaMaster = 1,

    /// <summary>Domain Naming Master role.</summary>
    DomainNamingMaster = 2,

    /// <summary>PDC Emulator role.</summary>
    PdcEmulator = 4,

    /// <summary>RID Master role.</summary>
    RidMaster = 8,

    /// <summary>Infrastructure Master role.</summary>
    InfrastructureMaster = 16,

    /// <summary>All domain-level FSMO roles.</summary>
    AllDomainRoles = PdcEmulator | RidMaster | InfrastructureMaster,

    /// <summary>All forest-level FSMO roles.</summary>
    AllForestRoles = SchemaMaster | DomainNamingMaster,

    /// <summary>All FSMO roles.</summary>
    All = AllDomainRoles | AllForestRoles
}

/// <summary>
/// Log entry severity levels.
/// </summary>
public enum LogLevel
{
    /// <summary>Trace level for debugging.</summary>
    Trace = 0,

    /// <summary>Debug level information.</summary>
    Debug = 1,

    /// <summary>Informational messages.</summary>
    Information = 2,

    /// <summary>Warning messages.</summary>
    Warning = 3,

    /// <summary>Error messages.</summary>
    Error = 4,

    /// <summary>Critical failure messages.</summary>
    Critical = 5
}

/// <summary>
/// Audit event types for security logging.
/// </summary>
public enum AuditEventType
{
    /// <summary>User authentication event.</summary>
    Authentication = 1,

    /// <summary>Authorization check event.</summary>
    Authorization = 2,

    /// <summary>Configuration change event.</summary>
    ConfigurationChange = 3,

    /// <summary>Task execution event.</summary>
    TaskExecution = 4,

    /// <summary>Data access event.</summary>
    DataAccess = 5,

    /// <summary>Security scan event.</summary>
    SecurityScan = 6,

    /// <summary>Credential operation event.</summary>
    CredentialOperation = 7,

    /// <summary>Application lifecycle event.</summary>
    ApplicationLifecycle = 8
}
