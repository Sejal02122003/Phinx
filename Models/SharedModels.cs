// ------------------------------------------------------------------------------
// Phoenix Infrastructure - Shared Models
// ------------------------------------------------------------------------------

namespace Phoenix.Core.Models;

// === Active Directory Models ===

/// <summary>
/// Represents RootDSE information from a domain controller.
/// </summary>
public sealed record RootDseInfo
{
    public string DefaultNamingContext { get; init; } = string.Empty;
    public string ConfigurationNamingContext { get; init; } = string.Empty;
    public string SchemaNamingContext { get; init; } = string.Empty;
    public string RootDomainNamingContext { get; init; } = string.Empty;
    public string DnsHostName { get; init; } = string.Empty;
    public string ServerName { get; init; } = string.Empty;
    public string[] SupportedLdapVersions { get; init; } = [];
    public string[] SupportedSaslMechanisms { get; init; } = [];
    public string[] SupportedControls { get; init; } = [];
    public string[] SupportedLdapPolicies { get; init; } = [];
    public int ForestFunctionality { get; init; }
    public int DomainFunctionality { get; init; }
    public int DcFunctionality { get; init; }
    public string ForestFunctionalLevel { get; init; } = string.Empty;
    public string DomainFunctionalLevel { get; init; } = string.Empty;
}

/// <summary>
/// Represents domain information.
/// </summary>
public class DomainInfo
{
    public string DistinguishedName { get; set; } = string.Empty;
    public string DnsName { get; set; } = string.Empty;
    public string NetBiosName { get; set; } = string.Empty;
    public bool IsForestRoot { get; set; }
    public string FunctionalLevel { get; set; } = string.Empty;
}

/// <summary>
/// IOE Finding result.
/// </summary>
public sealed class IoeFinding
{
    public Guid Id { get; init; } = Guid.NewGuid();
    public Guid ScanRunId { get; init; }
    public string IoeId { get; init; } = string.Empty;
    public string IoeName { get; init; } = string.Empty;
    public string Description { get; init; } = string.Empty;
    public string Severity { get; set; } = string.Empty;
    public string Category { get; init; } = string.Empty;
    public string DistinguishedName { get; init; } = string.Empty;
    public string ObjectName { get; set; } = string.Empty;
    public string Details { get; set; } = string.Empty;
    public string SamAccountName { get; set; } = string.Empty;
    public string DomainController { get; set; } = string.Empty;
    public string Domain { get; set; } = string.Empty;
    public string Remediation { get; init; } = string.Empty;
    public string MitreAttackTechnique { get; init; } = string.Empty;
    public DateTime DetectedAt { get; init; } = DateTime.UtcNow;
    public Dictionary<string, object> AdditionalData { get; init; } = [];

    /// <summary>
    /// Gets or sets the Indicator of Exposure reference.
    /// </summary>
    public Phoenix.Core.Domain.Entities.IndicatorOfExposure? Ioe { get; set; }

    /// <summary>
    /// Gets the affected object DN (alias for DistinguishedName).
    /// </summary>
    public string AffectedObjectDn => DistinguishedName;

    /// <summary>
    /// Gets or sets whether this finding has been acknowledged.
    /// </summary>
    public bool IsAcknowledged { get; set; }

    /// <summary>
    /// Gets or sets the acknowledged date.
    /// </summary>
    public DateTime? AcknowledgedAt { get; set; }

    /// <summary>
    /// Gets or sets the user who acknowledged this finding.
    /// </summary>
    public string? AcknowledgedBy { get; set; }

    public IoeFinding() { }

    public IoeFinding(Guid scanRunId, Phoenix.Core.Domain.Entities.IndicatorOfExposure ioe, string distinguishedName)
    {
        ScanRunId = scanRunId;
        IoeId = ioe.IoeId;
        IoeName = ioe.Name;
        Description = ioe.Description;
        Severity = ioe.DefaultSeverity.ToString();
        Category = ioe.Category.ToString();
        DistinguishedName = distinguishedName;
        Remediation = ioe.Remediation;
        MitreAttackTechnique = ioe.MitreAttackTechnique;
        Ioe = ioe;
    }

    /// <summary>
    /// Acknowledges this finding.
    /// </summary>
    /// <param name="acknowledgedBy">User acknowledging the finding.</param>
    /// <param name="reason">Reason for acknowledgment.</param>
    public void Acknowledge(string? acknowledgedBy = null, string? reason = null)
    {
        IsAcknowledged = true;
        AcknowledgedAt = DateTime.UtcNow;
        AcknowledgedBy = acknowledgedBy ?? Environment.UserName;
        if (!string.IsNullOrEmpty(reason))
        {
            AdditionalData["AcknowledgmentReason"] = reason;
        }
    }
}

// === Azure/Graph Models ===

/// <summary>
/// Graph API user representation.
/// </summary>
public class GraphUser
{
    public string Id { get; set; } = string.Empty;
    public string DisplayName { get; set; } = string.Empty;
    public string UserPrincipalName { get; set; } = string.Empty;
    public string Mail { get; set; } = string.Empty;
    public string GivenName { get; set; } = string.Empty;
    public string Surname { get; set; } = string.Empty;
    public string JobTitle { get; set; } = string.Empty;
    public string Department { get; set; } = string.Empty;
    public bool AccountEnabled { get; set; }
    public DateTime? CreatedDateTime { get; set; }
    public DateTime? LastSignInDateTime { get; set; }
    public string OnPremisesSamAccountName { get; set; } = string.Empty;
    public string OnPremisesDistinguishedName { get; set; } = string.Empty;
    public bool OnPremisesSyncEnabled { get; set; }
    public List<string> AssignedLicenses { get; set; } = [];
    public List<string> MemberOf { get; set; } = [];
}

/// <summary>
/// Graph API group representation.
/// </summary>
public class GraphGroup
{
    public string Id { get; set; } = string.Empty;
    public string DisplayName { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public string Mail { get; set; } = string.Empty;
    public bool SecurityEnabled { get; set; }
    public bool MailEnabled { get; set; }
    public string GroupTypes { get; set; } = string.Empty;
    public string Visibility { get; set; } = string.Empty;
    public DateTime? CreatedDateTime { get; set; }
    public bool OnPremisesSyncEnabled { get; set; }
    public List<string> Members { get; set; } = [];
    public List<string> Owners { get; set; } = [];
}

/// <summary>
/// Graph API directory object.
/// </summary>
public class GraphDirectoryObject
{
    public string Id { get; set; } = string.Empty;
    public string DisplayName { get; set; } = string.Empty;
    public string ObjectType { get; set; } = string.Empty;
    public string Type { get; set; } = string.Empty;
    public string UserType { get; set; } = string.Empty;
    public string OdataType { get; set; } = string.Empty;
}

/// <summary>
/// Graph API application.
/// </summary>
public class GraphApplication
{
    public string Id { get; set; } = string.Empty;
    public string AppId { get; set; } = string.Empty;
    public string DisplayName { get; set; } = string.Empty;
    public DateTime? CreatedDateTime { get; set; }
    public List<PasswordCredential> PasswordCredentials { get; set; } = [];
    public List<KeyCredential> KeyCredentials { get; set; } = [];
    public List<string> IdentifierUris { get; set; } = [];
    public string SignInAudience { get; set; } = string.Empty;
}

/// <summary>
/// Graph API service principal.
/// </summary>
public class GraphServicePrincipal
{
    public string Id { get; set; } = string.Empty;
    public string AppId { get; set; } = string.Empty;
    public string DisplayName { get; set; } = string.Empty;
    public string ServicePrincipalType { get; set; } = string.Empty;
    public bool AccountEnabled { get; set; }
    public bool PublisherVerified { get; set; }
    public string? PublisherName { get; set; }
    public List<PasswordCredential> PasswordCredentials { get; set; } = [];
    public List<KeyCredential> KeyCredentials { get; set; } = [];
}

/// <summary>
/// Password credential for application/service principal.
/// </summary>
public class PasswordCredential
{
    public string KeyId { get; set; } = string.Empty;
    public string DisplayName { get; set; } = string.Empty;
    public DateTime? StartDateTime { get; set; }
    public DateTime? EndDateTime { get; set; }
    public string Hint { get; set; } = string.Empty;
}

/// <summary>
/// Key credential for application/service principal.
/// </summary>
public class KeyCredential
{
    public string KeyId { get; set; } = string.Empty;
    public string DisplayName { get; set; } = string.Empty;
    public DateTime? StartDateTime { get; set; }
    public DateTime? EndDateTime { get; set; }
    public string Type { get; set; } = string.Empty;
    public string Usage { get; set; } = string.Empty;
}

/// <summary>
/// Device code flow response.
/// </summary>
public class DeviceCodeResponse
{
    public string DeviceCode { get; set; } = string.Empty;
    public string UserCode { get; set; } = string.Empty;
    public string VerificationUri { get; set; } = string.Empty;
    public int ExpiresIn { get; set; }
    public int Interval { get; set; }
    public string Message { get; set; } = string.Empty;
}

/// <summary>
/// OAuth token response.
/// </summary>
public class TokenResponse
{
    public string AccessToken { get; set; } = string.Empty;
    public string TokenType { get; set; } = string.Empty;
    public int ExpiresIn { get; set; }
    public string RefreshToken { get; set; } = string.Empty;
    public string Scope { get; set; } = string.Empty;
    public DateTime ExpiresAt { get; set; }
}

/// <summary>
/// Authentication method enumeration.
/// </summary>
public enum AuthenticationMethod
{
    DeviceCode,
    ClientSecret,
    Certificate,
    ManagedIdentity,
    InteractiveBrowser
}

/// <summary>
/// Authorization policy information.
/// </summary>
public class AuthorizationPolicyInfo
{
    public string Id { get; set; } = string.Empty;
    public string DisplayName { get; set; } = string.Empty;
    public bool BlockLegacyAuth { get; set; }
    public string? GuestUserRoleId { get; set; }
    public string GuestUserRole { get; set; } = string.Empty;
    public string AllowInvitesFrom { get; set; } = string.Empty;
    public bool BlockMsolPowerShell { get; set; }
    public DefaultUserRolePermissionsInfo? DefaultUserRolePermissions { get; set; }
    public bool AllowedToCreateApps { get; set; }
    public bool AllowedToCreateSecurityGroups { get; set; }
    public bool AllowedToReadOtherUsers { get; set; }
    public bool GuestUserRestrictions { get; set; }
}

/// <summary>
/// Default user role permissions info.
/// </summary>
public class DefaultUserRolePermissionsInfo
{
    public bool AllowedToCreateApps { get; set; }
    public bool AllowedToCreateSecurityGroups { get; set; }
    public bool AllowedToReadOtherUsers { get; set; }
}

/// <summary>
/// Authorization policy update request.
/// </summary>
public class AuthorizationPolicyUpdate
{
    public bool AllowedToCreateApps { get; set; }
    public bool AllowedToCreateSecurityGroups { get; set; }
    public string? AllowInvitesFrom { get; set; }
    public bool BlockMsolPowerShell { get; set; }
    public string? GuestUserRoleId { get; set; }
}

/// <summary>
/// Consent policy information from Graph API.
/// </summary>
public class ConsentPolicyInfo
{
    public string Id { get; set; } = string.Empty;
    public bool IsEnabled { get; set; }
    public bool UserConsentAllowed { get; set; }
    public bool NotifyReviewers { get; set; }
    public bool RemindersEnabled { get; set; }
    public int RequestDurationInDays { get; set; }
}

/// <summary>
/// Conditional access policy.
/// </summary>
public class ConditionalAccessPolicy
{
    public string Id { get; set; } = string.Empty;
    public string DisplayName { get; set; } = string.Empty;
    public string State { get; set; } = string.Empty;
    public DateTime? CreatedDateTime { get; set; }
    public DateTime? ModifiedDateTime { get; set; }
    public ConditionalAccessConditions? Conditions { get; set; }
    public ConditionalAccessGrantControls? GrantControls { get; set; }
}

/// <summary>
/// Conditional access conditions.
/// </summary>
public class ConditionalAccessConditions
{
    public ConditionalAccessUsers? Users { get; set; }
    public ConditionalAccessApplications? Applications { get; set; }
    public List<string> Platforms { get; set; } = [];
    public List<string> Locations { get; set; } = [];
    public List<string> ClientAppTypes { get; set; } = [];
    public List<string> SignInRiskLevels { get; set; } = [];
    public List<string> UserRiskLevels { get; set; } = [];
}

/// <summary>
/// Conditional access users.
/// </summary>
public class ConditionalAccessUsers
{
    public List<string> IncludeUsers { get; set; } = [];
    public List<string> ExcludeUsers { get; set; } = [];
    public List<string> IncludeGroups { get; set; } = [];
    public List<string> ExcludeGroups { get; set; } = [];
    public List<string> IncludeRoles { get; set; } = [];
    public List<string> ExcludeRoles { get; set; } = [];
}

/// <summary>
/// Conditional access applications.
/// </summary>
public class ConditionalAccessApplications
{
    public List<string> IncludeApplications { get; set; } = [];
    public List<string> ExcludeApplications { get; set; } = [];
    public List<string> IncludeUserActions { get; set; } = [];
}

/// <summary>
/// Conditional access grant controls.
/// </summary>
public class ConditionalAccessGrantControls
{
    public string Operator { get; set; } = string.Empty;
    public List<string> BuiltInControls { get; set; } = [];
    public List<string> CustomAuthenticationFactors { get; set; } = [];
    public List<string> TermsOfUse { get; set; } = [];
}

/// <summary>
/// Guard rails application options.
/// </summary>
public class GuardRailsApplicationOptions
{
    public bool Execute { get; set; } = true;
    public bool EnforceConditionalAccess { get; set; }
    public bool EnforceMfa { get; set; }
    public bool BlockLegacyAuth { get; set; }
    public bool RequireMfaForAdmins { get; set; }
    public bool RequireMfaForAllUsers { get; set; }
    public bool BlockRiskySignIns { get; set; }
    public bool DisableAdminSspr { get; set; }
    public bool EnableSecurityDefaults { get; set; }
    public bool HardenAuthorizationPolicy { get; set; }
    public bool RestrictUserConsent { get; set; }
    public bool ConfigureAuthorizationPolicy { get; set; }
    public bool RestrictUserSettings { get; set; }
    public bool RestrictGuestAccess { get; set; }
    public bool RestrictAppConsent { get; set; }
    public bool ReviewSecurityDefaults { get; set; }
    public List<string> AllowedLocations { get; set; } = [];
    public List<string> AllowedDevicePlatforms { get; set; } = [];
}

/// <summary>
/// Guard rails application result.
/// </summary>
public class GuardRailsApplicationResult
{
    public bool Success { get; set; }
    public int PoliciesCreated { get; set; }
    public int PoliciesUpdated { get; set; }
    public bool LegacyAuthBlocked { get; set; }
    public bool AdminMfaRequired { get; set; }
    public bool AllUsersMfaRequired { get; set; }
    public bool RiskySignInsBlocked { get; set; }
    public bool UserConsentRestricted { get; set; }
    public bool AdminSsprDisabled { get; set; }
    public bool SecurityDefaultsEnabled { get; set; }
    public bool AuthorizationPolicyHardened { get; set; }
    public bool AuthorizationPolicyConfigured { get; set; }
    public bool UserSettingsConfigured { get; set; }
    public bool GuestSettingsConfigured { get; set; }
    public bool AppConsentConfigured { get; set; }
    public bool SecurityDefaultsReviewed { get; set; }
    public bool IsWhatIf { get; set; }
    public DateTime StartTime { get; set; } = DateTime.UtcNow;
    public DateTime EndTime { get; set; } = DateTime.UtcNow;
    public string? ErrorMessage { get; set; }
    public List<string> Errors { get; set; } = [];
    public List<string> Warnings { get; set; } = [];
}

// === Authorization Policy Service Interface ===

public interface IAuthorizationPolicyService
{
    Task<AuthorizationPolicyInfo?> GetAuthorizationPolicyAsync(CancellationToken cancellationToken = default);
    Task<bool> UpdateAuthorizationPolicyAsync(AuthorizationPolicyInfo policy, CancellationToken cancellationToken = default);
}

// === Additional AD Models ===

/// <summary>
/// AD Site information.
/// </summary>
public class SiteInfo
{
    public string Name { get; set; } = string.Empty;
    public string DistinguishedName { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public string Location { get; set; } = string.Empty;
    public List<string> Subnets { get; set; } = [];
    public List<string> Servers { get; set; } = [];
    public List<string> SiteLinks { get; set; } = [];
}

/// <summary>
/// Server information within a site.
/// </summary>
public class ServerInfo
{
    public string Name { get; set; } = string.Empty;
    public string DnsHostName { get; set; } = string.Empty;
    public string Site { get; set; } = string.Empty;
    public string ComputerDn { get; set; } = string.Empty;
    public bool IsGlobalCatalog { get; set; }
    public string OperatingSystem { get; set; } = string.Empty;
}

/// <summary>
/// FSMO role holders.
/// </summary>
public class FsmoRoleHolders
{
    public string SchemaMaster { get; set; } = string.Empty;
    public string DomainNamingMaster { get; set; } = string.Empty;
    public string PdcEmulator { get; set; } = string.Empty;
    public string RidMaster { get; set; } = string.Empty;
    public string InfrastructureMaster { get; set; } = string.Empty;
}

/// <summary>
/// Discovery progress callback.
/// </summary>
public class DiscoveryProgress
{
    public string Phase { get; set; } = string.Empty;
    public string CurrentItem { get; set; } = string.Empty;
    public int PercentComplete { get; set; }
    public string Message { get; set; } = string.Empty;

    public DiscoveryProgress() { }

    public DiscoveryProgress(string phase, string message)
    {
        Phase = phase;
        Message = message;
    }

    public DiscoveryProgress(int percentComplete, string message)
    {
        PercentComplete = percentComplete;
        Message = message;
    }
}

// === Additional Azure/Graph Models ===

/// <summary>
/// Authentication result from Graph API.
/// </summary>
public class AuthenticationResult
{
    public bool Success { get; set; }
    public string AccessToken { get; set; } = string.Empty;
    public DateTimeOffset ExpiresOn { get; set; }
    public string TenantId { get; set; } = string.Empty;
    public string Account { get; set; } = string.Empty;
    public string ClientId { get; set; } = string.Empty;
    public string? ErrorMessage { get; set; }
}

/// <summary>
/// Device code result for interactive auth.
/// </summary>
public class DeviceCodeResult
{
    public bool Success { get; set; }
    public string DeviceCode { get; set; } = string.Empty;
    public string UserCode { get; set; } = string.Empty;
    public string VerificationUrl { get; set; } = string.Empty;
    public string VerificationUri { get; set; } = string.Empty;
    public string Message { get; set; } = string.Empty;
    public int ExpiresIn { get; set; }
    public DateTimeOffset ExpiresOn { get; set; }
    public string AccessToken { get; set; } = string.Empty;
    public string TenantId { get; set; } = string.Empty;
    public string UserPrincipalName { get; set; } = string.Empty;
    public string? ErrorMessage { get; set; }
}

/// <summary>
/// Device code info for callback.
/// </summary>
public class DeviceCodeInfo
{
    public string UserCode { get; set; } = string.Empty;
    public string VerificationUri { get; set; } = string.Empty;
    public string Message { get; set; } = string.Empty;
}

/// <summary>
/// Role definition from Graph API.
/// </summary>
public class RoleDefinition
{
    public string Id { get; set; } = string.Empty;
    public string DisplayName { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public bool IsBuiltIn { get; set; }
    public bool IsEnabled { get; set; }
    public List<string> RolePermissions { get; set; } = [];
}

/// <summary>
/// Role assignment from Graph API.
/// </summary>
public class RoleAssignment
{
    public string Id { get; set; } = string.Empty;
    public string PrincipalId { get; set; } = string.Empty;
    public string RoleDefinitionId { get; set; } = string.Empty;
    public string DirectoryScopeId { get; set; } = string.Empty;
    public string PrincipalDisplayName { get; set; } = string.Empty;
    public string RoleDisplayName { get; set; } = string.Empty;
    public string RoleName { get; set; } = string.Empty;
    public GraphDirectoryObject? Principal { get; set; }
    public bool IsPimManaged { get; set; }
}

/// <summary>
/// Graph API authentication method info.
/// </summary>
public class GraphAuthMethod
{
    public string Id { get; set; } = string.Empty;
    public string OdataType { get; set; } = string.Empty;
    public string MethodType { get; set; } = string.Empty;
}

/// <summary>
/// PIM role assignment.
/// </summary>
public class PimRoleAssignment
{
    public string Id { get; set; } = string.Empty;
    public string PrincipalId { get; set; } = string.Empty;
    public string RoleDefinitionId { get; set; } = string.Empty;
    public string DirectoryScopeId { get; set; } = string.Empty;
    public string MemberType { get; set; } = string.Empty;
    public string AssignmentType { get; set; } = string.Empty;
    public DateTime? StartDateTime { get; set; }
    public DateTime? EndDateTime { get; set; }
    public string Status { get; set; } = string.Empty;
}

/// <summary>
/// Sign-in log entry.
/// </summary>
public class SignInLog
{
    public string Id { get; set; } = string.Empty;
    public DateTime CreatedDateTime { get; set; }
    public string UserPrincipalName { get; set; } = string.Empty;
    public string UserDisplayName { get; set; } = string.Empty;
    public string AppDisplayName { get; set; } = string.Empty;
    public string IpAddress { get; set; } = string.Empty;
    public string Location { get; set; } = string.Empty;
    public string Status { get; set; } = string.Empty;
    public string ClientAppUsed { get; set; } = string.Empty;
    public bool IsInteractive { get; set; }
    public string RiskLevel { get; set; } = string.Empty;
    public string RiskState { get; set; } = string.Empty;
}

/// <summary>
/// Audit log entry.
/// </summary>
public class AuditLog
{
    public string Id { get; set; } = string.Empty;
    public DateTime ActivityDateTime { get; set; }
    public string ActivityDisplayName { get; set; } = string.Empty;
    public string Category { get; set; } = string.Empty;
    public string OperationType { get; set; } = string.Empty;
    public string Result { get; set; } = string.Empty;
    public string InitiatedByUser { get; set; } = string.Empty;
    public string InitiatedByApp { get; set; } = string.Empty;
    public List<string> TargetResources { get; set; } = [];
}

/// <summary>
/// App role assignment.
/// </summary>
public class AppRoleAssignment
{
    public string Id { get; set; } = string.Empty;
    public string AppRoleId { get; set; } = string.Empty;
    public string PrincipalId { get; set; } = string.Empty;
    public string PrincipalDisplayName { get; set; } = string.Empty;
    public string ResourceId { get; set; } = string.Empty;
    public string ResourceDisplayName { get; set; } = string.Empty;
    public DateTime? CreatedDateTime { get; set; }
}

/// <summary>
/// OAuth2 permission grant.
/// </summary>
public class OAuth2PermissionGrant
{
    public string Id { get; set; } = string.Empty;
    public string ClientId { get; set; } = string.Empty;
    public string ConsentType { get; set; } = string.Empty;
    public string PrincipalId { get; set; } = string.Empty;
    public string ResourceId { get; set; } = string.Empty;
    public string Scope { get; set; } = string.Empty;
    public string Name => Scope; // Alias for Scope for compatibility
}

/// <summary>
/// Graph organization info.
/// </summary>
public class GraphOrganization
{
    public string Id { get; set; } = string.Empty;
    public string DisplayName { get; set; } = string.Empty;
    public List<string> VerifiedDomains { get; set; } = [];
    public string TenantType { get; set; } = string.Empty;
    public DateTime? CreatedDateTime { get; set; }
}

/// <summary>
/// Graph domain info.
/// </summary>
public class GraphDomain
{
    public string Id { get; set; } = string.Empty;
    public bool IsDefault { get; set; }
    public bool IsInitial { get; set; }
    public bool IsVerified { get; set; }
    public string AuthenticationType { get; set; } = string.Empty;
}


/// <summary>
/// Graph role assignment for API responses.
/// </summary>
public class GraphRoleAssignment
{
    public string Id { get; set; } = string.Empty;
    public string PrincipalId { get; set; } = string.Empty;
    public string RoleDefinitionId { get; set; } = string.Empty;
    public string DirectoryScopeId { get; set; } = string.Empty;
}

/// <summary>
/// Graph eligible role assignment.
/// </summary>
public class GraphEligibleRoleAssignment
{
    public string Id { get; set; } = string.Empty;
    public string PrincipalId { get; set; } = string.Empty;
    public string RoleDefinitionId { get; set; } = string.Empty;
    public string DirectoryScopeId { get; set; } = string.Empty;
    public string MemberType { get; set; } = string.Empty;
    public DateTime? StartDateTime { get; set; }
    public DateTime? EndDateTime { get; set; }
}

/// <summary>
/// Graph active role assignment.
/// </summary>
public class GraphActiveRoleAssignment
{
    public string Id { get; set; } = string.Empty;
    public string PrincipalId { get; set; } = string.Empty;
    public string RoleDefinitionId { get; set; } = string.Empty;
    public string DirectoryScopeId { get; set; } = string.Empty;
    public string MemberType { get; set; } = string.Empty;
    public string AssignmentType { get; set; } = string.Empty;
}

/// <summary>
/// Graph sign-in for API responses.
/// </summary>
public class GraphSignIn
{
    public string Id { get; set; } = string.Empty;
    public DateTime CreatedDateTime { get; set; }
    public string UserPrincipalName { get; set; } = string.Empty;
    public string UserDisplayName { get; set; } = string.Empty;
    public string AppDisplayName { get; set; } = string.Empty;
    public string IpAddress { get; set; } = string.Empty;
    public string Status { get; set; } = string.Empty;
}

/// <summary>
/// User authentication method.
/// </summary>
public class UserAuthenticationMethod
{
    public string Id { get; set; } = string.Empty;
    public string OdataType { get; set; } = string.Empty;
    public string MethodType { get; set; } = string.Empty;
    public string Type { get; set; } = string.Empty;
}

/// <summary>
/// Graph directory audit for API responses.
/// </summary>
public class GraphDirectoryAudit
{
    public string Id { get; set; } = string.Empty;
    public DateTime ActivityDateTime { get; set; }
    public string ActivityDisplayName { get; set; } = string.Empty;
    public string Category { get; set; } = string.Empty;
    public string Result { get; set; } = string.Empty;
}

/// <summary>
/// Conditional access policy info for guard rails.
/// </summary>
public class ConditionalAccessPolicyInfo
{
    public string Id { get; set; } = string.Empty;
    public string DisplayName { get; set; } = string.Empty;
    public string State { get; set; } = string.Empty;
    public DateTime? CreatedDateTime { get; set; }
    public DateTime? ModifiedDateTime { get; set; }
    public bool HasMfaRequirement { get; set; }
    public bool HasCompliantDeviceRequirement { get; set; }
    public bool TargetsAllUsers { get; set; }
    public bool TargetsAdmins { get; set; }
}

/// <summary>
/// Authorization policy options.
/// </summary>
public class AuthorizationPolicyOptions
{
    public bool Execute { get; set; } = true;
    public bool AllowUsersToCreateApps { get; set; } = true;
    public bool AllowUsersToCreateSecurityGroups { get; set; } = true;
    public bool AllowUsersToReadOtherUsers { get; set; } = true;
    public bool BlockMsolPowerShell { get; set; }
    public bool RestrictUserConsent { get; set; }
    public string? GuestUserRoleId { get; set; }
    public GuestUserRole GuestUserRole { get; set; } = GuestUserRole.Guest;
    public InvitationRestriction InvitationRestriction { get; set; } = InvitationRestriction.Everyone;
}

/// <summary>
/// Graph paged response for API pagination.
/// </summary>
public class GraphPagedResponse<T>
{
    public List<T> Value { get; set; } = [];
    public string? OdataNextLink { get; set; }
    public string? OdataContext { get; set; }
}

/// <summary>
/// OAuth error response.
/// </summary>
public class OAuthError
{
    public string Error { get; set; } = string.Empty;
    public string ErrorDescription { get; set; } = string.Empty;
    public string[] ErrorCodes { get; set; } = [];
    public string CorrelationId { get; set; } = string.Empty;
    public string Timestamp { get; set; } = string.Empty;
}

/// <summary>
/// Conditional access policy creation model.
/// </summary>
public class ConditionalAccessPolicyCreate
{
    public string DisplayName { get; set; } = string.Empty;
    public string State { get; set; } = "enabled";
    public ConditionalAccessConditions? Conditions { get; set; }
    public ConditionalAccessGrantControls? GrantControls { get; set; }
}

/// <summary>
/// Guest user role enumeration.
/// </summary>
public enum GuestUserRole
{
    Member = 0,
    Guest = 1,
    RestrictedGuest = 2
}

/// <summary>
/// Invitation restriction enumeration.
/// </summary>
public enum InvitationRestriction
{
    None = 0,
    AdminsOnly = 1,
    AdminsAndGuestInvites = 2,
    AdminsGuestInvitesAndAllMembers = 3,
    Everyone = 4
}

/// <summary>
/// RBAC disposition options.
/// </summary>
public class RbacDispositionOptions
{
    public bool Execute { get; set; } = true;
    public string Scope { get; set; } = string.Empty;
    public string? OutputPath { get; set; }
    public List<string> ExcludedPrincipals { get; set; } = [];
}

/// <summary>
/// Disposition result from control plane disposition.
/// </summary>
public class DispositionResult
{
    public bool Success { get; set; }
    public string Mode { get; set; } = string.Empty;
    public bool IsWhatIf { get; set; }
    public int UsersProcessed { get; set; }
    public int ServicePrincipalsProcessed { get; set; }
    public int ExcludedCount { get; set; }
    public int RolesProcessed { get; set; }
    public int TotalAssignments { get; set; }
    public Dictionary<string, ActionResult> ActionSummary { get; set; } = [];
    public string? BackupFilePath { get; set; }
    public string? OutputPath { get; set; }
    public DateTime Timestamp { get; set; }
    public string? ErrorMessage { get; set; }
}

/// <summary>
/// Action result for disposition operations.
/// </summary>
public class ActionResult
{
    public int Attempted { get; set; }
    public int Succeeded { get; set; }
    public int Failed { get; set; }
}

/// <summary>
/// Aggregated role assignment data.
/// </summary>
public class RoleAssignmentData
{
    public List<RoleAssignment> PermanentAssignments { get; set; } = [];
    public List<PimRoleAssignment> PimActiveAssignments { get; set; } = [];
    public List<PimRoleAssignment> PimEligibleAssignments { get; set; } = [];
    public List<GraphUser> Users { get; set; } = [];
    public List<GraphServicePrincipal> ServicePrincipals { get; set; } = [];

    public int Total => PermanentAssignments.Count + PimActiveAssignments.Count + PimEligibleAssignments.Count;
}

