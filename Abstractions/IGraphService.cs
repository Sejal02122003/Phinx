using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Phoenix.Core.Common;

namespace Phoenix.Core.Abstractions;

/// <summary>
/// Defines the contract for Microsoft Graph API operations.
/// </summary>
public interface IGraphService : IDisposable
{
    bool IsAuthenticated { get; }
    string? TenantId { get; }
    string? CurrentUser { get; }

    Task<Result<AuthenticationInfo>> AuthenticateWithDeviceCodeAsync(
        string tenantId, string clientId, Action<DeviceCodeInfo> deviceCodeCallback,
        CancellationToken cancellationToken = default);

    Task<Result<AuthenticationInfo>> AuthenticateWithClientSecretAsync(
        string tenantId, string clientId, string clientSecret,
        CancellationToken cancellationToken = default);

    Task<Result<GraphUserInfo>> GetUserAsync(string userIdOrUpn, CancellationToken cancellationToken = default);
    Task<Result<IReadOnlyList<GraphUserInfo>>> GetUsersAsync(string? filter = null, int top = 100, CancellationToken cancellationToken = default);
    Task<Result> DisableUserAsync(string userId, CancellationToken cancellationToken = default);
    Task<Result> RevokeUserSessionsAsync(string userId, CancellationToken cancellationToken = default);
    Task<Result<IReadOnlyList<DirectoryRoleInfo>>> GetDirectoryRolesAsync(CancellationToken cancellationToken = default);
    Task<Result<IReadOnlyList<RoleAssignmentInfo>>> GetUserRoleAssignmentsAsync(string userId, CancellationToken cancellationToken = default);
    Task<Result> RemoveRoleAssignmentAsync(string roleAssignmentId, CancellationToken cancellationToken = default);
    Task SignOutAsync(CancellationToken cancellationToken = default);
}

public sealed record AuthenticationInfo
{
    public required string TenantId { get; init; }
    public required string Username { get; init; }
    public required DateTimeOffset ExpiresAt { get; init; }
    public IReadOnlyList<string> Scopes { get; init; } = [];
}

public sealed record DeviceCodeInfo
{
    public required string UserCode { get; init; }
    public required string VerificationUri { get; init; }
    public required string Message { get; init; }
    public required DateTimeOffset ExpiresAt { get; init; }
}

public sealed record GraphUserInfo
{
    public required string Id { get; init; }
    public required string UserPrincipalName { get; init; }
    public required string DisplayName { get; init; }
    public string? Mail { get; init; }
    public string? JobTitle { get; init; }
    public string? Department { get; init; }
    public bool AccountEnabled { get; init; }
    public DateTimeOffset? CreatedDateTime { get; init; }
    public DateTimeOffset? LastSignInDateTime { get; init; }
    public string? OnPremisesSamAccountName { get; init; }
    public bool OnPremisesSyncEnabled { get; init; }
    public IReadOnlyList<string> AssignedLicenses { get; init; } = [];
}

public sealed record DirectoryRoleInfo
{
    public required string Id { get; init; }
    public required string DisplayName { get; init; }
    public string? Description { get; init; }
    public required string RoleTemplateId { get; init; }
    public IReadOnlyList<string> Members { get; init; } = [];
}

public sealed record RoleAssignmentInfo
{
    public required string Id { get; init; }
    public required string PrincipalId { get; init; }
    public required string RoleDefinitionId { get; init; }
    public string? DirectoryScopeId { get; init; }
    public string? RoleDisplayName { get; init; }
    public string? PrincipalDisplayName { get; init; }
}
