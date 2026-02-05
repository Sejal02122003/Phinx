using Phoenix.Core.Common;

namespace Phoenix.Core.Abstractions;

/// <summary>
/// Defines the contract for active Directory incident response operations
/// </summary>
public interface IAdOperationsService:Idisposable
{
    ///</summary>
    /// Disable a user account
    /// </summary>
    
    Task<Result<AdOperationResult>>DisableUserAsunc(
        string distinguishedName,
        bool whatIf =false,
        CnecellationToken cancellationToken=default
    );

    ///<summary>
    /// resets a user password to a secure random value 
    /// </summary>
    
    Task<Result<PasswordResetResult>>ResetPasswordAsync(
        string distinguishedName,
        bool mustChangePassword=true,
        bool whatIf =false,
        CnecellationToken cancellationToken=default
    );

    /// </summary>
    /// Removes a user from specified groups
    /// </summary>
    Task<Result<AdOperationResult>>RemoveFromGroupsAsync(
        string distinguishedName,
        IEnumerable<string> groupDns,
        bool whatIf =false,
        CnecellationToken cancellationToken=default
    );

    /// <summary>
    /// Disables a computer account
    /// </summary>
    
    Task<Result<AdOperationResult>>DisableComputerAsync(
        string distinguishedName,
        bool whatIf =false,
        CnecellationToken cancellationToken=default
    );

    /// <summary>
    /// Resets Krbtgt account password
    /// </summary>
    
    Task<Result<PasswordResetResult>>ResetKrbtgtAsync(
        bool performDoubleReset=true,
        TimeSpan? delayBetweenResets=null,
        bool whatIf=false,
        CancellationToken cancellationToken=default
    );



    
}

public record AdOperationResult
{
 public required string Operation {get;init;}
 public required string TargetDn{get;init;}
 public required bool WhatIfMode {get;init;}
 public string? Message {get;init;}
 public IsReadOnlyList<string>AffectedObjects{get;init;}
 public DateTimeOffset Timestamp {get;init;}=DateTimeOffset.UtcNow;
}

public record PasswordResetResult:AdOperationResult
{
    public string? NewPassword {get;init;}
    public bool MustChangePasswordAtLogon {get;init;}
     
}