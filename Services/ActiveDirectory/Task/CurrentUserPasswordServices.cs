// --------------------------------------------------------------------------
// <copyright file="CurrentUserPasswordService.cs" company="Phoenix IR Platform">
//     © 2026 Phoenix IR Platform. All rights reserved.
//     100% Parity with PowerShell Set-CurrentPassword function from Invoke-WinUI11.ps1
// </copyright>
// --------------------------------------------------------------------------

using System.DirectoryServices;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Principal;
using Microsoft.Extensions.Logging;
using Phoenix.Core.Services.MicrosoftAzure.Models;

namespace Phoenix.Core.Services.ActiveDirectory.Tasks;

#region Result Models

/// <summary>
/// Result of current user password reset operation.
/// </summary>
public class CurrentUserPasswordResult : AdOperationResult
{
    public string Username { get; set; } = string.Empty;
    public string Domain { get; set; } = string.Empty;
    public string DomainController { get; set; } = string.Empty;
    public bool WasSkipped { get; set; }
    public string? SkipReason { get; set; }
    public DateTime? LastPasswordChange { get; set; }
}

#endregion

#region Interface

/// <summary>
/// Service for resetting the current user's password.
/// </summary>
public interface ICurrentUserPasswordService
{
    /// <summary>
    /// Checks if password was recently changed (within 24 hours).
    /// </summary>
    Task<(bool WasRecent, DateTime? LastChange)> CheckRecentPasswordChangeAsync(
        System.Net.NetworkCredential? credential = null,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Resets the current user's password.
    /// </summary>
    Task<CurrentUserPasswordResult> ResetPasswordAsync(
        SecureString newPassword,
        System.Net.NetworkCredential? credential = null,
        bool execute = true,
        CancellationToken cancellationToken = default);
}

#endregion

#region Implementation

/// <summary>
/// Service for resetting the current user's password.
/// Matches PowerShell Set-CurrentPassword function exactly.
/// </summary>
public class CurrentUserPasswordService : ICurrentUserPasswordService
{
    private readonly ILogger<CurrentUserPasswordService>? _logger;

    public CurrentUserPasswordService(ILogger<CurrentUserPasswordService>? logger = null)
    {
            _logger = logger;
        }

        /// <summary>
        /// Checks if password was recently changed (within 24 hours).
        /// Matches PS: Test-RecentPasswordChange function
        /// </summary>
        public async Task<(bool WasRecent, DateTime? LastChange)> CheckRecentPasswordChangeAsync(
            System.Net.NetworkCredential? credential = null,
            CancellationToken cancellationToken = default)
        {
            return await Task.Run(() =>
            {
                try
                {
                    var currentUsername = Environment.UserName;
                    if (string.IsNullOrEmpty(currentUsername))
                    {
                        _logger?.LogWarning("Cannot determine current username");
                        return (false, null);
                    }

                    var logonServer = GetLogonServerFqdn();
                    if (string.IsNullOrEmpty(logonServer))
                    {
                        _logger?.LogWarning("Cannot determine logon server");
                        return (false, null);
                    }

                    // Find user and get pwdLastSet
                    var userDn = FindUserDn(logonServer, currentUsername, credential);
                    if (string.IsNullOrEmpty(userDn))
                    {
                        _logger?.LogWarning("Cannot find user DN for {Username}", currentUsername);
                        return (false, null);
                    }

                    var pwdLastSet = GetPasswordLastSet(logonServer, userDn, credential);
                    if (!pwdLastSet.HasValue)
                    {
                        return (false, null);
                    }

                    var hoursSinceChange = (DateTime.UtcNow - pwdLastSet.Value).TotalHours;
                    var wasRecent = hoursSinceChange < 24;

                    _logger?.LogInformation("Password last changed: {LastChange}, Hours ago: {Hours}, Recent: {Recent}",
                        pwdLastSet.Value, hoursSinceChange, wasRecent);

                    return (wasRecent, pwdLastSet);
                }
                catch (Exception ex)
                {
                    _logger?.LogError(ex, "Error checking recent password change");
                    return (false, null);
                }
            }, cancellationToken);
        }

        /// <summary>
        /// Resets the current user's password.
        /// Matches PS: Set-CurrentPassword function exactly.
        /// </summary>
        public async Task<CurrentUserPasswordResult> ResetPasswordAsync(
            SecureString newPassword,
            System.Net.NetworkCredential? credential = null,
            bool execute = true,
            CancellationToken cancellationToken = default)
        {
            var result = new CurrentUserPasswordResult
            {
                IsWhatIf = !execute
            };

            try
            {
                // PS: $currentUsername = $env:USERNAME
                var currentUsername = Environment.UserName;
                if (string.IsNullOrEmpty(currentUsername))
                {
                    result.Message = "Unable to determine the currently logged-on username.";
                    result.Errors.Add(result.Message);
                    _logger?.LogError("Unable to determine the currently logged-on username");
                    return result;
                }

                result.Username = currentUsername;

                // PS: $logonServerNetBIOS = $env:LOGONSERVER -replace '^\\',''
                var logonServerNetBios = Environment.GetEnvironmentVariable("LOGONSERVER")?.TrimStart('\\');
                if (string.IsNullOrEmpty(logonServerNetBios))
                {
                    result.Message = "Unable to determine the authenticating domain controller (LOGONSERVER).";
                    result.Errors.Add(result.Message);
                    _logger?.LogError("Unable to determine the authenticating domain controller (LOGONSERVER)");
                    return result;
                }

                // PS: Try FQDN resolution, fallback to NetBIOS
                string logonServerFqdn;
                try
                {
                    var hostEntry = await System.Net.Dns.GetHostEntryAsync(logonServerNetBios, cancellationToken);
                    logonServerFqdn = hostEntry.HostName;
                }
                }
            }
            catch
            {
                logonServerFqdn = logonServerNetBios;
                _logger?.LogWarning("FQDN resolution failed for '{NetBios}'; using NetBIOS.", logonServerNetBios);
            }
            result.DomainController = logonServerFqdn;

            // PS: Connect to RootDSE, verify isSynchronized
            var (isSynchronized, domainDn) = await Task.Run(() =>
                GetRootDseInfo(logonServerFqdn, credential), cancellationToken);

            if (!isSynchronized)
            {
                result.Message = $"Authenticating DC '{logonServerFqdn}' is not synchronized.";
                result.Errors.Add(result.Message);
                _logger?.LogError("Authenticating DC '{DcFqdn}' is not synchronized", logonServerFqdn);
                return result;
            }

            if (string.IsNullOrEmpty(domainDn))
            {
                result.Message = $"defaultNamingContext missing on '{logonServerFqdn}'.";
                result.Errors.Add(result.Message);
                _logger?.LogError("defaultNamingContext missing on '{DcFqdn}'", logonServerFqdn);
                return result;
            }

            // PS: Extract domain name from DN
            var domainName = domainDn.Replace("DC=", "").Replace(",", ".");
            result.Domain = domainName;

            _logger?.LogInformation("Identified session: User='{Username}', Domain='{Domain}', DC='{DC}' (WhatIf={WhatIf})",
                currentUsername, domainName, logonServerFqdn, !execute);

            // PS: Locate current user via LDAP search
            var userDn = await Task.Run(() =>
                FindUserDn(logonServerFqdn, currentUsername, credential), cancellationToken);

            if (string.IsNullOrEmpty(userDn))
            {
                result.Message = $"User '{currentUsername}' not found in domain.";
                result.Errors.Add(result.Message);
                _logger?.LogError("User '{Username}' not found in domain", currentUsername);
                return result;
            }

            _logger?.LogInformation("Found user DN: {UserDn}", userDn);

            // WhatIf mode - don't actually change password
            if (!execute)
            {
                result.Success = true;
                result.Message = $"[WhatIf] Would reset password for user '{currentUsername}' on DC '{logonServerFqdn}'.";
                _logger?.LogInformation("[WhatIf] Would reset password for user '{Username}' on DC '{DcFqdn}'", currentUsername, logonServerFqdn);
                return result;
            }

            // PS: Actually reset the password via SetPassword
            await Task.Run(() =>
                SetUserPassword(logonServerFqdn, userDn, newPassword, credential), cancellationToken);

            result.Success = true;
            result.Message = $"Password successfully reset for user '{currentUsername}'.";
            _logger?.LogInformation("Password successfully reset for user '{Username}'", currentUsername);

            return result;
        }
        catch (Exception ex)
        {
            result.Message = $"Password reset failed: {ex.Message}";
            result.Errors.Add(result.Message);
            _logger?.LogError(ex, "Password reset failed");
            return result;
        }
    }

    #region Private Helper Methods

    /// <summary>
    /// Gets the FQDN of the logon server.
    /// </summary>
    private static string? GetLogonServerFqdn()
    {
        var logonServerNetBios = Environment.GetEnvironmentVariable("LOGONSERVER")?.TrimStart('\\');
        if (string.IsNullOrEmpty(logonServerNetBios))
            return null;

        try
        {
            var hostEntry = System.Net.Dns.GetHostEntry(logonServerNetBios);
            return hostEntry.HostName;
        }
        catch
        {
            return logonServerNetBios;
        }
    }

    /// <summary>
    /// Gets RootDSE info (isSynchronized and defaultNamingContext).
    /// Matches PS: RootDSE connection and property retrieval
    /// </summary>
    private static (bool IsSynchronized, string? DomainDn) GetRootDseInfo(
        string dcFqdn, System.Net.NetworkCredential? credential)
    {
        var rootDsePath = $"LDAP://{dcFqdn}/RootDSE";

        using var rootDse = credential != null
            ? new DirectoryEntry(rootDsePath, credential.UserName, credential.Password)
            : new DirectoryEntry(rootDsePath);

        var isSynchronized = false;
        if (rootDse.Properties["isSynchronized"].Count > 0)
        {
            var syncValue = rootDse.Properties["isSynchronized"][0];
            isSynchronized = syncValue?.ToString()?.Equals("TRUE", StringComparison.OrdinalIgnoreCase) == true
                           || (syncValue is bool b && b);
        }

        string? domainDn = null;
        if (rootDse.Properties["defaultNamingContext"].Count > 0)
        {
            domainDn = rootDse.Properties["defaultNamingContext"][0]?.ToString();
        }

        return (isSynchronized, domainDn);
    }

    /// <summary>
    /// Finds the user's DN via LDAP search.
    /// Matches PS: DirectorySearcher with sAMAccountName filter
    /// </summary>
    private static string? FindUserDn(string dcFqdn, string username, System.Net.NetworkCredential? credential)
    {
        var (_, domainDn) = GetRootDseInfo(dcFqdn, credential);
        if (string.IsNullOrEmpty(domainDn))
            return null;

        var searchRootPath = $"LDAP://{dcFqdn}/{domainDn}";

        using var searchRoot = credential != null
            ? new DirectoryEntry(searchRootPath, credential.UserName, credential.Password)
            : new DirectoryEntry(searchRootPath);

        using var searcher = new DirectorySearcher(searchRoot)
        {
            Filter = $"(&(objectClass=user)(sAMAccountName={EscapeLdapFilter(username)}))",
            SearchScope = SearchScope.Subtree,
            PageSize = 1
        };
        searcher.PropertiesToLoad.Add("distinguishedName");

        var result = searcher.FindOne();
        if (result?.Properties["distinguishedName"].Count > 0)
        {
            return result.Properties["distinguishedName"][0]?.ToString();
        }

        return null;
    }

    /// <summary>
    /// Gets the pwdLastSet attribute for a user.
    /// </summary>
    private static DateTime? GetPasswordLastSet(string dcFqdn, string userDn, System.Net.NetworkCredential? credential)
    {
        var userPath = $"LDAP://{dcFqdn}/{userDn}";

        using var userEntry = credential != null
            ? new DirectoryEntry(userPath, credential.UserName, credential.Password)
            : new DirectoryEntry(userPath);

        if (userEntry.Properties["pwdLastSet"].Count > 0)
        {
            var pwdLastSetValue = userEntry.Properties["pwdLastSet"][0];
            if (pwdLastSetValue is long fileTime && fileTime > 0)
            {
                return DateTime.FromFileTimeUtc(fileTime);
            }
        }

        return null;
    }
    }

    /// <summary>
    /// Sets the user's password via ADSI SetPassword.
    /// Matches PS: $userDE.Invoke("SetPassword", @($newPassword))
    /// </summary>
    private static void SetUserPassword(string dcFqdn, string userDn, SecureString newPassword,
        System.Net.NetworkCredential? credential)
    {
        var userPath = $"LDAP://{dcFqdn}/{userDn}";

        using var userEntry = credential != null
            ? new DirectoryEntry(userPath, credential.UserName, credential.Password)
            : new DirectoryEntry(userPath);

        // Convert SecureString to plain string for SetPassword
        var ptr = Marshal.SecureStringToGlobalAllocUnicode(newPassword);
        try
        {
            var plainPassword = Marshal.PtrToStringUni(ptr);
            userEntry.Invoke("SetPassword", new object[] { plainPassword! });
            userEntry.CommitChanges();

            // Clear the plain password from memory
            plainPassword = null;
        }
        finally
        {
            Marshal.ZeroFreeGlobalAllocUnicode(ptr);
        }
    }

    /// <summary>
    /// Escapes special characters for LDAP filter.
    /// </summary>
    private static string EscapeLdapFilter(string value)
    {
        if (string.IsNullOrEmpty(value)) return value;

        return value
            .Replace("\\", "\\5c")
            .Replace("*", "\\2a")
            .Replace("(", "\\28")
            .Replace(")", "\\29")
            .Replace("\0", "\\00");
    }

    #endregion
}

#endregion
