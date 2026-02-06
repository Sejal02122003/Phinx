using System.Globalization;
// <copyright file="AdUtilities.cs" company="NCS Dojo">
//     © 2026 NCS Dojo. All rights reserved.
//     Active Directory utility functions for incident response.
//     Converted from PowerShell utility functions:
//         - New-Password.ps1
//         - Convert-SidToLdapFilter.ps1
//         - Get-BuiltInAdmin.ps1
//         - Get-DeleteProtection.ps1
//         - Get-ReverseZoneIPv4.ps1
//         - Get-ReverseZoneIPv6.ps1
//         - Get-UserPrivileges.ps1
// </copyright>
// --------------------------------------------------------------------------

using System.DirectoryServices;
using System.Net;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using Microsoft.Extensions.Logging;

namespace Phoenix.Core.Services.ActiveDirectory;

/// <summary>
/// Active Directory utility functions for incident response operations.
/// </summary>
public static class AdUtilities
{
    private static readonly string[] DefaultSearchProperties = { "distinguishedName", "sAMAccountName", "objectSid" };
    #region Password Generation (New-Password.ps1)

    /// <summary>
    /// Character sets for password generation.
    /// </summary>
    private static class PasswordCharSets
    {
        public const string LowercaseWithAmbiguous = "abcdefghijklmnopqrstuvwxyz";
        public const string LowercaseNoAmbiguous = "abcdefghijkmnopqrstuvwxyz"; // excludes 'l'
        public const string UppercaseWithAmbiguous = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        public const string UppercaseNoAmbiguous = "ABCDEFGHJKLMNPQRSTUVWXYZ"; // excludes 'I', 'O'
        public const string Numbers = "0123456789";
        public const string DefaultSymbols = "@#$%^&*- _=+|[]{}:;.?,!/~';()<>\"";
    }

    /// <summary>
    /// Generates a cryptographically secure password.
    /// Converted from PowerShell New-Password.ps1.
    /// </summary>
    /// <param name="length">Password length (minimum 24).</param>
    /// <param name="includeAmbiguous">Include ambiguous characters (1, I, O).</param>
    /// <param name="customSymbols">Custom symbol set (null for default).</param>
    /// <returns>Generated password string.</returns>
    public static string GeneratePassword(int length = 24, bool includeAmbiguous = false, string? customSymbols = null)
    {
        if (length < 24)
            throw new ArgumentException("Password length must be at least 24 characters.", nameof(length));

        var lowercase = includeAmbiguous ? PasswordCharSets.LowercaseWithAmbiguous : PasswordCharSets.LowercaseNoAmbiguous;
        var uppercase = includeAmbiguous ? PasswordCharSets.UppercaseWithAmbiguous : PasswordCharSets.UppercaseNoAmbiguous;
        var numbers = PasswordCharSets.Numbers;
        var symbols = customSymbols ?? PasswordCharSets.DefaultSymbols;
        var allChars = lowercase + uppercase + numbers + symbols;

        using var rng = RandomNumberGenerator.Create();
        var password = new char[length];

        // Ensure at least one character from each class
        password[0] = GetRandomChar(rng, lowercase);
        password[1] = GetRandomChar(rng, uppercase);
        password[2] = GetRandomChar(rng, numbers);
        password[3] = GetRandomChar(rng, symbols);

        // Fill remaining with random characters from all sets
        for (int i = 4; i < length; i++)
        {
            password[i] = GetRandomChar(rng, allChars);
        }

        // Fisher-Yates shuffle
        for (int i = length - 1; i > 0; i--)
        {
            var bytes = new byte[4];
            rng.GetBytes(bytes);
            int j = (int)(BitConverter.ToUInt32(bytes, 0) % (uint)(i + 1));
            (password[i], password[j]) = (password[j], password[i]);
        }

        return new string(password);
    }

    /// <summary>
    /// Generates password with metadata including entropy calculation.
    /// </summary>
    public static PasswordMetadata GeneratePasswordWithMetadata(int length = 24, bool includeAmbiguous = false, string? customSymbols = null)
    {
        var password = GeneratePassword(length, includeAmbiguous, customSymbols);

        var lowercase = includeAmbiguous ? PasswordCharSets.LowercaseWithAmbiguous : PasswordCharSets.LowercaseNoAmbiguous;
        var uppercase = includeAmbiguous ? PasswordCharSets.UppercaseWithAmbiguous : PasswordCharSets.UppercaseNoAmbiguous;
        var symbols = customSymbols ?? PasswordCharSets.DefaultSymbols;
        var charSetSize = lowercase.Length + uppercase.Length + PasswordCharSets.Numbers.Length + symbols.Length;

        var entropy = Math.Log(Math.Pow(charSetSize, length), 2);

        return new PasswordMetadata
        {
            Password = password,
            Length = length,
            Entropy = Math.Round(entropy, 2)
        };
    }

    private static char GetRandomChar(RandomNumberGenerator rng, string charSet)
    {
        var bytes = new byte[4];
        rng.GetBytes(bytes);
        var index = BitConverter.ToUInt32(bytes, 0) % (uint)charSet.Length;
        return charSet[(int)index];
    }

    #endregion

    #region SID Utilities (Convert-SidToLdapFilter.ps1)

    /// <summary>
    /// Converts a SID string to LDAP filter format.
    /// Converted from PowerShell Convert-SidToLdapFilter.ps1.
    /// </summary>
    /// <param name="sidString">SID in string format (e.g., "S-1-5-21-...").</param>
    /// <returns>LDAP-escaped binary SID filter.</returns>
    public static string ConvertSidToLdapFilter(string sidString)
    {
        var sid = new SecurityIdentifier(sidString);
        var bytes = new byte[sid.BinaryLength];
        sid.GetBinaryForm(bytes, 0);

        return string.Concat(bytes.Select(b => $"\\{b:X2}"));
    }

    /// <summary>
    /// Converts a SecurityIdentifier to LDAP filter format.
    /// </summary>
    public static string ConvertSidToLdapFilter(SecurityIdentifier sid)
    {
        var bytes = new byte[sid.BinaryLength];
        sid.GetBinaryForm(bytes, 0);

        return string.Concat(bytes.Select(b => $"\\{b:X2}"));
    }

    #endregion

    #region Built-in Admin (Get-BuiltInAdmin.ps1)

    /// <summary>
    /// Gets the built-in Administrator account (RID 500) for a domain.
    /// Converted from PowerShell Get-BuiltInAdmin.ps1.
    /// </summary>
    /// <param name="targetDns">Target DC DNS name.</param>
    /// <param name="domainSid">Domain SID string.</param>
    /// <returns>DirectoryEntry for the RID 500 account, or null if not found.</returns>
    public static DirectoryEntry? GetBuiltinAdmin(string targetDns, string domainSid)
    {
        try
        {
            // Get default naming context
            using var rootDse = new DirectoryEntry($"LDAP://{targetDns}/RootDSE");
            var defaultNC = rootDse.Properties["defaultNamingContext"].Value?.ToString();

            if (string.IsNullOrEmpty(defaultNC))
                return null;

            // Build RID 500 SID
            var rid500Sid = new SecurityIdentifier($"{domainSid}-500");
            var escapedSid = ConvertSidToLdapFilter(rid500Sid);

            // Search for the account
            using var searchRoot = new DirectoryEntry($"LDAP://{targetDns}/{defaultNC}");
            using var searcher = new DirectorySearcher(searchRoot)
            {
                Filter = $"(&(objectClass=user)(objectSid={escapedSid}))",
                SearchScope = SearchScope.Subtree,
                PageSize = 1000
            };
            searcher.PropertiesToLoad.AddRange(DefaultSearchProperties);

            var result = searcher.FindOne();
            if (result == null)
                return null;

            var dn = result.Properties["distinguishedName"][0]?.ToString();
            return new DirectoryEntry($"LDAP://{targetDns}/{dn}");
        }
        catch
        {
            return null;
        }
    }

    #endregion

    #region Delete Protection (Get-DeleteProtection.ps1)

    /// <summary>
    /// Checks if an AD object has delete protection enabled.
    /// Converted from PowerShell Get-DeleteProtection.ps1.
    /// </summary>
    /// <param name="entry">DirectoryEntry to check.</param>
    /// <returns>True if protected from deletion.</returns>
    public static bool HasDeleteProtection(DirectoryEntry entry)
    {
        try
        {
            var security = entry.ObjectSecurity;
            var accessRules = security.GetAccessRules(true, false, typeof(NTAccount));

            foreach (System.DirectoryServices.ActiveDirectoryAccessRule rule in accessRules)
            {
                // Check for: Everyone, Deny, Delete+DeleteTree, Not Inherited
                if (rule.IdentityReference.Value == "Everyone" &&
                    rule.AccessControlType == System.Security.AccessControl.AccessControlType.Deny &&
                    rule.ActiveDirectoryRights.HasFlag(System.DirectoryServices.ActiveDirectoryRights.Delete) &&
                    rule.ActiveDirectoryRights.HasFlag(System.DirectoryServices.ActiveDirectoryRights.DeleteTree) &&
                    !rule.IsInherited)
                {
                    return true;
                }
            }

            return false;
        }
        catch
        {
            return false;
        }
    }

    #endregion

    #region Reverse DNS Zones (Get-ReverseZoneIPv4.ps1 / Get-ReverseZoneIPv6.ps1)

    /// <summary>
    /// Gets possible reverse DNS zone names for an IPv4 address.
    /// Converted from PowerShell Get-ReverseZoneIPv4.ps1.
    /// </summary>
    /// <param name="ipAddress">IPv4 address string.</param>
    /// <returns>List of possible reverse zone names.</returns>
    public static List<string> GetReverseZonesIPv4(string ipAddress)
    {
        var zones = new List<string>();

        try
        {
            var parts = ipAddress.Split('.');
            if (parts.Length != 4) return zones;

            // Generate /8, /16, /24 reverse zones
            for (int i = 1; i <= 3; i++)
            {
                var reverseParts = parts.Take(i).Reverse();
                var zone = string.Join(".", reverseParts) + ".in-addr.arpa";
                zones.Add(zone);
            }
        }
        catch
        {
            // Return empty list on error
        }

        return zones;
    }

    /// <summary>
    /// Gets possible reverse DNS zone names for an IPv6 address.
    /// Converted from PowerShell Get-ReverseZoneIPv6.ps1.
    /// </summary>
    /// <param name="ipAddress">IPv6 address string.</param>
    /// <returns>List of possible reverse zone names.</returns>
    public static List<string> GetReverseZonesIPv6(string ipAddress)
    {
        var zones = new List<string>();

        try
        {
            var ip = IPAddress.Parse(ipAddress);
            var bytes = ip.GetAddressBytes();

            // Convert to nibbles
            var nibbles = new List<char>();
            foreach (var b in bytes)
            {
                nibbles.Add(((b >> 4) & 0x0F).ToString("x", CultureInfo.InvariantCulture)[0]);
                nibbles.Add((b & 0x0F).ToString("x", CultureInfo.InvariantCulture)[0]);
            }

            // Generate zones at various boundaries (/16, /32, /48, /64, etc.)
            for (int i = 4; i <= 32; i += 4)
            {
                var nibbleCount = i * 2;
                var zoneNibbles = nibbles.TakeLast(nibbleCount).Reverse();
                var zone = string.Join(".", zoneNibbles) + ".ip6.arpa";
                zones.Add(zone);
            }
        }
        catch
        {
            // Return empty list on error
        }

        return zones;
    }

    #endregion

    #region User Privileges (Get-UserPrivileges.ps1)

    /// <summary>
    /// Verifies the current user has administrative privileges.
    /// Converted from PowerShell Get-UserPrivileges.ps1.
    /// </summary>
    /// <param name="requiredGroups">Groups to check membership (default: Domain Admins, Enterprise Admins).</param>
    /// <returns>True if user is member of at least one required group.</returns>
    public static bool VerifyAdminPrivileges(string[]? requiredGroups = null)
    {
        requiredGroups ??= new[] { "Domain Admins", "Enterprise Admins" };

        try
        {
            var identity = WindowsIdentity.GetCurrent();
            var principal = new WindowsPrincipal(identity);

            // Quick check for built-in admin
            if (principal.IsInRole(WindowsBuiltInRole.Administrator))
                return true;

            // Check group memberships via LDAP
            var userName = identity.Name.Split('\\').Last();

            using var forest = System.DirectoryServices.ActiveDirectory.Forest.GetCurrentForest();
            var rootDomain = forest.RootDomain.Name;

            using var searchRoot = new DirectoryEntry($"LDAP://{rootDomain}");
            using var userSearcher = new DirectorySearcher(searchRoot)
            {
                Filter = $"(&(objectClass=user)(sAMAccountName={userName}))",
                PageSize = 1000
            };
            userSearcher.PropertiesToLoad.Add("distinguishedName");

            var userResult = userSearcher.FindOne();
            if (userResult == null)
                return false;

            var userDn = userResult.Properties["distinguishedName"][0]?.ToString();

            foreach (var group in requiredGroups)
            {
                try
                {
                    using var groupSearcher = new DirectorySearcher(searchRoot)
                    {
                        Filter = $"(&(objectClass=group)(sAMAccountName={group}))",
                        PageSize = 1000
                    };
                    groupSearcher.PropertiesToLoad.Add("member");

                    var groupResult = groupSearcher.FindOne();
                    if (groupResult != null)
                    {
                        var members = groupResult.Properties["member"];
                        foreach (var member in members)
                        {
                            if (string.Equals(member?.ToString(), userDn, StringComparison.OrdinalIgnoreCase))
                                return true;
                        }
                    }
                }
                catch
                {
                    // Continue to next group
                }
            }

            return false;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Gets the current user's identity information.
    /// </summary>
    public static UserIdentityInfo GetCurrentUserIdentity()
    {
        var identity = WindowsIdentity.GetCurrent();
        return new UserIdentityInfo
        {
            Name = identity.Name,
            Sid = identity.User?.Value ?? "",
            IsAuthenticated = identity.IsAuthenticated,
            AuthenticationType = identity.AuthenticationType ?? ""
        };
    }

    #endregion

    #region Domain DN Utilities

    /// <summary>
    /// Converts a domain FQDN to distinguished name format.
    /// </summary>
    public static string GetDomainDN(string domainFqdn)
    {
        return string.Join(",", domainFqdn.Split('.').Select(p => $"DC={p}"));
    }

    /// <summary>
    /// Extracts the domain FQDN from a distinguished name.
    /// </summary>
    public static string GetDomainFromDN(string distinguishedName)
    {
        var dcParts = distinguishedName
            .Split(',')
            .Where(p => p.Trim().StartsWith("DC=", StringComparison.OrdinalIgnoreCase))
            .Select(p => p.Trim().Substring(3));

        return string.Join(".", dcParts);
    }

    #endregion
}

#region Models

/// <summary>
/// Password generation metadata.
/// </summary>
public class PasswordMetadata
{
    public string Password { get; set; } = string.Empty;
    public int Length { get; set; }
    public double Entropy { get; set; }
}

/// <summary>
/// User identity information.
/// </summary>
public class UserIdentityInfo
{
    public string Name { get; set; } = string.Empty;
    public string Sid { get; set; } = string.Empty;
    public bool IsAuthenticated { get; set; }
    public string AuthenticationType { get; set; } = string.Empty;
}

#endregion
