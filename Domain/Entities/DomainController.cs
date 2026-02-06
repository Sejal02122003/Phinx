// --------------------------------------------------------------------------
// <copyright file="DomainController.cs" company="NCS Dojo">
//     © 2026 NCS Dojo. All rights reserved.
//     Licensed under proprietary license. Unauthorized copying prohibited.
// </copyright>
// <summary>
//     Represents an Active Directory Domain Controller with security-critical metadata.
//     EAL 3.5+ compliant with input validation and immutability where appropriate.
// </summary>
// --------------------------------------------------------------------------

using System.ComponentModel.DataAnnotations;
using System.Net;
using System.Text.RegularExpressions;

namespace Phoenix.Core.Domain.Entities;

/// <summary>
/// Represents an Active Directory Domain Controller with comprehensive metadata
/// for incident response operations. Implements strict validation for EAL 3.5+ compliance.
/// </summary>
public sealed partial class DomainController : EntityBase
{
    private static readonly Regex FqdnPattern = GenerateFqdnRegex();
    private static readonly Regex DomainPattern = GenerateDomainRegex();

    /// <summary>
    /// Gets or sets the fully qualified domain name of the domain controller.
    /// </summary>
    [Required(ErrorMessage = "FQDN is required")]
    [StringLength(255, MinimumLength = 3, ErrorMessage = "FQDN must be between 3 and 255 characters")]
    public string Fqdn { get; set; } = string.Empty;

    /// <summary>
    /// Gets the domain name this controller belongs to.
    /// </summary>
    [Required(ErrorMessage = "Domain is required")]
    [StringLength(255, MinimumLength = 3, ErrorMessage = "Domain must be between 3 and 255 characters")]
    public string Domain { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the IP address of the domain controller.
    /// </summary>
    [Required(ErrorMessage = "IP address is required")]
    public string IpAddress { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the operating system version of the domain controller.
    /// </summary>
    [StringLength(255)]
    public string OperatingSystem { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the operating system service pack of the domain controller.
    /// </summary>
    [StringLength(255)]
    public string OperatingSystemServicePack { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the forest functional level.
    /// </summary>
    public string ForestFunctionalLevel { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the domain functional level.
    /// </summary>
    public string DomainFunctionalLevel { get; set; } = string.Empty;

    /// <summary>
    /// Gets a value indicating whether this DC holds the PDC Emulator role.
    /// </summary>
    public bool IsPdcRoleOwner { get; set; }

    /// <summary>
    /// Gets a value indicating whether this DC holds the RID Master role.
    /// </summary>
    public bool IsRidMaster { get; set; }

    /// <summary>
    /// Gets a value indicating whether this DC holds the Infrastructure Master role.
    /// </summary>
    public bool IsInfrastructureMaster { get; set; }

    /// <summary>
    /// Gets a value indicating whether this DC holds the Schema Master role.
    /// </summary>
    public bool IsSchemaMaster { get; set; }

    /// <summary>
    /// Gets a value indicating whether this DC holds the Domain Naming Master role.
    /// </summary>
    public bool IsDomainNamingMaster { get; set; }

    /// <summary>
    /// Gets the default naming context (domain DN).
    /// </summary>
    [StringLength(2048)]
    public string DefaultNamingContext { get; set; } = string.Empty;

    /// <summary>
    /// Gets the configuration naming context.
    /// </summary>
    [StringLength(2048)]
    public string ConfigurationNamingContext { get; set; } = string.Empty;

    /// <summary>
    /// Gets the schema naming context.
    /// </summary>
    [StringLength(2048)]
    public string SchemaNamingContext { get; set; } = string.Empty;

    /// <summary>
    /// Gets the root domain naming context.
    /// </summary>
    [StringLength(2048)]
    public string RootDomainNamingContext { get; set; } = string.Empty;

    /// <summary>
    /// Gets the forest name.
    /// </summary>
    [StringLength(255)]
    public string ForestName { get; set; } = string.Empty;

    /// <summary>
    /// Gets the DNS host name.
    /// </summary>
    [StringLength(255)]
    public string DnsHostName { get; set; } = string.Empty;

    /// <summary>
    /// Gets the server name.
    /// </summary>
    [StringLength(255)]
    public string ServerName { get; set; } = string.Empty;

    /// <summary>
    /// Gets the site name where this DC is located.
    /// </summary>
    [StringLength(255)]
    public string SiteName { get; set; } = string.Empty;

    /// <summary>
    /// Gets the host name of the domain controller.
    /// </summary>
    [StringLength(255)]
    public string HostName { get; set; } = string.Empty;

    /// <summary>
    /// Gets the distinguished name of the domain controller.
    /// </summary>
    [StringLength(2048)]
    public string DistinguishedName { get; set; } = string.Empty;

    /// <summary>
    /// Gets the AD site this DC belongs to.
    /// </summary>
    [StringLength(255)]
    public string Site { get; set; } = string.Empty;

    /// <summary>
    /// Gets the NTDS Settings DN.
    /// </summary>
    [StringLength(2048)]
    public string NtdsSettingsDn { get; set; } = string.Empty;

    /// <summary>
    /// Gets the Server Object DN.
    /// </summary>
    [StringLength(2048)]
    public string ServerObjectDn { get; set; } = string.Empty;

    /// <summary>Gets a value indicating whether the DC is online.</summary>
    public bool IsOnline { get; set; }

    /// <summary>Gets a value indicating whether the DC is a Read-Only DC.</summary>
    public bool IsRodc { get; set; }

    /// <summary>Gets a value indicating whether the DC is a GC server.</summary>
    public bool IsGlobalCatalog { get; set; }

    /// <summary>Gets a value indicating whether the DC is read-only.</summary>
    public bool IsReadOnly { get; set; }

    /// <summary>Gets or sets the last time the DC was contacted.</summary>
    public DateTimeOffset? LastContactTime { get; set; }

    /// <summary>Gets or sets the response latency in milliseconds.</summary>
    public int? LatencyMs { get; set; }

    /// <summary>Gets or sets the domain identifier.</summary>
    public Guid? DomainId { get; set; }

    /// <summary>Gets or sets the site identifier.</summary>
    public Guid? SiteId { get; set; }

    /// <summary>
    /// Gets or sets the domain type.
    /// </summary>
    public DomainType Type { get; set; }

    private List<string>? _roles;

    /// <summary>
    /// Gets or sets the FSMO roles held by this domain controller.
    /// </summary>
    public IReadOnlyList<string> Roles
    {
        get => _roles?.AsReadOnly() ?? GetFsmoRoles().ToList().AsReadOnly();
        set => _roles = value?.ToList();
    }

    /// <summary>
    /// Gets all FSMO roles held by this domain controller (alias for Roles).
    /// </summary>
    public IReadOnlyList<string> FsmoRoles => Roles;

    /// <summary>
    /// Constructor for controlled instantiation.
    /// </summary>
    public DomainController() { }

    /// <summary>
    /// Creates a new validated DomainController instance.
    /// </summary>
    /// <param name="fqdn">Fully qualified domain name.</param>
    /// <param name="domain">Domain name.</param>
    /// <param name="type">Domain type.</param>
    /// <returns>A validated DomainController instance.</returns>
    /// <exception cref="ArgumentException">Thrown when validation fails.</exception>
    public static DomainController Create(string fqdn, string domain, DomainType type)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(fqdn, nameof(fqdn));
        ArgumentException.ThrowIfNullOrWhiteSpace(domain, nameof(domain));

        // Security: Validate FQDN format to prevent injection attacks
        if (!FqdnPattern.IsMatch(fqdn))
        {
            throw new ArgumentException("Invalid FQDN format. Must be a valid DNS name.", nameof(fqdn));
        }

        if (!DomainPattern.IsMatch(domain))
        {
            throw new ArgumentException("Invalid domain format.", nameof(domain));
        }

        return new DomainController
        {
            Id = Guid.NewGuid(),
            Fqdn = fqdn.ToUpperInvariant(),
            Domain = domain.ToUpperInvariant(),
            Type = type,
            CreatedAt = DateTimeOffset.UtcNow
        };
    }

    /// <summary>
    /// Updates the online status of the domain controller.
    /// </summary>
    /// <param name="isOnline">Whether the DC is online.</param>
    /// <param name="latencyMs">Response latency in milliseconds.</param>
    public void UpdateOnlineStatus(bool isOnline, int? latencyMs = null)
    {
        IsOnline = isOnline;
        LastContactTime = DateTimeOffset.UtcNow;
        LatencyMs = latencyMs;
        ModifiedAt = DateTimeOffset.UtcNow;
    }

    /// <summary>
    /// Sets the IP address of the domain controller.
    /// </summary>
    /// <param name="ipAddress">The IP address.</param>
    public void SetIpAddress(IPAddress ipAddress)
    {
        IpAddress = ipAddress?.ToString() ?? throw new ArgumentNullException(nameof(ipAddress));
        ModifiedAt = DateTimeOffset.UtcNow;
    }

    /// <summary>
    /// Determines if this DC can be used for write operations.
    /// </summary>
    /// <returns>True if writable, false otherwise.</returns>
    public bool CanPerformWriteOperations() => IsOnline && !IsRodc;

    /// <summary>
    /// Gets all FSMO roles held by this domain controller.
    /// </summary>
    /// <returns>Collection of FSMO role names.</returns>
    public IEnumerable<string> GetFsmoRoles()
    {
        var roles = new List<string>();

        if (IsPdcRoleOwner) roles.Add("PDC Emulator");
        if (IsRidMaster) roles.Add("RID Master");
        if (IsInfrastructureMaster) roles.Add("Infrastructure Master");
        if (IsSchemaMaster) roles.Add("Schema Master");
        if (IsDomainNamingMaster) roles.Add("Domain Naming Master");

        return roles.AsReadOnly();
    }

    [GeneratedRegex(@"^(?=(.{1,255})$)[a-zA-Z0-9](?:[a-zA-Z0-9\-]*[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9\-]*[a-zA-Z0-9])?)*$", RegexOptions.Compiled | RegexOptions.CultureInvariant, matchTimeoutMilliseconds: 1000)]
    private static partial Regex GenerateFqdnRegex();

    [GeneratedRegex(@"^(?=(.{1,255})$)[a-zA-Z0-9\- \.]*$", RegexOptions.Compiled | RegexOptions.CultureInvariant, matchTimeoutMilliseconds: 1000)]
    private static partial Regex GenerateDomainRegex();
}

/// <summary>
/// Represents the type of domain in the Active Directory forest.
/// </summary>
public enum DomainType
{
    /// <summary>The forest root domain.</summary>
    ForestRoot = 1,

    /// <summary>A child domain within the forest.</summary>
    ChildDomain = 2,

    /// <summary>A tree root domain in a separate namespace.</summary>
    TreeRoot = 3,

    /// <summary>Unknown domain type.</summary>
    Unknown = 0
}

/// <summary>
/// Represents supported Kerberos encryption types.
/// </summary>
[Flags]
public enum EncryptionTypes
{
    /// <summary>No encryption types specified.</summary>
    None = 0,

    /// <summary>DES-CBC-CRC (deprecated, insecure).</summary>
    DesCbcCrc = 1,

    /// <summary>DES-CBC-MD5 (deprecated, insecure).</summary>
    DesCbcMd5 = 2,

    /// <summary>RC4-HMAC (legacy, weak).</summary>
    Rc4Hmac = 4,

    /// <summary>AES128-CTS-HMAC-SHA1-96.</summary>
    Aes128 = 8,

    /// <summary>AES256-CTS-HMAC-SHA1-96 (recommended).</summary>
    Aes256 = 16
}
