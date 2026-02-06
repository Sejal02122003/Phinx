// --------------------------------------------------------------------------
// Phoenix Identity Incident Response Platform
// Indicator of Exposure (IOE) Catalog
// --------------------------------------------------------------------------

using Phoenix.Core.Domain.Entities;
using Phoenix.Core.Domain.Enums;

namespace Phoenix.Core.Security;

/// <summary>
/// Catalog of Indicators of Exposure (IOE) for Active Directory security assessment.
/// </summary>
public static class IoeCatalog
{
    private static readonly List<IndicatorOfExposure> _indicators = [];
    private static bool _initialized;
    private static readonly object _lock = new();

    public static IReadOnlyList<IndicatorOfExposure> GetAll()
    {
        EnsureInitialized();
        return _indicators.AsReadOnly();
    }

    public static IEnumerable<IndicatorOfExposure> GetByCategory(IoeCategory category)
    {
        EnsureInitialized();
        return _indicators.Where(i => i.Category == category);
    }

    public static IEnumerable<IndicatorOfExposure> GetBySeverity(IoeSeverity severity)
    {
        EnsureInitialized();
        return _indicators.Where(i => i.DefaultSeverity == severity);
    }

    public static IndicatorOfExposure? GetById(string ioeId)
    {
        EnsureInitialized();
        return _indicators.FirstOrDefault(i => i.IoeId == ioeId);
    }

    private static void EnsureInitialized()
    {
        if (_initialized) return;
        lock (_lock)
        {
            if (_initialized) return;
            Initialize();
            _initialized = true;
        }
    }

    private static void Initialize()
    {
        // === KERBEROS CHECKS ===
        _indicators.Add(new IndicatorOfExposure(
            "IOE-K001", "KRBTGT Password Age",
            "KRBTGT account password is older than 180 days",
            IoeCategory.Kerberos, IoeSeverity.Critical,
            "(&(objectClass=user)(sAMAccountName=krbtgt))",
            "T1558.001", "Reset KRBTGT password twice"));

        _indicators.Add(new IndicatorOfExposure(
            "IOE-K002", "Kerberos Pre-Auth Disabled",
            "Accounts vulnerable to AS-REP roasting",
            IoeCategory.Kerberos, IoeSeverity.Critical,
            "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))",
            "T1558.004", "Enable Kerberos pre-authentication"));

        _indicators.Add(new IndicatorOfExposure(
            "IOE-K003", "Privileged SPN",
            "Privileged accounts with SPNs vulnerable to Kerberoasting",
            IoeCategory.Kerberos, IoeSeverity.Critical,
            "(&(objectClass=user)(servicePrincipalName=*)(adminCount=1))",
            "T1558.003", "Remove SPNs or use gMSA"));

        _indicators.Add(new IndicatorOfExposure(
            "IOE-K004", "User with SPN",
            "User accounts with SPNs",
            IoeCategory.Kerberos, IoeSeverity.Warning,
            "(&(objectClass=user)(servicePrincipalName=*)(!(objectClass=computer)))",
            "T1558.003", "Use gMSA for services"));

        _indicators.Add(new IndicatorOfExposure(
            "IOE-K005", "DES Encryption",
            "Accounts using weak DES encryption",
            IoeCategory.Kerberos, IoeSeverity.Critical,
            "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2097152))",
            "T1558", "Disable DES encryption"));

        // === DELEGATION CHECKS ===
        _indicators.Add(new IndicatorOfExposure(
            "IOE-D001", "Unconstrained Delegation",
            "Accounts with unconstrained delegation",
            IoeCategory.Delegation, IoeSeverity.Critical,
            "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=524288))",
            "T1558.003", "Use constrained delegation"));

        _indicators.Add(new IndicatorOfExposure(
            "IOE-D002", "RBCD Configured",
            "Resource-Based Constrained Delegation configured",
            IoeCategory.Delegation, IoeSeverity.Warning,
            "(&(objectClass=user)(msDS-AllowedToActOnBehalfOfOtherIdentity=*))",
            "T1558.003", "Review RBCD configurations"));

        _indicators.Add(new IndicatorOfExposure(
            "IOE-D003", "RBCD on DC",
            "Domain Controller with RBCD",
            IoeCategory.Delegation, IoeSeverity.Critical,
            "(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192)(msDS-AllowedToActOnBehalfOfOtherIdentity=*))",
            "T1558.003", "Remove RBCD from DCs"));

        // === PRIVILEGED ACCESS CHECKS ===
        _indicators.Add(new IndicatorOfExposure(
            "IOE-P001", "SID History",
            "Privileged accounts with SID History",
            IoeCategory.Privileged, IoeSeverity.Critical,
            "(&(objectClass=user)(adminCount=1)(sIDHistory=*))",
            "T1134.005", "Remove SID History"));

        _indicators.Add(new IndicatorOfExposure(
            "IOE-P002", "DCSync Rights",
            "Non-DC with replication rights",
            IoeCategory.Privileged, IoeSeverity.Critical,
            "(&(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=8192)))",
            "T1003.006", "Remove DCSync rights"));

        _indicators.Add(new IndicatorOfExposure(
            "IOE-P003", "Excessive Admins",
            "Too many Domain Admins",
            IoeCategory.Privileged, IoeSeverity.Warning,
            "(&(objectClass=group)(cn=Domain Admins))",
            "T1078.002", "Reduce membership"));

        // === PASSWORD POLICY CHECKS ===
        _indicators.Add(new IndicatorOfExposure(
            "IOE-PP001", "Password Not Required",
            "Accounts without password requirement",
            IoeCategory.Password, IoeSeverity.Critical,
            "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=32))",
            "T1078", "Require passwords"));

        _indicators.Add(new IndicatorOfExposure(
            "IOE-PP002", "Password Never Expires",
            "Accounts with non-expiring passwords",
            IoeCategory.Password, IoeSeverity.Warning,
            "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=65536))",
            "T1078", "Implement expiration"));

        _indicators.Add(new IndicatorOfExposure(
            "IOE-PP003", "Reversible Encryption",
            "Passwords stored with reversible encryption",
            IoeCategory.Password, IoeSeverity.Critical,
            "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=128))",
            "T1552", "Disable reversible encryption"));

        // === DOMAIN CONTROLLER CHECKS ===
        _indicators.Add(new IndicatorOfExposure(
            "IOE-DC001", "Print Spooler on DC",
            "Print Spooler service enabled on Domain Controller",
            IoeCategory.DomainController, IoeSeverity.Critical,
            "(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))",
            "T1547.012", "Disable Print Spooler on DCs"));

        _indicators.Add(new IndicatorOfExposure(
            "IOE-DC002", "SMBv1 Enabled",
            "SMBv1 protocol enabled",
            IoeCategory.DomainController, IoeSeverity.Critical,
            "(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))",
            "T1021.002", "Disable SMBv1"));

        _indicators.Add(new IndicatorOfExposure(
            "IOE-DC003", "LDAP Signing Not Required",
            "LDAP signing not enforced",
            IoeCategory.DomainController, IoeSeverity.Critical,
            "(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))",
            "T1557.001", "Require LDAP signing"));

        // === GROUP POLICY CHECKS ===
        _indicators.Add(new IndicatorOfExposure(
            "IOE-GP001", "GPP Passwords",
            "Group Policy Preferences passwords",
            IoeCategory.GroupPolicy, IoeSeverity.Critical,
            "(&(objectClass=groupPolicyContainer))",
            "T1552.006", "Remove GPP passwords"));

        _indicators.Add(new IndicatorOfExposure(
            "IOE-GP002", "GPO Permissions",
            "Weak GPO modification permissions",
            IoeCategory.GroupPolicy, IoeSeverity.Warning,
            "(&(objectClass=groupPolicyContainer))",
            "T1484.001", "Restrict GPO permissions"));

        // === CERTIFICATE CHECKS ===
        _indicators.Add(new IndicatorOfExposure(
            "IOE-CS001", "ESC1 Vulnerable",
            "Certificate template allows SAN override",
            IoeCategory.Certificate, IoeSeverity.Critical,
            "(&(objectClass=pKiCertificateTemplate))",
            "T1649", "Fix template permissions"));

        _indicators.Add(new IndicatorOfExposure(
            "IOE-CS002", "Weak Key Size",
            "Templates with weak key sizes",
            IoeCategory.Certificate, IoeSeverity.Warning,
            "(&(objectClass=pKiCertificateTemplate))",
            "T1552.004", "Require 2048+ bit keys"));

        // === DOMAIN CHECKS ===
        _indicators.Add(new IndicatorOfExposure(
            "IOE-DOM001", "Machine Account Quota",
            "Default machine account quota allows any user to join computers",
            IoeCategory.Domain, IoeSeverity.Warning,
            "(&(objectClass=domainDNS))",
            "T1136.002", "Set ms-DS-MachineAccountQuota to 0"));

        _indicators.Add(new IndicatorOfExposure(
            "IOE-DOM002", "Guest Account Enabled",
            "Guest account is enabled",
            IoeCategory.Domain, IoeSeverity.Warning,
            "(&(objectClass=user)(sAMAccountName=Guest)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
            "T1078.001", "Disable Guest account"));

        // === OBJECT CHECKS ===
        _indicators.Add(new IndicatorOfExposure(
            "IOE-OBJ001", "Obsolete OS",
            "Computers running obsolete operating systems",
            IoeCategory.Objects, IoeSeverity.Critical,
            "(&(objectClass=computer)(|(operatingSystem=*2003*)(operatingSystem=*XP*)(operatingSystem=*2000*)))",
            "T1210", "Upgrade or decommission"));

        _indicators.Add(new IndicatorOfExposure(
            "IOE-OBJ002", "Stale Computers",
            "Computer accounts not logged in for 90+ days",
            IoeCategory.Objects, IoeSeverity.Informational,
            "(&(objectClass=computer))",
            "T1078.002", "Disable stale accounts"));
    }
}
