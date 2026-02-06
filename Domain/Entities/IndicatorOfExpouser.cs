using System.Collections.ObjectModel;
using Phoenix.Core.Domain.Enums;

namespace Phoenix.Core.Domain.Entities;

public class IndicatorOfExposure : EntityBase
{
    public string IoeId { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public IoeCategory Category { get; set; }
    public IoeSeverity DefaultSeverity { get; set; }
    public string LdapFilter { get; set; } = string.Empty;
    public string MitreAttackTechnique { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the MITRE ATT&CK ID (alias for MitreAttackTechnique).
    /// </summary>
    public string MitreAttackId
    {
        get => MitreAttackTechnique;
        set => MitreAttackTechnique = value ?? string.Empty;
    }

    public string Remediation { get; set; } = string.Empty;
    public string? SearchBase { get; set; }
    public string? PowerShellCommand { get; set; }
    public ReadOnlyCollection<string> AffectedObjects { get; set; } = new List<string>().AsReadOnly();
    public int MatchCount { get; set; }
    public DateTime? LastScanned { get; set; }

    public IndicatorOfExposure() { }

    // 8-argument constructor for IoeCatalog
    public IndicatorOfExposure(
        string ioeId,
        string name,
        string description,
        IoeCategory category,
        IoeSeverity severity,
        string ldapFilter,
        string mitreAttackTechnique,
        string remediation)
    {
        IoeId = ioeId;
        Name = name;
        Description = description;
        Category = category;
        DefaultSeverity = severity;
        LdapFilter = ldapFilter;
        MitreAttackTechnique = mitreAttackTechnique;
        Remediation = remediation;
        AffectedObjects = new List<string>().AsReadOnly();
    }

    public void AddAffectedObject(string distinguishedName)
    {
        var list = AffectedObjects.ToList();
        list.Add(distinguishedName);
        AffectedObjects = list.AsReadOnly();
        MatchCount = AffectedObjects.Count;
    }

    public void SetAffectedObjects(IEnumerable<string> objects)
    {
        AffectedObjects = objects.ToList().AsReadOnly();
        MatchCount = AffectedObjects.Count;
    }
}
