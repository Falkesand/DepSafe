namespace DepSafe.Models;

/// <summary>
/// Type of package dependency relationship.
/// </summary>
public enum DependencyType
{
    /// <summary>Directly referenced in project file.</summary>
    Direct,
    /// <summary>Transitive dependency (dependency of a direct package, resolved by NuGet).</summary>
    Transitive,
    /// <summary>Sub-dependency (dependency of another package in the report).</summary>
    SubDependency
}
