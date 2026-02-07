namespace DepSafe.Models;

/// <summary>
/// A node in the dependency tree.
/// </summary>
public sealed class DependencyTreeNode
{
    public required string PackageId { get; init; }
    public required string Version { get; init; }
    public int? HealthScore { get; set; }
    public HealthStatus? Status { get; set; }
    public DependencyType DependencyType { get; init; }
    public int Depth { get; init; }
    public List<DependencyTreeNode> Children { get; init; } = [];

    /// <summary>True if this package appears elsewhere in the tree at a different depth.</summary>
    public bool IsDuplicate { get; set; }

    /// <summary>True if this package appears with a different version elsewhere in the tree.</summary>
    public bool HasVersionConflict { get; set; }

    /// <summary>Other versions of this package found in the tree.</summary>
    public List<string> ConflictingVersions { get; set; } = [];

    /// <summary>True if this package has known vulnerabilities.</summary>
    public bool HasVulnerabilities { get; set; }

    /// <summary>True if this package has a CISA KEV vulnerability (actively exploited).</summary>
    public bool HasKevVulnerability { get; set; }

    /// <summary>URL to primary vulnerability details (e.g., OSV).</summary>
    public string? VulnerabilityUrl { get; set; }

    /// <summary>Brief summary of the vulnerability for tooltip display.</summary>
    public string? VulnerabilitySummary { get; set; }

    /// <summary>True if any descendant (child, grandchild, etc.) has vulnerabilities.</summary>
    public bool HasVulnerableDescendant { get; set; }

    /// <summary>License identifier if known.</summary>
    public string? License { get; set; }

    /// <summary>Package ecosystem (NuGet or npm).</summary>
    public PackageEcosystem Ecosystem { get; init; } = PackageEcosystem.NuGet;
}
