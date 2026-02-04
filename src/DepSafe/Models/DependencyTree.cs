namespace DepSafe.Models;

/// <summary>
/// Type of project detected.
/// </summary>
public enum ProjectType
{
    /// <summary>.NET project (csproj, fsproj, vbproj, sln)</summary>
    DotNet,
    /// <summary>Node.js/npm project (package.json)</summary>
    Npm,
    /// <summary>Mixed project containing both .NET and npm</summary>
    Mixed
}

/// <summary>
/// Package ecosystem identifier.
/// </summary>
public enum PackageEcosystem
{
    NuGet,
    Npm
}

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

/// <summary>
/// Complete dependency tree for a project.
/// </summary>
public sealed class DependencyTree
{
    public required string ProjectPath { get; init; }
    public required ProjectType ProjectType { get; init; }
    public required List<DependencyTreeNode> Roots { get; init; }

    /// <summary>Total number of unique packages in the tree.</summary>
    public int TotalPackages { get; set; }

    /// <summary>Maximum depth of the dependency tree.</summary>
    public int MaxDepth { get; set; }

    /// <summary>Number of packages with known vulnerabilities.</summary>
    public int VulnerableCount { get; set; }

    /// <summary>Number of packages with version conflicts (same package, different versions).</summary>
    public int VersionConflictCount { get; set; }

    /// <summary>Detected dependency issues (version conflicts, peer mismatches).</summary>
    public List<DependencyIssue> Issues { get; set; } = [];
}

/// <summary>
/// Type of dependency issue detected.
/// </summary>
public enum DependencyIssueType
{
    /// <summary>Same package appears with multiple different versions.</summary>
    VersionConflict,
    /// <summary>Peer dependency version requirement not satisfied.</summary>
    PeerDependencyMismatch
}

/// <summary>
/// A detected dependency issue in the tree.
/// </summary>
public sealed class DependencyIssue
{
    /// <summary>Type of the issue.</summary>
    public required DependencyIssueType Type { get; init; }

    /// <summary>Package that has the issue.</summary>
    public required string PackageId { get; init; }

    /// <summary>Versions involved in the conflict.</summary>
    public required List<string> Versions { get; init; }

    /// <summary>Human-readable description of the issue.</summary>
    public required string Description { get; init; }

    /// <summary>Severity of the issue (for sorting/display).</summary>
    public string Severity { get; init; } = "Warning";

    /// <summary>Recommendation to resolve the issue.</summary>
    public string? Recommendation { get; init; }
}
