namespace DepSafe.Models;

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
