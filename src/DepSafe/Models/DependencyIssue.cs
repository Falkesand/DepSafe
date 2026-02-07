namespace DepSafe.Models;

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
