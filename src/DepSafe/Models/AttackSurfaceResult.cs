namespace DepSafe.Models;

/// <summary>
/// Result of attack surface analysis per CRA Annex I Part I(10).
/// </summary>
public sealed class AttackSurfaceResult
{
    /// <summary>Number of direct dependencies.</summary>
    public required int DirectCount { get; init; }

    /// <summary>Number of transitive dependencies.</summary>
    public required int TransitiveCount { get; init; }

    /// <summary>Ratio of transitive to direct dependencies.</summary>
    public double TransitiveToDirectRatio => DirectCount > 0
        ? Math.Round((double)TransitiveCount / DirectCount, 1)
        : 0;

    /// <summary>Maximum depth of the dependency tree.</summary>
    public required int MaxDepth { get; init; }

    /// <summary>Packages with more than 20 transitive dependencies ("heavy" packages).</summary>
    public required List<(string PackageId, int TransitiveCount)> HeavyPackages { get; init; }
}
