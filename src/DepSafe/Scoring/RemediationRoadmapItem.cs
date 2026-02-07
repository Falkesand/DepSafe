namespace DepSafe.Scoring;

/// <summary>
/// A prioritized remediation action for the CRA Remediation Roadmap.
/// </summary>
public sealed class RemediationRoadmapItem
{
    public required string PackageId { get; init; }
    public required string CurrentVersion { get; init; }
    public required string RecommendedVersion { get; init; }
    public required int CveCount { get; init; }
    public required List<string> CveIds { get; init; }
    public required int ScoreLift { get; init; }
    public required UpgradeEffort Effort { get; init; }
    public bool HasKevVulnerability { get; init; }
    public double MaxEpssProbability { get; init; }
    public int MaxPatchAgeDays { get; init; }

    /// <summary>Computed priority score for sorting (higher = more urgent).</summary>
    public int PriorityScore { get; init; }
}
