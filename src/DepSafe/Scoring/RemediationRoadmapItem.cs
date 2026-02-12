using DepSafe.Models;

namespace DepSafe.Scoring;

/// <summary>
/// A prioritized remediation action for the CRA Remediation Roadmap.
/// </summary>
public sealed class RemediationRoadmapItem
{
    public required string PackageId { get; init; }
    public required string CurrentVersion { get; init; }
    public string RecommendedVersion { get; init; } = "";
    public int CveCount { get; init; }
    public List<string> CveIds { get; init; } = [];
    public int ScoreLift { get; init; }
    public required UpgradeEffort Effort { get; init; }
    public bool HasKevVulnerability { get; init; }
    public double MaxEpssProbability { get; init; }
    public int MaxPatchAgeDays { get; init; }

    /// <summary>Computed priority score for sorting (higher = more urgent).</summary>
    public int PriorityScore { get; init; }

    /// <summary>Available upgrade tiers ranked by effort (patch → minor → major). Only distinct tiers included.</summary>
    public List<UpgradeTier> UpgradeTiers { get; init; } = [];

    /// <summary>Why this package appears in the roadmap.</summary>
    public RemediationReason Reason { get; init; } = RemediationReason.Vulnerability;

    /// <summary>Direct or transitive dependency.</summary>
    public DependencyType DependencyType { get; init; } = DependencyType.Direct;

    /// <summary>Parent dependency chain for transitives (e.g. "Newtonsoft.Json → yaml-parser").</summary>
    public string? ParentChain { get; init; }

    /// <summary>Human-readable action text (e.g. "Upgrade 1.0 → 2.0", "Replace deprecated package").</summary>
    public string? ActionText { get; init; }

    /// <summary>Per-tier risk assessments keyed by target version. Null when no GitHub repo available.</summary>
    public Dictionary<string, UpgradeRiskAssessment>? TierRiskAssessments { get; init; }
}
