namespace DepSafe.Scoring;

/// <summary>
/// A remediation item enriched with ROI tier and cumulative risk reduction data.
/// </summary>
public sealed class TieredRemediationItem
{
    public required RemediationRoadmapItem Item { get; init; }
    public required RemediationTier Tier { get; init; }
    public required double RoiScore { get; init; }
    public required double CumulativeRiskReductionPercent { get; init; }
}
