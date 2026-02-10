namespace DepSafe.Scoring;

/// <summary>
/// Result of security budget optimization: tiered remediation items with risk reduction analysis.
/// </summary>
public sealed class SecurityBudgetResult
{
    public required List<TieredRemediationItem> Items { get; init; }
    public required int TotalRiskScore { get; init; }
    public required int HighROIRiskReduction { get; init; }
    public required double HighROIPercentage { get; init; }
}
