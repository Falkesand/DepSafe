namespace DepSafe.Scoring;

/// <summary>
/// Groups remediation items into ROI tiers for security budget optimization.
/// High-ROI items achieve the most risk reduction per unit of upgrade effort.
/// </summary>
public static class SecurityBudgetOptimizer
{
    private const double HighRoiThreshold = 0.80;

    /// <summary>
    /// Optimize a remediation roadmap into ROI-tiered recommendations.
    /// Algorithm: ROI = PriorityScore / EffortWeight (Patch=1, Minor=2, Major=3).
    /// Sort by ROI descending. HighROI tier = items until cumulative risk reaches 80% of total.
    /// </summary>
    public static SecurityBudgetResult Optimize(List<RemediationRoadmapItem> roadmap)
    {
        if (roadmap.Count == 0)
        {
            return new SecurityBudgetResult
            {
                Items = [],
                TotalRiskScore = 0,
                HighROIRiskReduction = 0,
                HighROIPercentage = 0,
            };
        }

        int totalRisk = 0;
        foreach (var item in roadmap)
            totalRisk += item.PriorityScore;

        // Calculate ROI and sort descending
        var scored = new List<(RemediationRoadmapItem Item, double Roi)>(roadmap.Count);
        foreach (var item in roadmap)
        {
            int effortWeight = item.Effort switch
            {
                UpgradeEffort.Patch => 1,
                UpgradeEffort.Minor => 2,
                UpgradeEffort.Major => 3,
                _ => 3,
            };
            double roi = (double)item.PriorityScore / effortWeight;
            scored.Add((item, roi));
        }
        scored.Sort((a, b) =>
        {
            int cmp = b.Roi.CompareTo(a.Roi);
            if (cmp != 0) return cmp;
            cmp = b.Item.PriorityScore.CompareTo(a.Item.PriorityScore);
            return cmp != 0 ? cmp : string.Compare(a.Item.PackageId, b.Item.PackageId, StringComparison.Ordinal);
        });

        // Assign tiers based on cumulative risk reduction
        double cumulativeRisk = 0;
        double highRoiThresholdAbs = totalRisk * HighRoiThreshold;
        int highRoiReduction = 0;
        bool thresholdReached = false;

        var tieredItems = new List<TieredRemediationItem>(scored.Count);
        foreach (var (item, roi) in scored)
        {
            cumulativeRisk += item.PriorityScore;
            double cumulativePercent = totalRisk > 0
                ? Math.Round(100.0 * cumulativeRisk / totalRisk, 1)
                : 0;

            var tier = thresholdReached ? RemediationTier.LowROI : RemediationTier.HighROI;
            if (!thresholdReached)
                highRoiReduction += item.PriorityScore;

            tieredItems.Add(new TieredRemediationItem
            {
                Item = item,
                Tier = tier,
                RoiScore = roi,
                CumulativeRiskReductionPercent = cumulativePercent,
            });

            if (!thresholdReached && cumulativeRisk >= highRoiThresholdAbs)
                thresholdReached = true;
        }

        double highRoiPercent = totalRisk > 0
            ? Math.Round(100.0 * highRoiReduction / totalRisk, 1)
            : 0;

        return new SecurityBudgetResult
        {
            Items = tieredItems,
            TotalRiskScore = totalRisk,
            HighROIRiskReduction = highRoiReduction,
            HighROIPercentage = highRoiPercent,
        };
    }
}
