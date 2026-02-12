using DepSafe.Scoring;

namespace DepSafe.Tests;

public class SecurityBudgetOptimizerTests
{
    private static RemediationRoadmapItem CreateItem(
        string id = "Pkg",
        int priorityScore = 100,
        UpgradeEffort effort = UpgradeEffort.Patch,
        int scoreLift = 5) => new()
    {
        PackageId = id,
        CurrentVersion = "1.0.0",
        RecommendedVersion = "2.0.0",
        CveCount = 1,
        CveIds = ["CVE-2024-0001"],
        ScoreLift = scoreLift,
        Effort = effort,
        PriorityScore = priorityScore,
    };

    [Fact]
    public void Optimize_EmptyRoadmap_ReturnsEmptyResult()
    {
        var result = SecurityBudgetOptimizer.Optimize([]);

        Assert.Empty(result.Items);
        Assert.Equal(0, result.TotalRiskScore);
        Assert.Equal(0, result.HighROIRiskReduction);
        Assert.Equal(0, result.HighROIPercentage);
    }

    [Fact]
    public void Optimize_SingleItem_IsHighROI()
    {
        var items = new List<RemediationRoadmapItem> { CreateItem(priorityScore: 500) };

        var result = SecurityBudgetOptimizer.Optimize(items);

        Assert.Single(result.Items);
        Assert.Equal(RemediationTier.HighROI, result.Items[0].Tier);
        Assert.Equal(100.0, result.Items[0].CumulativeRiskReductionPercent);
    }

    [Fact]
    public void Optimize_SortsByRoiDescending()
    {
        var items = new List<RemediationRoadmapItem>
        {
            CreateItem(id: "LowROI", priorityScore: 100, effort: UpgradeEffort.Major),   // ROI = 100/3 ≈ 33
            CreateItem(id: "HighROI", priorityScore: 300, effort: UpgradeEffort.Patch),  // ROI = 300/1 = 300
            CreateItem(id: "MedROI", priorityScore: 200, effort: UpgradeEffort.Minor),   // ROI = 200/2 = 100
        };

        var result = SecurityBudgetOptimizer.Optimize(items);

        Assert.Equal("HighROI", result.Items[0].Item.PackageId);
        Assert.Equal("MedROI", result.Items[1].Item.PackageId);
        Assert.Equal("LowROI", result.Items[2].Item.PackageId);
    }

    [Fact]
    public void Optimize_EffortWeights_PatchOneMinorTwoMajorThree()
    {
        // Same priority score, different effort -> different ROI
        var patchItem = CreateItem(id: "Patch", priorityScore: 600, effort: UpgradeEffort.Patch);
        var minorItem = CreateItem(id: "Minor", priorityScore: 600, effort: UpgradeEffort.Minor);
        var majorItem = CreateItem(id: "Major", priorityScore: 600, effort: UpgradeEffort.Major);

        var result = SecurityBudgetOptimizer.Optimize([patchItem, minorItem, majorItem]);

        Assert.Equal(600.0, result.Items[0].RoiScore); // Patch: 600/1
        Assert.Equal(300.0, result.Items[1].RoiScore);  // Minor: 600/2
        Assert.Equal(200.0, result.Items[2].RoiScore);  // Major: 600/3
    }

    [Fact]
    public void Optimize_80PercentThreshold_SplitsTiers()
    {
        // Create items where first two cover >= 80% of total risk
        var items = new List<RemediationRoadmapItem>
        {
            CreateItem(id: "A", priorityScore: 500, effort: UpgradeEffort.Patch),  // ROI = 500
            CreateItem(id: "B", priorityScore: 300, effort: UpgradeEffort.Patch),  // ROI = 300
            CreateItem(id: "C", priorityScore: 100, effort: UpgradeEffort.Patch),  // ROI = 100
            CreateItem(id: "D", priorityScore: 50, effort: UpgradeEffort.Patch),   // ROI = 50
            CreateItem(id: "E", priorityScore: 50, effort: UpgradeEffort.Patch),   // ROI = 50
        };
        // Total = 1000. A=500 (50%), A+B=800 (80%) — exactly 80%, so A+B = HighROI

        var result = SecurityBudgetOptimizer.Optimize(items);

        Assert.Equal(RemediationTier.HighROI, result.Items[0].Tier);  // A
        Assert.Equal(RemediationTier.HighROI, result.Items[1].Tier);  // B
        Assert.Equal(RemediationTier.LowROI, result.Items[2].Tier);   // C
        Assert.Equal(RemediationTier.LowROI, result.Items[3].Tier);   // D
        Assert.Equal(RemediationTier.LowROI, result.Items[4].Tier);   // E
    }

    [Fact]
    public void Optimize_CumulativeRiskReduction_IsCorrect()
    {
        var items = new List<RemediationRoadmapItem>
        {
            CreateItem(id: "A", priorityScore: 600, effort: UpgradeEffort.Patch),
            CreateItem(id: "B", priorityScore: 400, effort: UpgradeEffort.Patch),
        };
        // Total = 1000. A = 60%, A+B = 100%

        var result = SecurityBudgetOptimizer.Optimize(items);

        Assert.Equal(60.0, result.Items[0].CumulativeRiskReductionPercent);
        Assert.Equal(100.0, result.Items[1].CumulativeRiskReductionPercent);
    }

    [Fact]
    public void Optimize_TotalRiskScore_IsSumOfPriorityScores()
    {
        var items = new List<RemediationRoadmapItem>
        {
            CreateItem(id: "A", priorityScore: 300),
            CreateItem(id: "B", priorityScore: 200),
        };

        var result = SecurityBudgetOptimizer.Optimize(items);

        Assert.Equal(500, result.TotalRiskScore);
    }

    [Fact]
    public void Optimize_HighROIPercentage_ReflectsHighTierReduction()
    {
        var items = new List<RemediationRoadmapItem>
        {
            CreateItem(id: "Big", priorityScore: 900, effort: UpgradeEffort.Patch),
            CreateItem(id: "Small", priorityScore: 100, effort: UpgradeEffort.Patch),
        };
        // Total = 1000. Big = 90% > 80% threshold -> Big = HighROI

        var result = SecurityBudgetOptimizer.Optimize(items);

        Assert.Equal(900, result.HighROIRiskReduction);
        Assert.Equal(90.0, result.HighROIPercentage);
    }

    [Fact]
    public void Optimize_MixedVulnAndMaintenance_SortsByRoi()
    {
        var vulnItem = CreateItem(id: "VulnPkg", priorityScore: 500, effort: UpgradeEffort.Patch);
        var maintItem = CreateItem(id: "DeprecatedPkg", priorityScore: 200, effort: UpgradeEffort.Major);

        var result = SecurityBudgetOptimizer.Optimize([vulnItem, maintItem]);

        // VulnPkg: ROI = 500/1 = 500. DeprecatedPkg: ROI = 200/3 ≈ 67.
        Assert.Equal("VulnPkg", result.Items[0].Item.PackageId);
        Assert.Equal("DeprecatedPkg", result.Items[1].Item.PackageId);
    }

    [Fact]
    public void Optimize_MaintenanceItemMajorEffort_LowerRoi()
    {
        // Same priority score but Major effort should have lower ROI
        var patchItem = CreateItem(id: "PatchPkg", priorityScore: 300, effort: UpgradeEffort.Patch);
        var majorItem = CreateItem(id: "MajorPkg", priorityScore: 300, effort: UpgradeEffort.Major);

        var result = SecurityBudgetOptimizer.Optimize([patchItem, majorItem]);

        Assert.Equal("PatchPkg", result.Items[0].Item.PackageId);
        Assert.True(result.Items[0].RoiScore > result.Items[1].RoiScore);
    }
}
