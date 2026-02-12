using DepSafe.Models;
using DepSafe.Scoring;

namespace DepSafe.Tests;

public class UpgradeRiskCalculatorTests
{
    [Fact]
    public void Assess_PatchWithNoSignals_LowRisk()
    {
        var result = UpgradeRiskCalculator.Assess(
            tier: UpgradeEffort.Patch,
            signals: new ChangelogSignals(0, 0, [], [], 1),
            trust: new MaintainerTrust(80, MaintainerTrustTier.High, 10, 500, 20, 3, "maintainer"),
            releasesBetween: 1,
            timeBetween: TimeSpan.FromDays(30));

        Assert.Equal(UpgradeRiskLevel.Low, result.RiskLevel);
        Assert.InRange(result.RiskScore, 0, 25);
    }

    [Fact]
    public void Assess_MajorWithBreakingChanges_HighOrCriticalRisk()
    {
        var signals = new ChangelogSignals(5, 2, ["break1", "break2", "break3", "break4", "break5"], ["dep1", "dep2"], 10);

        var result = UpgradeRiskCalculator.Assess(
            tier: UpgradeEffort.Major,
            signals: signals,
            trust: new MaintainerTrust(60, MaintainerTrustTier.Moderate, 5, 200, 10, 2, "dev"),
            releasesBetween: 10,
            timeBetween: TimeSpan.FromDays(365));

        Assert.True(result.RiskScore > 50, $"Expected > 50 but got {result.RiskScore}");
        Assert.True(result.RiskLevel == UpgradeRiskLevel.High || result.RiskLevel == UpgradeRiskLevel.Critical);
        Assert.Contains(result.RiskFactors, f => f.Contains("breaking", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Assess_LowMaintainerTrust_IncreasesRisk()
    {
        var signals = new ChangelogSignals(0, 0, [], [], 1);

        var highTrust = UpgradeRiskCalculator.Assess(
            UpgradeEffort.Minor, signals,
            new MaintainerTrust(90, MaintainerTrustTier.High, 10, 500, 20, 3, "dev"),
            1, TimeSpan.FromDays(30));

        var lowTrust = UpgradeRiskCalculator.Assess(
            UpgradeEffort.Minor, signals,
            new MaintainerTrust(20, MaintainerTrustTier.Low, 1, 10, 2, 1, "dev"),
            1, TimeSpan.FromDays(30));

        Assert.True(lowTrust.RiskScore > highTrust.RiskScore,
            $"Low trust ({lowTrust.RiskScore}) should be higher risk than high trust ({highTrust.RiskScore})");
    }

    [Fact]
    public void Assess_LongTimeGap_IncreasesRisk()
    {
        var signals = new ChangelogSignals(0, 0, [], [], 1);
        var trust = new MaintainerTrust(70, MaintainerTrustTier.Moderate, 5, 200, 10, 2, "dev");

        var shortGap = UpgradeRiskCalculator.Assess(
            UpgradeEffort.Minor, signals, trust, 1, TimeSpan.FromDays(30));

        var longGap = UpgradeRiskCalculator.Assess(
            UpgradeEffort.Minor, signals, trust, 1, TimeSpan.FromDays(900));

        Assert.True(longGap.RiskScore > shortGap.RiskScore,
            $"Long gap ({longGap.RiskScore}) should be higher risk than short gap ({shortGap.RiskScore})");
    }

    [Fact]
    public void Assess_NullSignals_UsesOnlySemverAndTrust()
    {
        var result = UpgradeRiskCalculator.Assess(
            tier: UpgradeEffort.Major,
            signals: null,
            trust: new MaintainerTrust(50, MaintainerTrustTier.Moderate, 5, 200, 10, 2, "dev"),
            releasesBetween: 0,
            timeBetween: TimeSpan.Zero);

        // Major=50*0.4=20, no changelog=0, trust=(100-50)*0.15=7.5, no time=0 => ~28
        Assert.True(result.RiskScore > 0);
        Assert.NotEmpty(result.RiskFactors);
    }
}
