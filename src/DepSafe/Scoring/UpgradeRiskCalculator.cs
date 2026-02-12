using DepSafe.Models;

namespace DepSafe.Scoring;

/// <summary>
/// Computes a composite upgrade risk score (0-100) from semver tier, changelog signals,
/// maintainer trust, and time gap between versions.
/// </summary>
public static class UpgradeRiskCalculator
{
    private const double SemverWeight = 0.40;
    private const double ChangelogWeight = 0.35;
    private const double StabilityWeight = 0.15;
    private const double TimeGapWeight = 0.10;
    private const double MaxTimeGapDays = 730.0;

    /// <summary>
    /// Assess the risk of upgrading to a specific version tier.
    /// </summary>
    public static UpgradeRiskAssessment Assess(
        UpgradeEffort tier,
        ChangelogSignals? signals,
        MaintainerTrust? trust,
        int releasesBetween,
        TimeSpan timeBetween)
    {
        var riskFactors = new List<string>();

        // 1. Semver signal (0-100 scaled): Patch=0, Minor=25, Major=50
        double semverRaw = tier switch
        {
            UpgradeEffort.Patch => 0,
            UpgradeEffort.Minor => 25,
            UpgradeEffort.Major => 50,
            _ => 50
        };
        if (tier == UpgradeEffort.Major)
            riskFactors.Add("Major version bump (possible breaking changes)");
        else if (tier == UpgradeEffort.Minor)
            riskFactors.Add("Minor version bump (new features)");

        // 2. Changelog signals (0-100 scaled)
        double changelogRaw = 0;
        int breakingCount = 0;
        int deprecationCount = 0;
        if (signals is not null)
        {
            breakingCount = signals.BreakingChangeCount;
            deprecationCount = signals.DeprecationCount;
            changelogRaw = Math.Min(breakingCount * 10 + deprecationCount * 5, 100);

            if (breakingCount > 0)
                riskFactors.Add($"{breakingCount} breaking change signal{(breakingCount > 1 ? "s" : "")} detected");
            if (deprecationCount > 0)
                riskFactors.Add($"{deprecationCount} deprecation signal{(deprecationCount > 1 ? "s" : "")} detected");
        }

        // 3. Stability / maintainer trust (0-100 scaled): 100 - trust score
        int trustScore = trust?.Score ?? 50;
        double stabilityRaw = 100 - trustScore;
        if (trustScore < 40)
            riskFactors.Add($"Low maintainer trust (score: {trustScore})");

        // 4. Time gap (0-100 scaled): days/730*100, capped at 100
        double days = Math.Max(timeBetween.TotalDays, 0);
        double timeGapRaw = Math.Min(days / MaxTimeGapDays * 100, 100);
        if (days > 365)
        {
            int months = (int)(days / 30.44);
            riskFactors.Add($"{months} months between versions");
        }

        // Composite score
        double composite = semverRaw * SemverWeight
                         + changelogRaw * ChangelogWeight
                         + stabilityRaw * StabilityWeight
                         + timeGapRaw * TimeGapWeight;

        int riskScore = (int)Math.Round(Math.Clamp(composite, 0, 100));

        var riskLevel = riskScore switch
        {
            <= 25 => UpgradeRiskLevel.Low,
            <= 50 => UpgradeRiskLevel.Medium,
            <= 75 => UpgradeRiskLevel.High,
            _ => UpgradeRiskLevel.Critical,
        };

        if (riskFactors.Count == 0)
            riskFactors.Add("No significant risk factors identified");

        return new UpgradeRiskAssessment(
            RiskScore: riskScore,
            RiskLevel: riskLevel,
            BreakingChangeSignals: breakingCount,
            DeprecationSignals: deprecationCount,
            RiskFactors: riskFactors,
            ReleasesBetween: releasesBetween,
            TimeBetween: timeBetween);
    }
}
