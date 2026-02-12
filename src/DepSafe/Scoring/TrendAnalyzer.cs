using DepSafe.Compliance;
using DepSafe.Models;

namespace DepSafe.Scoring;

public static class TrendAnalyzer
{
    public static TrendSummary Analyze(IReadOnlyList<TrendSnapshot> snapshots)
    {
        if (snapshots.Count < 2)
        {
            return new TrendSummary(
                Metrics: [],
                SnapshotCount: snapshots.Count,
                FirstSnapshot: snapshots.Count > 0 ? snapshots[0].CapturedAt : null,
                LastSnapshot: snapshots.Count > 0 ? snapshots[^1].CapturedAt : null,
                OverallDirection: TrendDirection.Stable);
        }

        var current = snapshots[^1];
        var previous = snapshots[^2];

        var metrics = new List<TrendMetric>
        {
            BuildMetric("Health Score", current.HealthScore, previous.HealthScore, snapshots, s => s.HealthScore, higherIsBetter: true),
            BuildMetric("CRA Readiness Score", current.CraReadinessScore, previous.CraReadinessScore, snapshots, s => s.CraReadinessScore, higherIsBetter: true),
            BuildMetric("Vulnerability Count", current.VulnerabilityCount, previous.VulnerabilityCount, snapshots, s => s.VulnerabilityCount, higherIsBetter: false),
            BuildMetric("Critical Packages", current.CriticalPackageCount, previous.CriticalPackageCount, snapshots, s => s.CriticalPackageCount, higherIsBetter: false),
            BuildMetric("Reportable Vulnerabilities", current.ReportableVulnerabilityCount, previous.ReportableVulnerabilityCount, snapshots, s => s.ReportableVulnerabilityCount, higherIsBetter: false),
            BuildNullableMetric("SBOM Completeness", current.SbomCompletenessPercentage, previous.SbomCompletenessPercentage, snapshots, s => s.SbomCompletenessPercentage, higherIsBetter: true),
            BuildNullableMetric("Max Unpatched Days", current.MaxUnpatchedVulnerabilityDays, previous.MaxUnpatchedVulnerabilityDays, snapshots, s => s.MaxUnpatchedVulnerabilityDays, higherIsBetter: false)
        };

        // Overall direction: majority of the 7 metrics
        var improvingCount = metrics.Count(m => m.Direction == TrendDirection.Improving);
        var degradingCount = metrics.Count(m => m.Direction == TrendDirection.Degrading);
        var overallDirection = improvingCount > degradingCount ? TrendDirection.Improving
            : degradingCount > improvingCount ? TrendDirection.Degrading
            : TrendDirection.Stable;

        return new TrendSummary(
            Metrics: metrics,
            SnapshotCount: snapshots.Count,
            FirstSnapshot: snapshots[0].CapturedAt,
            LastSnapshot: snapshots[^1].CapturedAt,
            OverallDirection: overallDirection);
    }

    public static TrendSnapshot BuildSnapshot(CraReport report)
    {
        return new TrendSnapshot(
            CapturedAt: report.GeneratedAt,
            ProjectPath: report.ProjectPath,
            HealthScore: report.HealthScore,
            CraReadinessScore: report.CraReadinessScore,
            VulnerabilityCount: report.VulnerabilityCount,
            CriticalPackageCount: report.CriticalPackageCount,
            ReportableVulnerabilityCount: report.ReportableVulnerabilityCount,
            MaxUnpatchedVulnerabilityDays: report.MaxUnpatchedVulnerabilityDays,
            SbomCompletenessPercentage: report.SbomCompletenessPercentage,
            MaxDependencyDepth: report.MaxDependencyDepth,
            HasUnmaintainedPackages: report.HasUnmaintainedPackages,
            PackageCount: report.PackageCount,
            TransitivePackageCount: report.TransitivePackageCount);
    }

    private static TrendMetric BuildMetric(
        string name, int current, int previous,
        IReadOnlyList<TrendSnapshot> snapshots,
        Func<TrendSnapshot, int> selector,
        bool higherIsBetter)
    {
        var delta = current - previous;
        var direction = DetermineDirection(snapshots, s => (int?)selector(s), higherIsBetter);

        return new TrendMetric(name, current, previous, delta, direction, higherIsBetter);
    }

    private static TrendMetric BuildNullableMetric(
        string name, int? current, int? previous,
        IReadOnlyList<TrendSnapshot> snapshots,
        Func<TrendSnapshot, int?> selector,
        bool higherIsBetter)
    {
        if (current is null || previous is null)
        {
            return new TrendMetric(name, current ?? 0, previous, null, TrendDirection.Stable, higherIsBetter);
        }

        var delta = current.Value - previous.Value;
        var direction = DetermineDirection(snapshots, selector, higherIsBetter);

        return new TrendMetric(name, current.Value, previous.Value, delta, direction, higherIsBetter);
    }

    private static TrendDirection DetermineDirection(
        IReadOnlyList<TrendSnapshot> snapshots,
        Func<TrendSnapshot, int?> selector,
        bool higherIsBetter)
    {
        // Look at up to last 10 snapshots for trend
        var start = Math.Max(0, snapshots.Count - 10);
        var consecutiveUp = 0;
        var consecutiveDown = 0;
        var maxConsecutiveUp = 0;
        var maxConsecutiveDown = 0;

        for (var i = start + 1; i < snapshots.Count; i++)
        {
            var prev = selector(snapshots[i - 1]);
            var curr = selector(snapshots[i]);

            if (prev is null || curr is null)
            {
                consecutiveUp = 0;
                consecutiveDown = 0;
                continue;
            }

            if (curr > prev)
            {
                consecutiveUp++;
                consecutiveDown = 0;
            }
            else if (curr < prev)
            {
                consecutiveDown++;
                consecutiveUp = 0;
            }
            else
            {
                consecutiveUp = 0;
                consecutiveDown = 0;
            }

            maxConsecutiveUp = Math.Max(maxConsecutiveUp, consecutiveUp);
            maxConsecutiveDown = Math.Max(maxConsecutiveDown, consecutiveDown);
        }

        // 3+ consecutive moves = trend
        if (maxConsecutiveUp >= 3 && higherIsBetter) return TrendDirection.Improving;
        if (maxConsecutiveUp >= 3 && !higherIsBetter) return TrendDirection.Degrading;
        if (maxConsecutiveDown >= 3 && higherIsBetter) return TrendDirection.Degrading;
        if (maxConsecutiveDown >= 3 && !higherIsBetter) return TrendDirection.Improving;

        return TrendDirection.Stable;
    }
}
