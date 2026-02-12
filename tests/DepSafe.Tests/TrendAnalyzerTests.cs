using DepSafe.Models;
using DepSafe.Scoring;

namespace DepSafe.Tests;

public class TrendAnalyzerTests
{
    [Fact]
    public void EmptySnapshots_ReturnsEmptyMetrics()
    {
        var result = TrendAnalyzer.Analyze([]);

        Assert.Empty(result.Metrics);
        Assert.Null(result.FirstSnapshot);
        Assert.Null(result.LastSnapshot);
        Assert.Equal(0, result.SnapshotCount);
    }

    [Fact]
    public void SingleSnapshot_ReturnsEmptyMetrics()
    {
        var snapshots = new[] { CreateSnapshot(healthScore: 75) };

        var result = TrendAnalyzer.Analyze(snapshots);

        Assert.Empty(result.Metrics);
        Assert.Equal(1, result.SnapshotCount);
    }

    [Fact]
    public void TwoSnapshots_CorrectDeltaCalculation()
    {
        var snapshots = new[]
        {
            CreateSnapshot(healthScore: 70, craReadinessScore: 80, vulnCount: 5, capturedAt: DateTime.UtcNow.AddDays(-1)),
            CreateSnapshot(healthScore: 78, craReadinessScore: 84, vulnCount: 3, capturedAt: DateTime.UtcNow)
        };

        var result = TrendAnalyzer.Analyze(snapshots);

        Assert.Equal(7, result.Metrics.Count);

        var health = result.Metrics.First(m => m.Name == "Health Score");
        Assert.Equal(78, health.CurrentValue);
        Assert.Equal(70, health.PreviousValue);
        Assert.Equal(8, health.Delta);

        var vulns = result.Metrics.First(m => m.Name == "Vulnerability Count");
        Assert.Equal(3, vulns.CurrentValue);
        Assert.Equal(5, vulns.PreviousValue);
        Assert.Equal(-2, vulns.Delta);
    }

    [Fact]
    public void HigherIsBetter_Increasing_IsImproving()
    {
        var snapshots = new[]
        {
            CreateSnapshot(healthScore: 60, capturedAt: DateTime.UtcNow.AddDays(-3)),
            CreateSnapshot(healthScore: 65, capturedAt: DateTime.UtcNow.AddDays(-2)),
            CreateSnapshot(healthScore: 70, capturedAt: DateTime.UtcNow.AddDays(-1)),
            CreateSnapshot(healthScore: 78, capturedAt: DateTime.UtcNow)
        };

        var result = TrendAnalyzer.Analyze(snapshots);
        var health = result.Metrics.First(m => m.Name == "Health Score");

        Assert.Equal(TrendDirection.Improving, health.Direction);
    }

    [Fact]
    public void LowerIsBetter_Decreasing_IsImproving()
    {
        var snapshots = new[]
        {
            CreateSnapshot(vulnCount: 10, capturedAt: DateTime.UtcNow.AddDays(-3)),
            CreateSnapshot(vulnCount: 7, capturedAt: DateTime.UtcNow.AddDays(-2)),
            CreateSnapshot(vulnCount: 5, capturedAt: DateTime.UtcNow.AddDays(-1)),
            CreateSnapshot(vulnCount: 3, capturedAt: DateTime.UtcNow)
        };

        var result = TrendAnalyzer.Analyze(snapshots);
        var vulns = result.Metrics.First(m => m.Name == "Vulnerability Count");

        Assert.Equal(TrendDirection.Improving, vulns.Direction);
    }

    [Fact]
    public void StableValues_DirectionStable()
    {
        var snapshots = new[]
        {
            CreateSnapshot(healthScore: 75, capturedAt: DateTime.UtcNow.AddDays(-3)),
            CreateSnapshot(healthScore: 75, capturedAt: DateTime.UtcNow.AddDays(-2)),
            CreateSnapshot(healthScore: 75, capturedAt: DateTime.UtcNow.AddDays(-1)),
            CreateSnapshot(healthScore: 75, capturedAt: DateTime.UtcNow)
        };

        var result = TrendAnalyzer.Analyze(snapshots);
        var health = result.Metrics.First(m => m.Name == "Health Score");

        Assert.Equal(TrendDirection.Stable, health.Direction);
    }

    [Fact]
    public void ThreeConsecutiveDegrades_DirectionDegrading()
    {
        var snapshots = new[]
        {
            CreateSnapshot(healthScore: 85, capturedAt: DateTime.UtcNow.AddDays(-3)),
            CreateSnapshot(healthScore: 78, capturedAt: DateTime.UtcNow.AddDays(-2)),
            CreateSnapshot(healthScore: 70, capturedAt: DateTime.UtcNow.AddDays(-1)),
            CreateSnapshot(healthScore: 62, capturedAt: DateTime.UtcNow)
        };

        var result = TrendAnalyzer.Analyze(snapshots);
        var health = result.Metrics.First(m => m.Name == "Health Score");

        Assert.Equal(TrendDirection.Degrading, health.Direction);
    }

    [Fact]
    public void MixedDirections_DirectionStable()
    {
        var snapshots = new[]
        {
            CreateSnapshot(healthScore: 70, capturedAt: DateTime.UtcNow.AddDays(-3)),
            CreateSnapshot(healthScore: 80, capturedAt: DateTime.UtcNow.AddDays(-2)),
            CreateSnapshot(healthScore: 72, capturedAt: DateTime.UtcNow.AddDays(-1)),
            CreateSnapshot(healthScore: 78, capturedAt: DateTime.UtcNow)
        };

        var result = TrendAnalyzer.Analyze(snapshots);
        var health = result.Metrics.First(m => m.Name == "Health Score");

        Assert.Equal(TrendDirection.Stable, health.Direction);
    }

    [Fact]
    public void OverallDirection_MajorityOfMetrics()
    {
        // All metrics improving
        var snapshots = new[]
        {
            CreateSnapshot(healthScore: 60, craReadinessScore: 60, vulnCount: 10, criticalCount: 3,
                reportableCount: 5, sbomCompleteness: 70, maxUnpatchedDays: 30,
                capturedAt: DateTime.UtcNow.AddDays(-3)),
            CreateSnapshot(healthScore: 65, craReadinessScore: 65, vulnCount: 8, criticalCount: 2,
                reportableCount: 4, sbomCompleteness: 75, maxUnpatchedDays: 25,
                capturedAt: DateTime.UtcNow.AddDays(-2)),
            CreateSnapshot(healthScore: 70, craReadinessScore: 70, vulnCount: 6, criticalCount: 1,
                reportableCount: 3, sbomCompleteness: 80, maxUnpatchedDays: 20,
                capturedAt: DateTime.UtcNow.AddDays(-1)),
            CreateSnapshot(healthScore: 78, craReadinessScore: 78, vulnCount: 3, criticalCount: 0,
                reportableCount: 1, sbomCompleteness: 92, maxUnpatchedDays: 14,
                capturedAt: DateTime.UtcNow)
        };

        var result = TrendAnalyzer.Analyze(snapshots);

        Assert.Equal(TrendDirection.Improving, result.OverallDirection);
    }

    [Fact]
    public void NullPreviousValues_DeltaNull_DirectionStable()
    {
        var snapshots = new[]
        {
            CreateSnapshot(maxUnpatchedDays: null, capturedAt: DateTime.UtcNow.AddDays(-1)),
            CreateSnapshot(maxUnpatchedDays: 14, capturedAt: DateTime.UtcNow)
        };

        var result = TrendAnalyzer.Analyze(snapshots);
        var unpatched = result.Metrics.First(m => m.Name == "Max Unpatched Days");

        Assert.Null(unpatched.PreviousValue);
        Assert.Null(unpatched.Delta);
        Assert.Equal(TrendDirection.Stable, unpatched.Direction);
    }

    private static TrendSnapshot CreateSnapshot(
        int healthScore = 75,
        int craReadinessScore = 80,
        int vulnCount = 3,
        int criticalCount = 0,
        int reportableCount = 1,
        int? sbomCompleteness = 92,
        int? maxUnpatchedDays = 14,
        int? maxDepth = 4,
        bool hasUnmaintained = false,
        int packageCount = 12,
        int transitiveCount = 45,
        DateTime? capturedAt = null,
        string projectPath = "/test/project")
    {
        return new TrendSnapshot(
            CapturedAt: capturedAt ?? DateTime.UtcNow,
            ProjectPath: projectPath,
            HealthScore: healthScore,
            CraReadinessScore: craReadinessScore,
            VulnerabilityCount: vulnCount,
            CriticalPackageCount: criticalCount,
            ReportableVulnerabilityCount: reportableCount,
            MaxUnpatchedVulnerabilityDays: maxUnpatchedDays,
            SbomCompletenessPercentage: sbomCompleteness,
            MaxDependencyDepth: maxDepth,
            HasUnmaintainedPackages: hasUnmaintained,
            PackageCount: packageCount,
            TransitivePackageCount: transitiveCount);
    }
}
