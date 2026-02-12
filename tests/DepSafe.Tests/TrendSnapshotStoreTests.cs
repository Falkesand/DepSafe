using DepSafe.Models;
using DepSafe.Persistence;

namespace DepSafe.Tests;

public class TrendSnapshotStoreTests : IDisposable
{
    private readonly string _tempDir;
    private readonly TrendSnapshotStore _store;

    public TrendSnapshotStoreTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), "depsafe-test-" + Guid.NewGuid().ToString("N")[..8]);
        _store = new TrendSnapshotStore(_tempDir);
    }

    public void Dispose()
    {
        if (Directory.Exists(_tempDir))
            Directory.Delete(_tempDir, true);
    }

    [Fact]
    public async Task SaveAndLoad_RoundTrip()
    {
        var snapshot = CreateSnapshot(healthScore: 75, craReadinessScore: 80);

        await _store.SaveAsync(snapshot);
        var loaded = await _store.LoadAsync(snapshot.ProjectPath);

        var result = Assert.Single(loaded);
        Assert.Equal(75, result.HealthScore);
        Assert.Equal(80, result.CraReadinessScore);
        Assert.Equal(snapshot.ProjectPath, result.ProjectPath);
    }

    [Fact]
    public async Task Load_NoDirectory_ReturnsEmptyList()
    {
        var loaded = await _store.LoadAsync("/nonexistent/project");

        Assert.Empty(loaded);
    }

    [Fact]
    public async Task MultipleSaves_LoadedInChronologicalOrder()
    {
        var project = "/test/project";
        var s1 = CreateSnapshot(healthScore: 60, capturedAt: DateTime.UtcNow.AddDays(-2), projectPath: project);
        var s2 = CreateSnapshot(healthScore: 70, capturedAt: DateTime.UtcNow.AddDays(-1), projectPath: project);
        var s3 = CreateSnapshot(healthScore: 80, capturedAt: DateTime.UtcNow, projectPath: project);

        await _store.SaveAsync(s1);
        await _store.SaveAsync(s2);
        await _store.SaveAsync(s3);

        var loaded = await _store.LoadAsync(project);

        Assert.Equal(3, loaded.Count);
        Assert.Equal(60, loaded[0].HealthScore);
        Assert.Equal(70, loaded[1].HealthScore);
        Assert.Equal(80, loaded[2].HealthScore);
    }

    [Fact]
    public async Task MaxCount_ReturnsOnlyMostRecent()
    {
        var project = "/test/project";
        for (int i = 0; i < 5; i++)
        {
            await _store.SaveAsync(CreateSnapshot(
                healthScore: 50 + i * 10,
                capturedAt: DateTime.UtcNow.AddDays(-4 + i),
                projectPath: project));
        }

        var loaded = await _store.LoadAsync(project, maxCount: 2);

        Assert.Equal(2, loaded.Count);
        Assert.Equal(80, loaded[0].HealthScore); // 4th (index 3)
        Assert.Equal(90, loaded[1].HealthScore); // 5th (index 4)
    }

    [Fact]
    public async Task DifferentProjects_IsolatedSnapshots()
    {
        var s1 = CreateSnapshot(healthScore: 60, projectPath: "/project/alpha");
        var s2 = CreateSnapshot(healthScore: 90, projectPath: "/project/beta");

        await _store.SaveAsync(s1);
        await _store.SaveAsync(s2);

        var alpha = await _store.LoadAsync("/project/alpha");
        var beta = await _store.LoadAsync("/project/beta");

        Assert.Single(alpha);
        Assert.Equal(60, alpha[0].HealthScore);
        Assert.Single(beta);
        Assert.Equal(90, beta[0].HealthScore);
    }

    [Fact]
    public async Task CorruptedFile_SkippedGracefully()
    {
        var project = "/test/project";
        await _store.SaveAsync(CreateSnapshot(healthScore: 70, projectPath: project));

        // Write a corrupted file into the snapshot directory
        var projectHash = TrendSnapshotStore.GetProjectHash(project);
        var projectDir = Path.Combine(_tempDir, projectHash);
        await File.WriteAllTextAsync(Path.Combine(projectDir, "2026-01-01T000000Z.json"), "NOT VALID JSON{{{");

        var loaded = await _store.LoadAsync(project);

        // Should load the valid snapshot and skip the corrupted one
        Assert.Single(loaded);
        Assert.Equal(70, loaded[0].HealthScore);
    }

    private static TrendSnapshot CreateSnapshot(
        int healthScore = 75,
        int craReadinessScore = 80,
        int vulnerabilityCount = 3,
        int criticalPackageCount = 0,
        int reportableVulnerabilityCount = 1,
        int? maxUnpatchedDays = 14,
        int? sbomCompleteness = 92,
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
            VulnerabilityCount: vulnerabilityCount,
            CriticalPackageCount: criticalPackageCount,
            ReportableVulnerabilityCount: reportableVulnerabilityCount,
            MaxUnpatchedVulnerabilityDays: maxUnpatchedDays,
            SbomCompletenessPercentage: sbomCompleteness,
            MaxDependencyDepth: maxDepth,
            HasUnmaintainedPackages: hasUnmaintained,
            PackageCount: packageCount,
            TransitivePackageCount: transitiveCount);
    }
}
