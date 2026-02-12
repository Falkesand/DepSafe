# Security Debt Trend Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add `--snapshot` flag to `cra-report` that persists project-level metrics and displays trend deltas via CLI table and HTML report section.

**Architecture:** JSON file snapshots in `%LocalAppData%/DepSafe/snapshots/{project-hash}/`, analyzed by a static `TrendAnalyzer`, rendered as Spectre.Console table and inline SVG sparklines in the HTML report.

**Tech Stack:** .NET 10, System.Text.Json, Spectre.Console, xUnit

---

### Task 1: Create Models

**Files:**
- Create: `src/DepSafe/Models/TrendSnapshot.cs`
- Create: `src/DepSafe/Models/TrendDirection.cs`
- Create: `src/DepSafe/Models/TrendMetric.cs`
- Create: `src/DepSafe/Models/TrendSummary.cs`

**Step 1: Create TrendSnapshot**

```csharp
// src/DepSafe/Models/TrendSnapshot.cs
namespace DepSafe.Models;

public sealed record TrendSnapshot(
    DateTime CapturedAt,
    string ProjectPath,
    int HealthScore,
    int CraReadinessScore,
    int VulnerabilityCount,
    int CriticalPackageCount,
    int ReportableVulnerabilityCount,
    int? MaxUnpatchedVulnerabilityDays,
    int? SbomCompletenessPercentage,
    int? MaxDependencyDepth,
    bool HasUnmaintainedPackages,
    int PackageCount,
    int TransitivePackageCount);
```

**Step 2: Create TrendDirection**

```csharp
// src/DepSafe/Models/TrendDirection.cs
namespace DepSafe.Models;

public enum TrendDirection { Improving, Stable, Degrading }
```

**Step 3: Create TrendMetric**

```csharp
// src/DepSafe/Models/TrendMetric.cs
namespace DepSafe.Models;

public sealed record TrendMetric(
    string Name,
    int CurrentValue,
    int? PreviousValue,
    int? Delta,
    TrendDirection Direction,
    bool HigherIsBetter);
```

**Step 4: Create TrendSummary**

```csharp
// src/DepSafe/Models/TrendSummary.cs
namespace DepSafe.Models;

public sealed record TrendSummary(
    List<TrendMetric> Metrics,
    int SnapshotCount,
    DateTime? FirstSnapshot,
    DateTime? LastSnapshot,
    TrendDirection OverallDirection);
```

**Step 5: Commit**

```bash
git add src/DepSafe/Models/TrendSnapshot.cs src/DepSafe/Models/TrendDirection.cs src/DepSafe/Models/TrendMetric.cs src/DepSafe/Models/TrendSummary.cs
git commit -m "feat: add TrendSnapshot, TrendDirection, TrendMetric, TrendSummary models"
```

---

### Task 2: Write TrendSnapshotStore Tests

**Files:**
- Create: `tests/DepSafe.Tests/TrendSnapshotStoreTests.cs`

Write 6 tests. Use a temp directory for isolation. Each test creates its own `TrendSnapshotStore` with a unique temp path.

**Step 1: Write the tests**

```csharp
// tests/DepSafe.Tests/TrendSnapshotStoreTests.cs
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
```

**Step 2: Run tests to verify they fail**

Run: `dotnet test --filter "TrendSnapshotStore" -v minimal`
Expected: FAIL — `TrendSnapshotStore` and `TrendSnapshotStore.GetProjectHash` don't exist yet.

**Step 3: Commit**

```bash
git add tests/DepSafe.Tests/TrendSnapshotStoreTests.cs
git commit -m "test: add 6 failing tests for TrendSnapshotStore"
```

---

### Task 3: Implement TrendSnapshotStore

**Files:**
- Create: `src/DepSafe/Persistence/TrendSnapshotStore.cs`

**Step 1: Implement the store**

```csharp
// src/DepSafe/Persistence/TrendSnapshotStore.cs
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using DepSafe.Models;

namespace DepSafe.Persistence;

public sealed class TrendSnapshotStore
{
    private readonly string _basePath;

    public TrendSnapshotStore(string? basePath = null)
    {
        _basePath = basePath ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "DepSafe",
            "snapshots");
    }

    public async Task SaveAsync(TrendSnapshot snapshot, CancellationToken ct = default)
    {
        var projectDir = GetProjectDirectory(snapshot.ProjectPath);
        Directory.CreateDirectory(projectDir);

        var fileName = snapshot.CapturedAt.ToString("yyyy-MM-ddTHHmmssZ") + ".json";
        var filePath = Path.Combine(projectDir, fileName);

        var json = JsonSerializer.Serialize(snapshot, JsonDefaults.CamelCase);
        await File.WriteAllTextAsync(filePath, json, ct);
    }

    public async Task<List<TrendSnapshot>> LoadAsync(string projectPath, int? maxCount = null, CancellationToken ct = default)
    {
        var projectDir = GetProjectDirectory(projectPath);
        if (!Directory.Exists(projectDir))
            return [];

        var files = Directory.GetFiles(projectDir, "*.json");
        Array.Sort(files, StringComparer.Ordinal); // Lexicographic = chronological

        var snapshots = new List<TrendSnapshot>(files.Length);
        foreach (var file in files)
        {
            try
            {
                var json = await File.ReadAllTextAsync(file, ct);
                var snapshot = JsonSerializer.Deserialize<TrendSnapshot>(json, JsonDefaults.CamelCase);
                if (snapshot is not null)
                    snapshots.Add(snapshot);
            }
            catch (JsonException)
            {
                // Skip corrupted files — warn on stderr
                await Console.Error.WriteLineAsync($"Warning: Skipping corrupted snapshot file: {Path.GetFileName(file)}");
            }
        }

        if (maxCount.HasValue && snapshots.Count > maxCount.Value)
        {
            return snapshots.GetRange(snapshots.Count - maxCount.Value, maxCount.Value);
        }

        return snapshots;
    }

    public static string GetProjectHash(string projectPath)
    {
        var normalized = projectPath.Replace('\\', '/').TrimEnd('/').ToLowerInvariant();
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(normalized));
        return Convert.ToHexString(hash)[..12].ToLowerInvariant();
    }

    private string GetProjectDirectory(string projectPath)
    {
        return Path.Combine(_basePath, GetProjectHash(projectPath));
    }
}
```

**Step 2: Run tests**

Run: `dotnet test --filter "TrendSnapshotStore" -v minimal`
Expected: All 6 PASS.

**Step 3: Commit**

```bash
git add src/DepSafe/Persistence/TrendSnapshotStore.cs
git commit -m "feat: implement TrendSnapshotStore with JSON file persistence"
```

---

### Task 4: Write TrendAnalyzer Tests

**Files:**
- Create: `tests/DepSafe.Tests/TrendAnalyzerTests.cs`

Write 10 tests covering delta computation and direction logic.

**Step 1: Write the tests**

```csharp
// tests/DepSafe.Tests/TrendAnalyzerTests.cs
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
```

**Step 2: Run tests to verify they fail**

Run: `dotnet test --filter "TrendAnalyzer" -v minimal`
Expected: FAIL — `TrendAnalyzer` doesn't exist yet.

**Step 3: Commit**

```bash
git add tests/DepSafe.Tests/TrendAnalyzerTests.cs
git commit -m "test: add 10 failing tests for TrendAnalyzer"
```

---

### Task 5: Implement TrendAnalyzer

**Files:**
- Create: `src/DepSafe/Scoring/TrendAnalyzer.cs`

**Step 1: Implement the analyzer**

```csharp
// src/DepSafe/Scoring/TrendAnalyzer.cs
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
```

**Step 2: Run tests**

Run: `dotnet test --filter "TrendAnalyzer" -v minimal`
Expected: All 10 PASS.

**Step 3: Commit**

```bash
git add src/DepSafe/Scoring/TrendAnalyzer.cs
git commit -m "feat: implement TrendAnalyzer with delta computation and direction logic"
```

---

### Task 6: Write Integration Test (TrendSnapshot from CraReport)

**Files:**
- Create: `tests/DepSafe.Tests/TrendSnapshotIntegrationTests.cs`

Write 1 test: build a TrendSnapshot from a CraReport and verify all fields are mapped.

**Step 1: Write the test**

```csharp
// tests/DepSafe.Tests/TrendSnapshotIntegrationTests.cs
using DepSafe.Models;
using DepSafe.Scoring;

namespace DepSafe.Tests;

public class TrendSnapshotIntegrationTests
{
    [Fact]
    public void BuildFromCraReport_AllFieldsMapped()
    {
        var report = new CraReport
        {
            GeneratedAt = new DateTime(2026, 2, 12, 14, 30, 0, DateTimeKind.Utc),
            ProjectPath = "/test/project",
            HealthScore = 78,
            HealthStatus = HealthStatus.Watch,
            ComplianceItems = [],
            OverallComplianceStatus = CraComplianceStatus.Compliant,
            PackageCount = 12,
            TransitivePackageCount = 45,
            VulnerabilityCount = 3,
            CriticalPackageCount = 1,
            CraReadinessScore = 84,
            MaxUnpatchedVulnerabilityDays = 14,
            SbomCompletenessPercentage = 92,
            MaxDependencyDepth = 4,
            HasUnmaintainedPackages = false,
            ReportableVulnerabilityCount = 2
        };

        var snapshot = TrendAnalyzer.BuildSnapshot(report);

        Assert.Equal(report.GeneratedAt, snapshot.CapturedAt);
        Assert.Equal(report.ProjectPath, snapshot.ProjectPath);
        Assert.Equal(78, snapshot.HealthScore);
        Assert.Equal(84, snapshot.CraReadinessScore);
        Assert.Equal(3, snapshot.VulnerabilityCount);
        Assert.Equal(1, snapshot.CriticalPackageCount);
        Assert.Equal(2, snapshot.ReportableVulnerabilityCount);
        Assert.Equal(14, snapshot.MaxUnpatchedVulnerabilityDays);
        Assert.Equal(92, snapshot.SbomCompletenessPercentage);
        Assert.Equal(4, snapshot.MaxDependencyDepth);
        Assert.False(snapshot.HasUnmaintainedPackages);
        Assert.Equal(12, snapshot.PackageCount);
        Assert.Equal(45, snapshot.TransitivePackageCount);
    }
}
```

**Step 2: Add `BuildSnapshot` to TrendAnalyzer**

Add this method to `src/DepSafe/Scoring/TrendAnalyzer.cs`:

```csharp
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
```

**Step 3: Add `using DepSafe.Compliance;` to TrendAnalyzer.cs** for CraReport access.

**Step 4: Run all tests**

Run: `dotnet test -v minimal`
Expected: All pass (486 + 17 new = 503).

**Step 5: Commit**

```bash
git add tests/DepSafe.Tests/TrendSnapshotIntegrationTests.cs src/DepSafe/Scoring/TrendAnalyzer.cs
git commit -m "feat: add BuildSnapshot method and integration test"
```

---

### Task 7: Wire --snapshot Flag into CraReportCommand

**Files:**
- Modify: `src/DepSafe/Commands/CraReportOptions.cs`
- Modify: `src/DepSafe/Commands/CraReportOptionsBinder.cs`
- Modify: `src/DepSafe/Commands/CraReportCommand.cs`

**Step 1: Add Snapshot to CraReportOptions**

In `src/DepSafe/Commands/CraReportOptions.cs`, add `bool Snapshot` as the last parameter:

```csharp
public sealed record CraReportOptions(
    string? Path,
    CraOutputFormat Format,
    string? Output,
    bool SkipGitHub,
    bool Deep,
    LicenseOutputFormat? Licenses,
    SbomFormat? Sbom,
    bool CheckTyposquat,
    bool Sign,
    string? SignKey,
    bool ReleaseGate,
    bool EvidencePack,
    bool AuditMode,
    bool Snapshot);
```

**Step 2: Add to CraReportOptionsBinder**

In `src/DepSafe/Commands/CraReportOptionsBinder.cs`:
- Add field: `private readonly Option<bool> _snapshot;`
- Add constructor parameter: `Option<bool> snapshot`
- Add assignment: `_snapshot = snapshot;`
- Add to GetBoundValue: `bindingContext.ParseResult.GetValueForOption(_snapshot)`

**Step 3: Add --snapshot option to CraReportCommand.Create()**

In `src/DepSafe/Commands/CraReportCommand.cs`, in `Create()`:
- Add option definition after `auditModeOption` (around line 72):
  ```csharp
  var snapshotOption = new Option<bool>(
      ["--snapshot"],
      "Save snapshot for trend tracking and display historical trend analysis");
  ```
- Add to command children (after `auditModeOption` in the command initializer)
- Add to binder constructor call

**Step 4: Thread `snapshot` through ExecuteAsync**

In `ExecuteAsync()` (around line 169), add: `var snapshot = options.Snapshot;`

Thread `snapshot` into the calls to `GenerateReportAsync` and `GenerateMixedReportAsync` — add `bool snapshot = false` parameter to both methods, after `auditMode`.

**Step 5: Add snapshot logic to both GenerateReportAsync and GenerateMixedReportAsync**

After the report file is written and before the "Display summary" section, insert the snapshot capture block. Same block in both methods:

```csharp
// Snapshot & trend analysis
TrendSummary? trendSummary = null;
if (snapshot)
{
    var store = new TrendSnapshotStore();
    var currentSnapshot = TrendAnalyzer.BuildSnapshot(craReport);
    var history = await store.LoadAsync(path, maxCount: 10, ct);
    await store.SaveAsync(currentSnapshot, ct);
    history.Add(currentSnapshot);
    trendSummary = TrendAnalyzer.Analyze(history);
    reportGenerator.SetTrendData(trendSummary);

    // Re-generate report with trend data included
    if (format == CraOutputFormat.Html)
    {
        output = reportGenerator.GenerateHtml(craReport, licenseFilePath);
        await File.WriteAllTextAsync(outputPath, output, ct);
    }
}
```

Add required usings at top of file: `using DepSafe.Persistence;`

**Step 6: Build and run all tests**

Run: `dotnet build --no-restore -v minimal && dotnet test --no-restore -v minimal`
Expected: 0 errors, 0 warnings, all tests pass.

Note: `SetTrendData` doesn't exist yet on `CraReportGenerator` — it will be added in Task 9. For now, the build will warn/fail if you try to compile. If so, comment out or stub the `SetTrendData` call temporarily, or implement Task 9 first. The recommended approach is to add a stub `SetTrendData` method to CraReportGenerator in this task:

```csharp
// In CraReportGenerator.cs, after SetMaintainerTrustData
private TrendSummary? _trendSummary;

public void SetTrendData(TrendSummary summary)
{
    _trendSummary = summary;
}
```

**Step 7: Commit**

```bash
git add src/DepSafe/Commands/CraReportOptions.cs src/DepSafe/Commands/CraReportOptionsBinder.cs src/DepSafe/Commands/CraReportCommand.cs src/DepSafe/Compliance/CraReportGenerator.cs
git commit -m "feat: wire --snapshot flag through CraReportCommand pipeline"
```

---

### Task 8: Add CLI Trend Table Output

**Files:**
- Modify: `src/DepSafe/Commands/CraReportCommand.cs`

Add the Spectre.Console trend table display after the existing summary output, before `EvaluateExitCode`. This goes in both `GenerateReportAsync` and `GenerateMixedReportAsync`.

**Step 1: Add DisplayTrendSummary method**

Add a private static method to `CraReportCommand`:

```csharp
private static void DisplayTrendSummary(TrendSummary? trendSummary)
{
    if (trendSummary is null || trendSummary.Metrics.Count == 0)
        return;

    AnsiConsole.WriteLine();
    var since = trendSummary.FirstSnapshot?.ToString("yyyy-MM-dd") ?? "unknown";
    AnsiConsole.Write(new Rule($"[bold]Security Debt Trend ({trendSummary.SnapshotCount} snapshots, since {since})[/]").LeftJustified());

    var table = new Table()
        .Border(TableBorder.Rounded)
        .AddColumn("Metric")
        .AddColumn(new TableColumn("Current").RightAligned())
        .AddColumn(new TableColumn("Previous").RightAligned())
        .AddColumn(new TableColumn("Delta").RightAligned())
        .AddColumn("Trend");

    foreach (var metric in trendSummary.Metrics)
    {
        var currentStr = metric.Name.Contains('%') || metric.Name == "SBOM Completeness"
            ? $"{metric.CurrentValue}%"
            : metric.CurrentValue.ToString();
        var previousStr = metric.PreviousValue.HasValue
            ? (metric.Name == "SBOM Completeness" ? $"{metric.PreviousValue}%" : metric.PreviousValue.Value.ToString())
            : "\u2014";
        var deltaStr = metric.Delta.HasValue
            ? (metric.Delta.Value > 0 ? $"+{metric.Delta.Value}" : metric.Delta.Value.ToString())
            : "\u2014";

        var (icon, color) = metric.Direction switch
        {
            TrendDirection.Improving => ("\u25b2", "green"),
            TrendDirection.Degrading => ("\u25bc", "red"),
            _ => ("\u25cf", "blue")
        };

        var trendStr = $"[{color}]{icon} {metric.Direction}[/]";

        table.AddRow(metric.Name, currentStr, previousStr, deltaStr, trendStr);
    }

    AnsiConsole.Write(table);

    var (overallIcon, overallColor) = trendSummary.OverallDirection switch
    {
        TrendDirection.Improving => ("\u25b2", "green"),
        TrendDirection.Degrading => ("\u25bc", "red"),
        _ => ("\u25cf", "blue")
    };

    AnsiConsole.MarkupLine($"\n[bold]Overall:[/] [{overallColor}]{overallIcon} {trendSummary.OverallDirection}[/]");
}
```

**Step 2: Call DisplayTrendSummary in both report methods**

In both `GenerateReportAsync` and `GenerateMixedReportAsync`, after `DisplaySecurityBudgetSummary(roadmap)` and before `AnsiConsole.MarkupLine($"\n[green]Report written to {outputPath}[/]")`, add:

```csharp
DisplayTrendSummary(trendSummary);
```

**Step 3: Build and run all tests**

Run: `dotnet build --no-restore -v minimal && dotnet test --no-restore -v minimal`
Expected: 0 errors, 0 warnings, all tests pass.

**Step 4: Commit**

```bash
git add src/DepSafe/Commands/CraReportCommand.cs
git commit -m "feat: add CLI trend table output with Spectre.Console"
```

---

### Task 9: Add HTML Trend Section to Report

**Files:**
- Modify: `src/DepSafe/Compliance/CraReportGenerator.cs` (nav item + section call + SetTrendData field)
- Modify: `src/DepSafe/Compliance/CraReportGenerator.Sections.cs` (GenerateTrendSection)
- Modify: `src/DepSafe/Resources/report-styles.css` (trend CSS)

**Step 1: Add nav item in CraReportGenerator.cs**

In the nav section (around line 884, after the maintenance nav item), add a conditional trend nav item:

```csharp
if (_trendSummary is not null && _trendSummary.Metrics.Count > 0)
{
    sb.AppendLine("        <li><a href=\"#\" onclick=\"showSection('security-debt-trend')\" data-section=\"security-debt-trend\">");
    sb.AppendLine("          <svg class=\"nav-icon\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\"><polyline points=\"22 12 18 12 15 21 9 3 6 12 2 12\"/></svg>");
    var (trendIcon, trendColor) = _trendSummary.OverallDirection switch
    {
        TrendDirection.Improving => ("\u25b2", "var(--success)"),
        TrendDirection.Degrading => ("\u25bc", "var(--danger)"),
        _ => ("\u25cf", "var(--accent)")
    };
    sb.AppendLine($"          Security Debt Trend<span class=\"nav-badge\" style=\"background:{trendColor}\">{trendIcon}</span></a></li>");
}
```

**Step 2: Add section call**

After the maintenance section block (around line 1020+), add:

```csharp
if (_trendSummary is not null && _trendSummary.Metrics.Count > 0)
{
    sb.AppendLine("<section id=\"security-debt-trend\" class=\"section\">");
    GenerateTrendSection(sb);
    sb.AppendLine("</section>");
}
```

**Step 3: Implement GenerateTrendSection in CraReportGenerator.Sections.cs**

Add at the end of the file:

```csharp
private void GenerateTrendSection(StringBuilder sb)
{
    if (_trendSummary is null) return;

    sb.AppendLine("<div class=\"section-header\">");
    sb.AppendLine("  <h2>Security Debt Trend</h2>");
    sb.AppendLine("</div>");

    // Summary card
    var (dirIcon, dirClass) = _trendSummary.OverallDirection switch
    {
        TrendDirection.Improving => ("\u25b2", "trend-improving"),
        TrendDirection.Degrading => ("\u25bc", "trend-degrading"),
        _ => ("\u25cf", "trend-stable")
    };
    var since = _trendSummary.FirstSnapshot?.ToString("MMM d, yyyy") ?? "unknown";

    sb.AppendLine($"<div class=\"trend-card {dirClass}\">");
    sb.AppendLine($"  <span class=\"trend-direction-icon\">{dirIcon}</span>");
    sb.AppendLine($"  <span>Security posture is <strong>{_trendSummary.OverallDirection.ToString().ToLowerInvariant()}</strong> over {_trendSummary.SnapshotCount} snapshots since {EscapeHtml(since)}.</span>");
    sb.AppendLine("</div>");

    // Sparkline chart rows
    sb.AppendLine("<div class=\"trend-metrics\">");
    foreach (var metric in _trendSummary.Metrics)
    {
        var sparklineData = GetSparklineData(metric.Name);
        var (metricIcon, metricClass) = metric.Direction switch
        {
            TrendDirection.Improving => ("\u25b2", "trend-improving"),
            TrendDirection.Degrading => ("\u25bc", "trend-degrading"),
            _ => ("\u25cf", "trend-stable")
        };
        var deltaStr = metric.Delta.HasValue
            ? (metric.Delta.Value > 0 ? $"+{metric.Delta.Value}" : metric.Delta.Value.ToString())
            : "\u2014";
        var suffix = metric.Name == "SBOM Completeness" ? "%" : "";

        sb.AppendLine($"  <div class=\"trend-metric-row\">");
        sb.AppendLine($"    <div class=\"trend-metric-name\">{EscapeHtml(metric.Name)}</div>");
        sb.AppendLine($"    <div class=\"trend-sparkline\">{GenerateSparklineSvg(sparklineData)}</div>");
        sb.AppendLine($"    <div class=\"trend-metric-value\">{metric.CurrentValue}{suffix}</div>");
        sb.AppendLine($"    <div class=\"trend-delta {metricClass}\">{metricIcon} {deltaStr}</div>");
        sb.AppendLine($"  </div>");
    }
    sb.AppendLine("</div>");

    // History table (collapsible)
    if (_trendSnapshots is not null && _trendSnapshots.Count > 1)
    {
        sb.AppendLine("<details class=\"trend-history\">");
        sb.AppendLine("<summary>Snapshot History</summary>");
        sb.AppendLine("<table class=\"detail-table\">");
        sb.AppendLine("  <thead><tr>");
        sb.AppendLine("    <th>Date</th><th>Health</th><th>CRA</th><th>Vulns</th><th>Critical</th><th>Reportable</th><th>SBOM %</th><th>Unpatched Days</th>");
        sb.AppendLine("  </tr></thead>");
        sb.AppendLine("  <tbody>");

        // Most recent first
        for (var i = _trendSnapshots.Count - 1; i >= 0 && i >= _trendSnapshots.Count - 10; i--)
        {
            var s = _trendSnapshots[i];
            sb.AppendLine("    <tr>");
            sb.AppendLine($"      <td>{s.CapturedAt:yyyy-MM-dd HH:mm}</td>");
            sb.AppendLine($"      <td>{s.HealthScore}</td>");
            sb.AppendLine($"      <td>{s.CraReadinessScore}</td>");
            sb.AppendLine($"      <td>{s.VulnerabilityCount}</td>");
            sb.AppendLine($"      <td>{s.CriticalPackageCount}</td>");
            sb.AppendLine($"      <td>{s.ReportableVulnerabilityCount}</td>");
            sb.AppendLine($"      <td>{s.SbomCompletenessPercentage?.ToString() ?? "\u2014"}</td>");
            sb.AppendLine($"      <td>{s.MaxUnpatchedVulnerabilityDays?.ToString() ?? "\u2014"}</td>");
            sb.AppendLine("    </tr>");
        }

        sb.AppendLine("  </tbody>");
        sb.AppendLine("</table>");
        sb.AppendLine("</details>");
    }
}

private List<int> GetSparklineData(string metricName)
{
    if (_trendSnapshots is null || _trendSnapshots.Count == 0)
        return [];

    var start = Math.Max(0, _trendSnapshots.Count - 10);
    var data = new List<int>();
    for (var i = start; i < _trendSnapshots.Count; i++)
    {
        var s = _trendSnapshots[i];
        var value = metricName switch
        {
            "Health Score" => s.HealthScore,
            "CRA Readiness Score" => s.CraReadinessScore,
            "Vulnerability Count" => s.VulnerabilityCount,
            "Critical Packages" => s.CriticalPackageCount,
            "Reportable Vulnerabilities" => s.ReportableVulnerabilityCount,
            "SBOM Completeness" => s.SbomCompletenessPercentage ?? 0,
            "Max Unpatched Days" => s.MaxUnpatchedVulnerabilityDays ?? 0,
            _ => 0
        };
        data.Add(value);
    }
    return data;
}

private static string GenerateSparklineSvg(List<int> data)
{
    if (data.Count < 2)
        return "<svg width=\"80\" height=\"24\"></svg>";

    var min = data.Min();
    var max = data.Max();
    var range = max - min;
    if (range == 0) range = 1; // avoid division by zero

    var width = 80;
    var height = 24;
    var padding = 2;
    var usableWidth = width - 2 * padding;
    var usableHeight = height - 2 * padding;

    var points = new List<string>();
    for (var i = 0; i < data.Count; i++)
    {
        var x = padding + (int)((double)i / (data.Count - 1) * usableWidth);
        var y = padding + usableHeight - (int)((double)(data[i] - min) / range * usableHeight);
        points.Add($"{x},{y}");
    }

    return $"<svg width=\"{width}\" height=\"{height}\" viewBox=\"0 0 {width} {height}\"><polyline points=\"{string.Join(" ", points)}\" fill=\"none\" stroke=\"var(--accent)\" stroke-width=\"1.5\" stroke-linecap=\"round\" stroke-linejoin=\"round\"/></svg>";
}
```

**Step 4: Update SetTrendData to also store snapshots**

In `CraReportGenerator.cs`, update `SetTrendData`:

```csharp
private TrendSummary? _trendSummary;
private List<TrendSnapshot>? _trendSnapshots;

public void SetTrendData(TrendSummary summary, List<TrendSnapshot>? snapshots = null)
{
    _trendSummary = summary;
    _trendSnapshots = snapshots;
}
```

Update the caller in `CraReportCommand.cs` to pass the snapshot list:
```csharp
reportGenerator.SetTrendData(trendSummary, history);
```

**Step 5: Add CSS**

Append to `src/DepSafe/Resources/report-styles.css`:

```css
/* Security Debt Trend */
.trend-card {
    padding: 16px 20px;
    border-radius: 8px;
    margin-bottom: 20px;
    display: flex;
    align-items: center;
    gap: 12px;
    font-size: 1.05em;
}
.trend-card.trend-improving { background: rgba(46, 204, 113, 0.12); border-left: 4px solid var(--success); }
.trend-card.trend-degrading { background: rgba(231, 76, 60, 0.12); border-left: 4px solid var(--danger); }
.trend-card.trend-stable { background: rgba(52, 152, 219, 0.12); border-left: 4px solid var(--accent); }
.trend-direction-icon { font-size: 1.5em; }
.trend-metrics { display: flex; flex-direction: column; gap: 8px; margin-bottom: 20px; }
.trend-metric-row { display: flex; align-items: center; gap: 16px; padding: 8px 12px; background: var(--card-bg); border-radius: 6px; }
.trend-metric-name { flex: 1; font-weight: 500; }
.trend-sparkline { flex: 0 0 80px; }
.trend-metric-value { flex: 0 0 60px; text-align: right; font-weight: 600; }
.trend-delta { flex: 0 0 100px; text-align: right; font-size: 0.9em; }
.trend-delta.trend-improving { color: var(--success); }
.trend-delta.trend-degrading { color: var(--danger); }
.trend-delta.trend-stable { color: var(--accent); }
.trend-history { margin-top: 16px; }
.trend-history summary { cursor: pointer; font-weight: 600; padding: 8px 0; }
```

**Step 6: Build and run all tests**

Run: `dotnet build --no-restore -v minimal && dotnet test --no-restore -v minimal`
Expected: 0 errors, 0 warnings, all tests pass.

**Step 7: Commit**

```bash
git add src/DepSafe/Compliance/CraReportGenerator.cs src/DepSafe/Compliance/CraReportGenerator.Sections.cs src/DepSafe/Resources/report-styles.css src/DepSafe/Commands/CraReportCommand.cs
git commit -m "feat: add Security Debt Trend HTML section with SVG sparklines"
```

---

### Task 10: Empty State Handling

**Files:**
- Modify: `src/DepSafe/Compliance/CraReportGenerator.Sections.cs`
- Modify: `src/DepSafe/Commands/CraReportCommand.cs`

**Step 1: Add empty-state card for first snapshot**

In the snapshot capture block in both `GenerateReportAsync` and `GenerateMixedReportAsync`, after `trendSummary = TrendAnalyzer.Analyze(history)`:

```csharp
if (trendSummary.Metrics.Count == 0)
{
    AnsiConsole.MarkupLine("[dim]First snapshot recorded. Run again with --snapshot to see trends.[/]");
}
```

**Step 2: Build and run all tests**

Run: `dotnet build --no-restore -v minimal && dotnet test --no-restore -v minimal`
Expected: 0 errors, all tests pass.

**Step 3: Commit**

```bash
git add src/DepSafe/Commands/CraReportCommand.cs
git commit -m "feat: add empty-state message for first snapshot"
```

---

### Task 11: Final Verification and Code Review

**Step 1: Full build**

Run: `dotnet build --no-restore -v minimal`
Expected: 0 warnings, 0 errors.

**Step 2: Full test suite**

Run: `dotnet test --no-restore -v minimal`
Expected: All tests pass (486 existing + 17 new = 503 total).

**Step 3: Code review**

Dispatch two code reviewer subagents (Opus + Sonnet) per CLAUDE.md rules.

**Step 4: Fix any review findings and commit.**
