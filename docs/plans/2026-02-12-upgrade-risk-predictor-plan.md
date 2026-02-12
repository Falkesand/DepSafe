# Phase 2.5 Upgrade Risk Predictor — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Enrich remediation roadmap UpgradeTier rows with a composite risk assessment (0-100) based on changelog analysis, semver signal, maintainer trust, and time gap.

**Architecture:** New static analyzers (`ChangelogAnalyzer`, `UpgradeRiskCalculator`) compute risk per tier. `GitHubApiClient` gains a new GraphQL method to fetch release note bodies. Risk assessments attach to `RemediationRoadmapItem` as a dictionary keyed by target version. HTML rendering adds a risk badge column to the roadmap table.

**Tech Stack:** .NET 10, xUnit, NuGet.Versioning, GitHub GraphQL API, Result\<T\> pattern

---

### Task 1: Create Data Models

**Files:**
- Create: `src/DepSafe/Models/ReleaseNote.cs`
- Create: `src/DepSafe/Models/ChangelogSignals.cs`
- Create: `src/DepSafe/Models/UpgradeRiskAssessment.cs`
- Create: `src/DepSafe/Models/UpgradeRiskLevel.cs`

**Step 1: Create ReleaseNote record**

Create `src/DepSafe/Models/ReleaseNote.cs`:
```csharp
namespace DepSafe.Models;

public sealed record ReleaseNote(
    string TagName,
    string? Body,
    DateTime PublishedAt);
```

**Step 2: Create ChangelogSignals record**

Create `src/DepSafe/Models/ChangelogSignals.cs`:
```csharp
namespace DepSafe.Models;

public sealed record ChangelogSignals(
    int BreakingChangeCount,
    int DeprecationCount,
    List<string> BreakingSnippets,
    List<string> DeprecationSnippets,
    int ReleaseCount);
```

**Step 3: Create UpgradeRiskLevel enum**

Create `src/DepSafe/Models/UpgradeRiskLevel.cs`:
```csharp
namespace DepSafe.Models;

public enum UpgradeRiskLevel { Low, Medium, High, Critical }
```

**Step 4: Create UpgradeRiskAssessment record**

Create `src/DepSafe/Models/UpgradeRiskAssessment.cs`:
```csharp
namespace DepSafe.Models;

public sealed record UpgradeRiskAssessment(
    int RiskScore,
    UpgradeRiskLevel RiskLevel,
    int BreakingChangeSignals,
    int DeprecationSignals,
    List<string> RiskFactors,
    int ReleasesBetween,
    TimeSpan TimeBetween);
```

**Step 5: Build to verify models compile**

Run: `dotnet build src/DepSafe/DepSafe.csproj`
Expected: Build succeeded. 0 Warning(s). 0 Error(s).

**Step 6: Commit**

```bash
git add src/DepSafe/Models/ReleaseNote.cs src/DepSafe/Models/ChangelogSignals.cs src/DepSafe/Models/UpgradeRiskLevel.cs src/DepSafe/Models/UpgradeRiskAssessment.cs
git commit -m "feat: add data models for upgrade risk assessment"
```

---

### Task 2: Extend RemediationRoadmapItem with TierRiskAssessments

**Files:**
- Modify: `src/DepSafe/Scoring/RemediationRoadmapItem.cs`

**Step 1: Add TierRiskAssessments property**

Add after the `ActionText` property (line 37):
```csharp
/// <summary>Per-tier risk assessments keyed by target version. Null when no GitHub repo available.</summary>
public Dictionary<string, UpgradeRiskAssessment>? TierRiskAssessments { get; init; }
```

Also add the using directive at the top:
```csharp
using DepSafe.Models;
```

**Step 2: Build to verify**

Run: `dotnet build src/DepSafe/DepSafe.csproj`
Expected: Build succeeded.

**Step 3: Run all tests to verify no regressions**

Run: `dotnet test tests/DepSafe.Tests/DepSafe.Tests.csproj`
Expected: All tests pass.

**Step 4: Commit**

```bash
git add src/DepSafe/Scoring/RemediationRoadmapItem.cs
git commit -m "feat: add TierRiskAssessments property to RemediationRoadmapItem"
```

---

### Task 3: Write Failing Tests for ChangelogAnalyzer

**Files:**
- Create: `tests/DepSafe.Tests/ChangelogAnalyzerTests.cs`

**Step 1: Write 5 failing tests**

Create `tests/DepSafe.Tests/ChangelogAnalyzerTests.cs`:
```csharp
using DepSafe.Models;
using DepSafe.Scoring;

namespace DepSafe.Tests;

public class ChangelogAnalyzerTests
{
    private static ReleaseNote MakeRelease(string tag, string? body, string date = "2024-06-15")
        => new(tag, body, DateTime.Parse(date));

    [Fact]
    public void Analyze_BreakingKeywords_CountsCorrectly()
    {
        var releases = new List<ReleaseNote>
        {
            MakeRelease("v2.0.0", "This release has BREAKING changes. Removed old API."),
            MakeRelease("v2.1.0", "Renamed configuration option."),
        };

        var result = ChangelogAnalyzer.Analyze(releases, "1.0.0", "3.0.0");

        Assert.Equal(3, result.BreakingChangeCount); // breaking, removed, renamed
        Assert.Equal(3, result.BreakingSnippets.Count);
    }

    [Fact]
    public void Analyze_NoSignals_ReturnsZeroCounts()
    {
        var releases = new List<ReleaseNote>
        {
            MakeRelease("v1.1.0", "Bug fixes and performance improvements."),
        };

        var result = ChangelogAnalyzer.Analyze(releases, "1.0.0", "2.0.0");

        Assert.Equal(0, result.BreakingChangeCount);
        Assert.Equal(0, result.DeprecationCount);
        Assert.Empty(result.BreakingSnippets);
        Assert.Empty(result.DeprecationSnippets);
    }

    [Fact]
    public void Analyze_FiltersReleasesOutsideVersionRange()
    {
        var releases = new List<ReleaseNote>
        {
            MakeRelease("v0.9.0", "BREAKING: total rewrite"),
            MakeRelease("v1.5.0", "Deprecated old endpoint."),
            MakeRelease("v3.0.0", "BREAKING: new architecture"),
        };

        // Only v1.5.0 is between 1.0.0 and 2.0.0
        var result = ChangelogAnalyzer.Analyze(releases, "1.0.0", "2.0.0");

        Assert.Equal(0, result.BreakingChangeCount);
        Assert.Equal(1, result.DeprecationCount);
        Assert.Equal(1, result.ReleaseCount);
    }

    [Fact]
    public void Analyze_CaseInsensitiveMatching()
    {
        var releases = new List<ReleaseNote>
        {
            MakeRelease("v1.1.0", "BREAKING change. Deprecated method. OBSOLETE class."),
        };

        var result = ChangelogAnalyzer.Analyze(releases, "1.0.0", "2.0.0");

        Assert.Equal(1, result.BreakingChangeCount);
        Assert.Equal(2, result.DeprecationCount); // deprecated + obsolete
    }

    [Fact]
    public void Analyze_EmptyReleaseBody_Skipped()
    {
        var releases = new List<ReleaseNote>
        {
            MakeRelease("v1.1.0", null),
            MakeRelease("v1.2.0", ""),
            MakeRelease("v1.3.0", "   "),
        };

        var result = ChangelogAnalyzer.Analyze(releases, "1.0.0", "2.0.0");

        Assert.Equal(0, result.BreakingChangeCount);
        Assert.Equal(0, result.DeprecationCount);
        Assert.Equal(3, result.ReleaseCount); // all 3 are in range, even with empty body
    }
}
```

**Step 2: Verify tests fail (ChangelogAnalyzer class doesn't exist)**

Run: `dotnet test tests/DepSafe.Tests/DepSafe.Tests.csproj --filter "FullyQualifiedName~ChangelogAnalyzerTests"`
Expected: Build error — `ChangelogAnalyzer` does not exist.

---

### Task 4: Implement ChangelogAnalyzer

**Files:**
- Create: `src/DepSafe/Scoring/ChangelogAnalyzer.cs`

**Step 1: Implement ChangelogAnalyzer**

Create `src/DepSafe/Scoring/ChangelogAnalyzer.cs`:
```csharp
using System.Text.RegularExpressions;
using DepSafe.Models;
using NuGet.Versioning;

namespace DepSafe.Scoring;

/// <summary>
/// Analyzes GitHub release note bodies for breaking change and deprecation signals.
/// </summary>
public static class ChangelogAnalyzer
{
    private static readonly string[] s_breakingPatterns =
        ["breaking", "removed", "renamed", "incompatible", "migration required", "no longer supports"];

    private static readonly string[] s_deprecationPatterns =
        ["deprecated", "obsolete", "will be removed", "end of life"];

    private const int MaxSnippetLength = 50;

    /// <summary>
    /// Analyze release notes between two versions for breaking/deprecation signals.
    /// </summary>
    public static ChangelogSignals Analyze(
        IReadOnlyList<ReleaseNote> releases,
        string fromVersion,
        string toVersion)
    {
        var breakingCount = 0;
        var deprecationCount = 0;
        var breakingSnippets = new List<string>();
        var deprecationSnippets = new List<string>();
        var releaseCount = 0;

        if (!NuGetVersion.TryParse(fromVersion, out var from) ||
            !NuGetVersion.TryParse(toVersion, out var to))
        {
            return new ChangelogSignals(0, 0, [], [], 0);
        }

        foreach (var release in releases)
        {
            // Parse tag name, stripping optional 'v' prefix
            var tag = release.TagName.StartsWith('v') || release.TagName.StartsWith('V')
                ? release.TagName[1..]
                : release.TagName;

            if (!NuGetVersion.TryParse(tag, out var version))
                continue;

            // Filter to versions between from (exclusive) and to (inclusive)
            if (version <= from || version > to)
                continue;

            releaseCount++;

            if (string.IsNullOrWhiteSpace(release.Body))
                continue;

            var body = release.Body;

            foreach (var pattern in s_breakingPatterns)
            {
                if (body.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                {
                    breakingCount++;
                    breakingSnippets.Add(ExtractSnippet(body, pattern));
                }
            }

            foreach (var pattern in s_deprecationPatterns)
            {
                if (body.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                {
                    deprecationCount++;
                    deprecationSnippets.Add(ExtractSnippet(body, pattern));
                }
            }
        }

        return new ChangelogSignals(
            breakingCount,
            deprecationCount,
            breakingSnippets,
            deprecationSnippets,
            releaseCount);
    }

    private static string ExtractSnippet(string body, string keyword)
    {
        var idx = body.IndexOf(keyword, StringComparison.OrdinalIgnoreCase);
        if (idx < 0) return "";

        // Take context around the keyword
        var start = Math.Max(0, idx - 10);
        var end = Math.Min(body.Length, idx + keyword.Length + 30);
        var snippet = body[start..end].ReplaceLineEndings(" ").Trim();

        return snippet.Length > MaxSnippetLength
            ? string.Concat(snippet.AsSpan(0, MaxSnippetLength), "...")
            : snippet;
    }
}
```

**Step 2: Run tests to verify they pass**

Run: `dotnet test tests/DepSafe.Tests/DepSafe.Tests.csproj --filter "FullyQualifiedName~ChangelogAnalyzerTests"`
Expected: 5 passed, 0 failed.

**Step 3: Commit**

```bash
git add src/DepSafe/Scoring/ChangelogAnalyzer.cs tests/DepSafe.Tests/ChangelogAnalyzerTests.cs
git commit -m "feat: add ChangelogAnalyzer with keyword-based signal detection"
```

---

### Task 5: Write Failing Tests for UpgradeRiskCalculator

**Files:**
- Create: `tests/DepSafe.Tests/UpgradeRiskCalculatorTests.cs`

**Step 1: Write 5 failing tests**

Create `tests/DepSafe.Tests/UpgradeRiskCalculatorTests.cs`:
```csharp
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
            trust: new MaintainerTrust(60, MaintainerTrustTier.Medium, 5, 200, 10, 2, "dev"),
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
        var trust = new MaintainerTrust(70, MaintainerTrustTier.Medium, 5, 200, 10, 2, "dev");

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
            trust: new MaintainerTrust(50, MaintainerTrustTier.Medium, 5, 200, 10, 2, "dev"),
            releasesBetween: 0,
            timeBetween: TimeSpan.Zero);

        // Major=50*0.4=20, no changelog=0, trust=(100-50)*0.15=7.5, no time=0 => ~28
        Assert.True(result.RiskScore > 0);
        Assert.NotEmpty(result.RiskFactors);
    }
}
```

**Step 2: Verify tests fail (UpgradeRiskCalculator doesn't exist)**

Run: `dotnet test tests/DepSafe.Tests/DepSafe.Tests.csproj --filter "FullyQualifiedName~UpgradeRiskCalculatorTests"`
Expected: Build error — `UpgradeRiskCalculator` does not exist.

---

### Task 6: Implement UpgradeRiskCalculator

**Files:**
- Create: `src/DepSafe/Scoring/UpgradeRiskCalculator.cs`

**Step 1: Implement UpgradeRiskCalculator**

Create `src/DepSafe/Scoring/UpgradeRiskCalculator.cs`:
```csharp
using DepSafe.Models;

namespace DepSafe.Scoring;

/// <summary>
/// Computes a composite upgrade risk score (0-100) from semver tier, changelog signals,
/// maintainer trust, and time gap between versions.
/// </summary>
public static class UpgradeRiskCalculator
{
    // Weight factors (must sum to 1.0)
    private const double SemverWeight = 0.40;
    private const double ChangelogWeight = 0.35;
    private const double StabilityWeight = 0.15;
    private const double TimeGapWeight = 0.10;

    // Max time gap for scaling (2 years in days)
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
```

**Step 2: Run tests to verify they pass**

Run: `dotnet test tests/DepSafe.Tests/DepSafe.Tests.csproj --filter "FullyQualifiedName~UpgradeRiskCalculatorTests"`
Expected: 5 passed, 0 failed.

**Step 3: Commit**

```bash
git add src/DepSafe/Scoring/UpgradeRiskCalculator.cs tests/DepSafe.Tests/UpgradeRiskCalculatorTests.cs
git commit -m "feat: add UpgradeRiskCalculator with composite risk scoring"
```

---

### Task 7: Add GetReleaseNotesAsync to GitHubApiClient

**Files:**
- Modify: `src/DepSafe/DataSources/GitHubApiClient.cs`

**Context:** The existing `FetchRepositoriesBatchGraphQLAsync` method (line 142) uses StringBuilder to construct GraphQL queries. It already fetches releases with `tagName`, `createdAt`, `author { login }` but NOT `description` (release body). The new method fetches release notes for a single repo with body text included.

**Step 1: Add the GetReleaseNotesAsync method**

Add after the existing `GetRepositoryInfoAsync` method (after line ~475). The method should:
- Return `Result<List<ReleaseNote>>`
- Use the existing Octokit `_client` for simplicity (the batch GraphQL path is for multi-repo; this is single-repo)
- Cache with key format `github-releases:{owner}/{repo}` using existing `_cache`
- Fetch up to `count` releases (default 50)

```csharp
/// <summary>
/// Fetch release notes (with body text) for a repository.
/// </summary>
public async Task<Result<List<ReleaseNote>>> GetReleaseNotesAsync(
    string owner, string repo, int count = 50, CancellationToken ct = default)
{
    if (string.IsNullOrWhiteSpace(owner) || string.IsNullOrWhiteSpace(repo))
        return Result.Fail<List<ReleaseNote>>("Owner/repo is empty", ErrorKind.InvalidInput);

    if (_isRateLimited)
        return Result.Fail<List<ReleaseNote>>("GitHub API rate limited", ErrorKind.RateLimited);

    var cacheKey = $"github-releases:{owner}/{repo}";
    if (_cache.TryGet<List<ReleaseNote>>(cacheKey, out var cached))
        return cached;

    try
    {
        var releases = await _client.Repository.Release.GetAll(owner, repo,
            new Octokit.ApiOptions { PageSize = count, PageCount = 1 });

        var notes = new List<ReleaseNote>(releases.Count);
        foreach (var r in releases)
        {
            notes.Add(new ReleaseNote(
                r.TagName,
                r.Body,
                r.PublishedAt?.UtcDateTime ?? r.CreatedAt.UtcDateTime));
        }

        _cache.Set(cacheKey, notes);
        return notes;
    }
    catch (Octokit.RateLimitExceededException)
    {
        _isRateLimited = true;
        return Result.Fail<List<ReleaseNote>>("GitHub API rate limited", ErrorKind.RateLimited);
    }
    catch (Octokit.NotFoundException)
    {
        return Result.Fail<List<ReleaseNote>>($"Repository {owner}/{repo} not found", ErrorKind.NotFound);
    }
    catch (HttpRequestException ex)
    {
        return Result.Fail<List<ReleaseNote>>(ex.Message, ErrorKind.NetworkError);
    }
    catch (Exception ex) when (ex is not OperationCanceledException)
    {
        return Result.Fail<List<ReleaseNote>>(ex.Message, ErrorKind.Unknown);
    }
}
```

Also add the using directive at the top if not present:
```csharp
using DepSafe.Models;
```

**Step 2: Build to verify**

Run: `dotnet build src/DepSafe/DepSafe.csproj`
Expected: Build succeeded.

**Step 3: Run all tests**

Run: `dotnet test tests/DepSafe.Tests/DepSafe.Tests.csproj`
Expected: All existing tests pass.

**Step 4: Commit**

```bash
git add src/DepSafe/DataSources/GitHubApiClient.cs
git commit -m "feat: add GetReleaseNotesAsync to fetch release bodies for changelog analysis"
```

---

### Task 8: Wire Risk Assessment into CraReportCommand

**Files:**
- Modify: `src/DepSafe/Commands/CraReportCommand.cs`

**Context:** There are two wiring points:
1. `GenerateMixedReportAsync` (~line 2156-2170): after `PrioritizeUpdates()` and `PrioritizeMaintenanceItems()`, before `SetRemediationRoadmap()`
2. `GenerateReportAsync` (~line 3067-3081): same pattern

Both need identical risk assessment logic inserted. The `githubClient` is already available in both methods, as is `repoInfoMap` (maps package ID to GitHubRepoInfo) and `maintainerTrust` (maps package ID to MaintainerTrust).

**Step 1: Create a private static helper method**

Add a helper method to `CraReportCommand` that enriches roadmap items with risk assessments:

```csharp
private static async Task EnrichWithRiskAssessmentsAsync(
    List<RemediationRoadmapItem> roadmap,
    GitHubApiClient githubClient,
    IReadOnlyDictionary<string, GitHubRepoInfo?>? repoInfoMap,
    IReadOnlyDictionary<string, MaintainerTrust>? trustMap,
    CancellationToken ct)
{
    if (repoInfoMap is null) return;

    foreach (var item in roadmap)
    {
        if (item.UpgradeTiers.Count == 0) continue;
        if (!repoInfoMap.TryGetValue(item.PackageId, out var repoInfo) || repoInfo is null)
            continue;

        // Fetch release notes for this package's repo
        var releaseResult = await githubClient.GetReleaseNotesAsync(
            repoInfo.Owner, repoInfo.Name, ct: ct);
        var releaseNotes = releaseResult.ValueOr([]);

        if (releaseNotes.Count == 0) continue;

        var tierAssessments = new Dictionary<string, UpgradeRiskAssessment>();
        var trust = trustMap?.GetValueOrDefault(item.PackageId);

        foreach (var tier in item.UpgradeTiers)
        {
            var signals = ChangelogAnalyzer.Analyze(releaseNotes, item.CurrentVersion, tier.TargetVersion);

            // Count releases between versions
            int releasesBetween = signals.ReleaseCount;

            // Compute time gap from release dates
            var timeBetween = ComputeTimeGap(releaseNotes, item.CurrentVersion, tier.TargetVersion);

            var assessment = UpgradeRiskCalculator.Assess(
                tier.Effort, signals, trust, releasesBetween, timeBetween);

            tierAssessments[tier.TargetVersion] = assessment;
        }

        // RemediationRoadmapItem uses init-only props, so we need to replace the item
        // Since we're using a List, find index and replace
        var idx = roadmap.IndexOf(item);
        if (idx >= 0)
        {
            roadmap[idx] = new RemediationRoadmapItem
            {
                PackageId = item.PackageId,
                CurrentVersion = item.CurrentVersion,
                RecommendedVersion = item.RecommendedVersion,
                CveCount = item.CveCount,
                CveIds = item.CveIds,
                ScoreLift = item.ScoreLift,
                Effort = item.Effort,
                HasKevVulnerability = item.HasKevVulnerability,
                MaxEpssProbability = item.MaxEpssProbability,
                MaxPatchAgeDays = item.MaxPatchAgeDays,
                PriorityScore = item.PriorityScore,
                UpgradeTiers = item.UpgradeTiers,
                Reason = item.Reason,
                DependencyType = item.DependencyType,
                ParentChain = item.ParentChain,
                ActionText = item.ActionText,
                TierRiskAssessments = tierAssessments,
            };
        }
    }
}

private static TimeSpan ComputeTimeGap(
    List<ReleaseNote> releases, string fromVersion, string toVersion)
{
    if (!NuGetVersion.TryParse(fromVersion, out var from) ||
        !NuGetVersion.TryParse(toVersion, out var to))
        return TimeSpan.Zero;

    DateTime? fromDate = null;
    DateTime? toDate = null;

    foreach (var release in releases)
    {
        var tag = release.TagName.StartsWith('v') || release.TagName.StartsWith('V')
            ? release.TagName[1..]
            : release.TagName;

        if (!NuGetVersion.TryParse(tag, out var ver)) continue;

        if (ver == from) fromDate = release.PublishedAt;
        if (ver == to) toDate = release.PublishedAt;
    }

    if (fromDate.HasValue && toDate.HasValue)
        return toDate.Value - fromDate.Value;

    return TimeSpan.Zero;
}
```

Note: The method requires these usings at the top of the file (add if not already present):
```csharp
using DepSafe.Scoring;
using NuGet.Versioning;
```

**Step 2: Wire into GenerateMixedReportAsync**

Find the block after `roadmap.AddRange(maintenanceItems);` and before `reportGenerator.SetRemediationRoadmap(roadmap);` in `GenerateMixedReportAsync` (~line 2168). Insert:

```csharp
await EnrichWithRiskAssessmentsAsync(roadmap, githubClient, repoInfoMap, maintainerTrust, ct);
```

Where `maintainerTrust` is the existing dictionary variable in that method. Grep the method for the exact variable name holding the Dictionary<string, MaintainerTrust>.

**Step 3: Wire into GenerateReportAsync**

Same pattern — find the same block in `GenerateReportAsync` (~line 3079). Insert the same call.

**Step 4: Build to verify**

Run: `dotnet build src/DepSafe/DepSafe.csproj`
Expected: Build succeeded.

**Step 5: Run all tests**

Run: `dotnet test tests/DepSafe.Tests/DepSafe.Tests.csproj`
Expected: All tests pass.

**Step 6: Commit**

```bash
git add src/DepSafe/Commands/CraReportCommand.cs
git commit -m "feat: wire upgrade risk assessment into CRA report generation"
```

---

### Task 9: Add Risk Badge to HTML Rendering

**Files:**
- Modify: `src/DepSafe/Compliance/CraReportGenerator.Sections.cs`
- Modify: `src/DepSafe/Resources/report-styles.css`

**Context:** The `GenerateRemediationRoadmapSection` method (line 1031-1143 in CraReportGenerator.Sections.cs) renders a table with columns: #, Package, Upgrade Options, CVEs Fixed, Score Lift, Effort. We add a "Risk" column after Effort.

**Step 1: Add CSS styles for risk badges**

In `src/DepSafe/Resources/report-styles.css`, add at the end (or near other badge styles):

```css
/* Risk assessment badges */
.risk-badge {
    display: inline-block;
    padding: 2px 8px;
    border-radius: 12px;
    font-size: 0.75rem;
    font-weight: 600;
    white-space: nowrap;
}
.risk-badge.low { background: var(--success); color: #fff; }
.risk-badge.medium { background: var(--warning); color: #1a1a2e; }
.risk-badge.high { background: #e67e22; color: #fff; }
.risk-badge.critical { background: var(--danger); color: #fff; }
.risk-score { font-size: 0.7rem; color: var(--text-secondary); margin-left: 4px; }
.risk-factors { font-size: 0.75rem; color: var(--text-secondary); margin-top: 2px; }
```

**Step 2: Add Risk column header**

In `GenerateRemediationRoadmapSection`, add after the Effort `<th>` line (~line 1061):
```csharp
sb.AppendLine("    <th>Risk</th>");
```

**Step 3: Add risk badge cell to primary row**

After the effort `<td>` in the primary row (~line 1109), add a Risk `<td>`:

```csharp
// Risk assessment badge
string riskCell;
if (item.TierRiskAssessments is not null &&
    item.UpgradeTiers.Count > 0 &&
    item.TierRiskAssessments.TryGetValue(item.UpgradeTiers[0].TargetVersion, out var primaryRisk))
{
    var riskClass = primaryRisk.RiskLevel.ToString().ToLowerInvariant();
    riskCell = $"<span class=\"risk-badge {riskClass}\">{primaryRisk.RiskLevel}</span>"
             + $"<span class=\"risk-score\">{primaryRisk.RiskScore}/100</span>";
}
else
{
    riskCell = "\u2014"; // em-dash when no assessment available
}
sb.AppendLine($"      <td>{riskCell}</td>");
```

**Step 4: Add risk badge cell to alternative tier rows**

In the alt tier row loop (~line 1130-1137), add after the effort `<td>`:

```csharp
// Risk for alt tier
string altRiskCell;
if (item.TierRiskAssessments is not null &&
    item.TierRiskAssessments.TryGetValue(tier.TargetVersion, out var altRisk))
{
    var altRiskClass = altRisk.RiskLevel.ToString().ToLowerInvariant();
    altRiskCell = $"<span class=\"risk-badge {altRiskClass}\">{altRisk.RiskLevel}</span>"
                + $"<span class=\"risk-score\">{altRisk.RiskScore}/100</span>";
}
else
{
    altRiskCell = "\u2014";
}
sb.AppendLine($"      <td>{altRiskCell}</td>");
```

**Step 5: Build to verify**

Run: `dotnet build src/DepSafe/DepSafe.csproj`
Expected: Build succeeded.

**Step 6: Run all tests**

Run: `dotnet test tests/DepSafe.Tests/DepSafe.Tests.csproj`
Expected: All tests pass.

**Step 7: Commit**

```bash
git add src/DepSafe/Compliance/CraReportGenerator.Sections.cs src/DepSafe/Resources/report-styles.css
git commit -m "feat: add risk badge column to remediation roadmap HTML table"
```

---

### Task 10: Write Integration Tests

**Files:**
- Modify: `tests/DepSafe.Tests/CraReportGeneratorTests.cs`

**Step 1: Add test for risk badge rendering**

Add to the existing `CraReportGeneratorTests` class:

```csharp
[Fact]
public void GenerateHtml_RoadmapWithRiskAssessment_RendersRiskBadge()
{
    var generator = CreateGenerator();
    var roadmap = new List<RemediationRoadmapItem>
    {
        new()
        {
            PackageId = "RiskyPkg",
            CurrentVersion = "1.0.0",
            RecommendedVersion = "2.0.0",
            Effort = UpgradeEffort.Major,
            PriorityScore = 500,
            CveCount = 2,
            CveIds = ["CVE-2024-0001", "CVE-2024-0002"],
            ScoreLift = 5,
            UpgradeTiers =
            [
                new UpgradeTier("2.0.0", UpgradeEffort.Major, 2, 2, true),
            ],
            TierRiskAssessments = new Dictionary<string, UpgradeRiskAssessment>
            {
                ["2.0.0"] = new(65, UpgradeRiskLevel.High, 3, 1, ["Major version bump", "3 breaking changes"], 8, TimeSpan.FromDays(400))
            },
        }
    };
    generator.SetRemediationRoadmap(roadmap);

    var html = generator.Generate(CreateHealthReport(), new Dictionary<string, List<VulnerabilityInfo>>(), null, null, DateTime.UtcNow).HtmlContent;

    Assert.Contains("risk-badge high", html);
    Assert.Contains("65/100", html);
    Assert.Contains("High", html);
}
```

**Step 2: Add test for null risk assessment (em-dash rendered)**

```csharp
[Fact]
public void GenerateHtml_RoadmapWithoutRiskAssessment_RendersEmDash()
{
    var generator = CreateGenerator();
    var roadmap = new List<RemediationRoadmapItem>
    {
        new()
        {
            PackageId = "NormalPkg",
            CurrentVersion = "1.0.0",
            RecommendedVersion = "1.0.1",
            Effort = UpgradeEffort.Patch,
            PriorityScore = 100,
            CveCount = 1,
            CveIds = ["CVE-2024-0001"],
            ScoreLift = 2,
            UpgradeTiers = [new UpgradeTier("1.0.1", UpgradeEffort.Patch, 1, 1, true)],
            // TierRiskAssessments is null (no GitHub repo)
        }
    };
    generator.SetRemediationRoadmap(roadmap);

    var html = generator.Generate(CreateHealthReport(), new Dictionary<string, List<VulnerabilityInfo>>(), null, null, DateTime.UtcNow).HtmlContent;

    // Should have the Risk column header
    Assert.Contains("<th>Risk</th>", html);
}
```

**Step 3: Run tests to verify they pass**

Run: `dotnet test tests/DepSafe.Tests/DepSafe.Tests.csproj`
Expected: All tests pass.

**Step 4: Commit**

```bash
git add tests/DepSafe.Tests/CraReportGeneratorTests.cs
git commit -m "test: add integration tests for risk badge HTML rendering"
```

---

### Task 11: Final Build Verification & All Tests

**Step 1: Full build**

Run: `dotnet build src/DepSafe/DepSafe.csproj --no-incremental`
Expected: Build succeeded. 0 Warning(s). 0 Error(s).

**Step 2: Run all tests**

Run: `dotnet test tests/DepSafe.Tests/DepSafe.Tests.csproj`
Expected: All tests pass (existing + 12 new).

**Step 3: Verify test count**

New tests added:
- ChangelogAnalyzerTests: 5
- UpgradeRiskCalculatorTests: 5
- CraReportGeneratorTests: 2 (integration)
Total new: 12

**Step 4: No commit needed — this is verification only.**
