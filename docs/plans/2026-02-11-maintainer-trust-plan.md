# Maintainer Trust Score Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add a separate Maintainer Trust Score (0-100) per package, computed from GitHub data already in the batch query (extended with contributor/release fields), shown in the package table, feeding into a new CRA compliance item and audit simulation check.

**Architecture:** Extend the existing GraphQL batch query with 4 new fields (zero extra API calls). New `MaintainerTrustCalculator` static class in Scoring/ computes a 5-factor weighted score. Score stored on `PackageHealth.MaintainerTrust`, rendered as a new table column + summary section, and evaluated as CRA compliance item "Art. 13(5) — Maintainer Trust" (weight 8).

**Tech Stack:** .NET 10, xUnit, System.Text.Json, Octokit, GitHub GraphQL API

---

### Task 1: Create models — ReleaseInfo, MaintainerTrustTier, MaintainerTrust

**Files:**
- Create: `src/DepSafe/Models/ReleaseInfo.cs`
- Create: `src/DepSafe/Models/MaintainerTrustTier.cs`
- Create: `src/DepSafe/Models/MaintainerTrust.cs`
- Modify: `src/DepSafe/Models/GitHubRepoInfo.cs`
- Modify: `src/DepSafe/Models/PackageHealth.cs`

**Step 1: Create ReleaseInfo record**

```csharp
// src/DepSafe/Models/ReleaseInfo.cs
namespace DepSafe.Models;

public sealed record ReleaseInfo(string TagName, DateTime CreatedAt, string? AuthorLogin);
```

**Step 2: Create MaintainerTrustTier enum**

```csharp
// src/DepSafe/Models/MaintainerTrustTier.cs
namespace DepSafe.Models;

public enum MaintainerTrustTier { Critical, Low, Moderate, High }
```

**Step 3: Create MaintainerTrust record**

```csharp
// src/DepSafe/Models/MaintainerTrust.cs
namespace DepSafe.Models;

public sealed record MaintainerTrust(
    int Score,
    MaintainerTrustTier Tier,
    int ContributorCount,
    int TotalCommits,
    int TotalReleases,
    int ReleaseAuthorCount,
    string? TopReleaseAuthor);
```

**Step 4: Add new properties to GitHubRepoInfo**

File: `src/DepSafe/Models/GitHubRepoInfo.cs`

After line 19 (`public int CommitsLastYear { get; init; }`), add:

```csharp
    /// <summary>Number of users with access to the repository (mentionableUsers — proxy for contributor count).</summary>
    public int ContributorCount { get; init; }

    /// <summary>Total number of commits on the default branch.</summary>
    public int TotalCommits { get; init; }

    /// <summary>Total number of releases.</summary>
    public int TotalReleases { get; init; }

    /// <summary>Last 5 releases with date and author login.</summary>
    public List<ReleaseInfo> RecentReleases { get; init; } = [];
```

**Step 5: Add MaintainerTrust property to PackageHealth**

File: `src/DepSafe/Models/PackageHealth.cs`

After line 68 (`public PackageEcosystem Ecosystem ...`), add:

```csharp
    /// <summary>Maintainer trust assessment (null when no GitHub data available).</summary>
    public MaintainerTrust? MaintainerTrust { get; init; }
```

**Step 6: Build and verify**

Run: `dotnet build --nologo -v quiet`
Expected: 0 errors, 0 warnings

**Step 7: Commit**

```
git add src/DepSafe/Models/ReleaseInfo.cs src/DepSafe/Models/MaintainerTrustTier.cs src/DepSafe/Models/MaintainerTrust.cs src/DepSafe/Models/GitHubRepoInfo.cs src/DepSafe/Models/PackageHealth.cs
git commit -m "feat: add MaintainerTrust, MaintainerTrustTier, ReleaseInfo models"
```

---

### Task 2: Write failing tests for MaintainerTrustCalculator

**Files:**
- Create: `tests/DepSafe.Tests/MaintainerTrustCalculatorTests.cs`

**Step 1: Write all test cases**

Create `tests/DepSafe.Tests/MaintainerTrustCalculatorTests.cs` with these tests:

```csharp
using DepSafe.Models;
using DepSafe.Scoring;

namespace DepSafe.Tests;

public class MaintainerTrustCalculatorTests
{
    private static GitHubRepoInfo CreateRepoInfo(
        int contributorCount = 10,
        int totalCommits = 500,
        int totalReleases = 20,
        int stars = 1000,
        int forks = 100,
        int openIssues = 10,
        bool isArchived = false,
        bool hasSecurityPolicy = true,
        string? license = "MIT",
        int daysSinceLastCommit = 5,
        List<ReleaseInfo>? recentReleases = null)
    {
        return new GitHubRepoInfo
        {
            Owner = "test",
            Name = "repo",
            FullName = "test/repo",
            Stars = stars,
            Forks = forks,
            OpenIssues = openIssues,
            LastCommitDate = DateTime.UtcNow.AddDays(-daysSinceLastCommit),
            LastPushDate = DateTime.UtcNow.AddDays(-daysSinceLastCommit),
            IsArchived = isArchived,
            License = license,
            ContributorCount = contributorCount,
            TotalCommits = totalCommits,
            TotalReleases = totalReleases,
            RecentReleases = recentReleases ?? CreateDiverseReleases(),
            HasSecurityPolicy = hasSecurityPolicy,
        };
    }

    private static List<ReleaseInfo> CreateDiverseReleases() =>
    [
        new("v1.5.0", DateTime.UtcNow.AddDays(-10), "alice"),
        new("v1.4.0", DateTime.UtcNow.AddDays(-40), "bob"),
        new("v1.3.0", DateTime.UtcNow.AddDays(-80), "alice"),
        new("v1.2.0", DateTime.UtcNow.AddDays(-120), "charlie"),
        new("v1.1.0", DateTime.UtcNow.AddDays(-200), "bob"),
    ];

    private static List<ReleaseInfo> CreateSingleAuthorReleases() =>
    [
        new("v1.5.0", DateTime.UtcNow.AddDays(-10), "solo-dev"),
        new("v1.4.0", DateTime.UtcNow.AddDays(-40), "solo-dev"),
        new("v1.3.0", DateTime.UtcNow.AddDays(-80), "solo-dev"),
        new("v1.2.0", DateTime.UtcNow.AddDays(-120), "solo-dev"),
        new("v1.1.0", DateTime.UtcNow.AddDays(-200), "solo-dev"),
    ];

    private static PackageMetrics CreateMetrics(
        double releasesPerYear = 4.0,
        int? daysSinceLastRelease = 30,
        int? daysSinceLastCommit = 5,
        int? stars = 1000,
        int? openIssues = 10) =>
        new()
        {
            ReleasesPerYear = releasesPerYear,
            DaysSinceLastRelease = daysSinceLastRelease,
            DaysSinceLastCommit = daysSinceLastCommit,
            Stars = stars,
            OpenIssues = openIssues,
            TotalDownloads = 100_000,
            DownloadTrend = 0.1,
        };

    [Fact]
    public void SingleContributor_LowBusFactorScore()
    {
        var repo = CreateRepoInfo(contributorCount: 1);
        var result = MaintainerTrustCalculator.Calculate(repo, CreateMetrics());

        Assert.NotNull(result);
        Assert.True(result.Score < 70, $"Single contributor should penalize score, got {result.Score}");
        Assert.Equal(1, result.ContributorCount);
    }

    [Fact]
    public void FivePlusContributors_HighBusFactorScore()
    {
        var repo = CreateRepoInfo(contributorCount: 10);
        var result = MaintainerTrustCalculator.Calculate(repo, CreateMetrics());

        Assert.NotNull(result);
        Assert.True(result.Score >= 80, $"10 contributors should yield high trust, got {result.Score}");
    }

    [Fact]
    public void ArchivedRepo_ZeroActivityContinuity()
    {
        var repo = CreateRepoInfo(isArchived: true);
        var result = MaintainerTrustCalculator.Calculate(repo, CreateMetrics());

        Assert.NotNull(result);
        Assert.True(result.Score < 80, $"Archived repo should penalize trust, got {result.Score}");
    }

    [Fact]
    public void RecentCommit_FullActivityScore()
    {
        var repo = CreateRepoInfo(daysSinceLastCommit: 5);
        var result = MaintainerTrustCalculator.Calculate(repo, CreateMetrics(daysSinceLastCommit: 5));

        Assert.NotNull(result);
        Assert.True(result.Score >= 80, $"Recent commit should yield high trust, got {result.Score}");
    }

    [Fact]
    public void StaleCommit_LowActivityScore()
    {
        var repo = CreateRepoInfo(daysSinceLastCommit: 400, stars: 50, contributorCount: 3);
        var metrics = CreateMetrics(daysSinceLastCommit: 400, releasesPerYear: 0.5, daysSinceLastRelease: 400, stars: 50);
        var result = MaintainerTrustCalculator.Calculate(repo, metrics);

        Assert.NotNull(result);
        Assert.True(result.Score < 60, $"400-day stale commit should yield low trust, got {result.Score}");
    }

    [Fact]
    public void SingleReleaseAuthor_ReleaseDisciplinePenalty()
    {
        var repo = CreateRepoInfo(contributorCount: 5, recentReleases: CreateSingleAuthorReleases());
        var result = MaintainerTrustCalculator.Calculate(repo, CreateMetrics());

        Assert.NotNull(result);
        Assert.Equal(1, result.ReleaseAuthorCount);
        Assert.Equal("solo-dev", result.TopReleaseAuthor);
    }

    [Fact]
    public void MultipleReleaseAuthors_NoPenalty()
    {
        var repo = CreateRepoInfo(recentReleases: CreateDiverseReleases());
        var result = MaintainerTrustCalculator.Calculate(repo, CreateMetrics());

        Assert.NotNull(result);
        Assert.Equal(3, result.ReleaseAuthorCount); // alice, bob, charlie
    }

    [Fact]
    public void HighStars_GoodCommunityHealth()
    {
        var repo = CreateRepoInfo(stars: 15000, openIssues: 50);
        var result = MaintainerTrustCalculator.Calculate(repo, CreateMetrics(stars: 15000, openIssues: 50));

        Assert.NotNull(result);
        Assert.True(result.Score >= 80, $"Popular repo should have high trust, got {result.Score}");
    }

    [Fact]
    public void NoSecurityPolicy_SecurityPosturePenalty()
    {
        var repo = CreateRepoInfo(hasSecurityPolicy: false, license: null);
        var result = MaintainerTrustCalculator.Calculate(repo, CreateMetrics());

        Assert.NotNull(result);
        // Compare against a repo WITH security policy and license
        var repoWithPolicy = CreateRepoInfo(hasSecurityPolicy: true, license: "MIT");
        var resultWithPolicy = MaintainerTrustCalculator.Calculate(repoWithPolicy, CreateMetrics());
        Assert.True(result.Score < resultWithPolicy!.Score,
            $"No security policy/license should score lower ({result.Score}) than with ({resultWithPolicy.Score})");
    }

    [Fact]
    public void FullCleanInputs_HighTrustScore()
    {
        var repo = CreateRepoInfo();
        var result = MaintainerTrustCalculator.Calculate(repo, CreateMetrics());

        Assert.NotNull(result);
        Assert.True(result.Score >= 80, $"Clean inputs should yield high trust (>= 80), got {result.Score}");
        Assert.Equal(MaintainerTrustTier.High, result.Tier);
    }

    [Theory]
    [InlineData(39, MaintainerTrustTier.Critical)]
    [InlineData(40, MaintainerTrustTier.Low)]
    [InlineData(59, MaintainerTrustTier.Low)]
    [InlineData(60, MaintainerTrustTier.Moderate)]
    [InlineData(79, MaintainerTrustTier.Moderate)]
    [InlineData(80, MaintainerTrustTier.High)]
    [InlineData(100, MaintainerTrustTier.High)]
    public void TierBoundaries_CorrectMapping(int score, MaintainerTrustTier expectedTier)
    {
        var tier = MaintainerTrustCalculator.GetTier(score);
        Assert.Equal(expectedTier, tier);
    }

    [Fact]
    public void NullRepoInfo_ReturnsNull()
    {
        var result = MaintainerTrustCalculator.Calculate(null, CreateMetrics());
        Assert.Null(result);
    }
}
```

**Step 2: Verify tests fail to compile**

Run: `dotnet build --nologo -v quiet`
Expected: CS0103 errors — `MaintainerTrustCalculator` does not exist

**Step 3: Commit**

```
git add tests/DepSafe.Tests/MaintainerTrustCalculatorTests.cs
git commit -m "test: add 12 failing tests for MaintainerTrustCalculator"
```

---

### Task 3: Implement MaintainerTrustCalculator

**Files:**
- Create: `src/DepSafe/Scoring/MaintainerTrustCalculator.cs`

**Step 1: Implement the calculator**

```csharp
// src/DepSafe/Scoring/MaintainerTrustCalculator.cs
using DepSafe.Models;

namespace DepSafe.Scoring;

/// <summary>
/// Calculates a Maintainer Trust Score (0-100) from GitHub repository signals.
/// Five weighted factors: Bus Factor (30%), Activity Continuity (25%),
/// Release Discipline (20%), Community Health (15%), Security Posture (10%).
/// </summary>
public static class MaintainerTrustCalculator
{
    /// <summary>
    /// Calculate maintainer trust score from repository and package metrics.
    /// Returns null when no GitHub data is available.
    /// </summary>
    public static MaintainerTrust? Calculate(GitHubRepoInfo? repoInfo, PackageMetrics metrics)
    {
        if (repoInfo is null)
            return null;

        int busFactor = CalculateBusFactorScore(repoInfo.ContributorCount);
        int activity = CalculateActivityContinuityScore(repoInfo, metrics);
        int release = CalculateReleaseDisciplineScore(repoInfo, metrics);
        int community = CalculateCommunityHealthScore(repoInfo);
        int security = CalculateSecurityPostureScore(repoInfo);

        // Weighted average: Bus 30%, Activity 25%, Release 20%, Community 15%, Security 10%
        int score = (int)Math.Round(
            busFactor * 0.30 +
            activity * 0.25 +
            release * 0.20 +
            community * 0.15 +
            security * 0.10);

        score = Math.Clamp(score, 0, 100);

        // Compute release author diversity from recent releases
        var releaseAuthors = repoInfo.RecentReleases
            .Where(r => !string.IsNullOrEmpty(r.AuthorLogin))
            .Select(r => r.AuthorLogin!)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        var topAuthor = repoInfo.RecentReleases
            .Where(r => !string.IsNullOrEmpty(r.AuthorLogin))
            .GroupBy(r => r.AuthorLogin!, StringComparer.OrdinalIgnoreCase)
            .OrderByDescending(g => g.Count())
            .FirstOrDefault()?.Key;

        return new MaintainerTrust(
            Score: score,
            Tier: GetTier(score),
            ContributorCount: repoInfo.ContributorCount,
            TotalCommits: repoInfo.TotalCommits,
            TotalReleases: repoInfo.TotalReleases,
            ReleaseAuthorCount: releaseAuthors.Count,
            TopReleaseAuthor: topAuthor);
    }

    /// <summary>
    /// Map a score (0-100) to a trust tier.
    /// </summary>
    public static MaintainerTrustTier GetTier(int score) => score switch
    {
        >= 80 => MaintainerTrustTier.High,
        >= 60 => MaintainerTrustTier.Moderate,
        >= 40 => MaintainerTrustTier.Low,
        _ => MaintainerTrustTier.Critical,
    };

    /// <summary>
    /// Bus Factor: contributor count as proxy for single-maintainer risk.
    /// 1 = 20, 2 = 50, 3-4 = 75, 5+ = 100.
    /// </summary>
    private static int CalculateBusFactorScore(int contributorCount) => contributorCount switch
    {
        <= 0 => 10,
        1 => 20,
        2 => 50,
        3 or 4 => 75,
        _ => 100,
    };

    /// <summary>
    /// Activity Continuity: last commit recency + archived status.
    /// Archived = 0. Otherwise: &lt;30d = 100, &lt;90d = 80, &lt;180d = 60, &lt;365d = 40, &gt;365d = 10.
    /// </summary>
    private static int CalculateActivityContinuityScore(GitHubRepoInfo repoInfo, PackageMetrics metrics)
    {
        if (repoInfo.IsArchived)
            return 0;

        var daysSinceCommit = metrics.DaysSinceLastCommit ?? (int)(DateTime.UtcNow - repoInfo.LastCommitDate).TotalDays;

        return daysSinceCommit switch
        {
            < 30 => 100,
            < 90 => 80,
            < 180 => 60,
            < 365 => 40,
            _ => 10,
        };
    }

    /// <summary>
    /// Release Discipline: release frequency + release author diversity.
    /// Base from ReleasesPerYear, penalty if all recent releases by single author.
    /// </summary>
    private static int CalculateReleaseDisciplineScore(GitHubRepoInfo repoInfo, PackageMetrics metrics)
    {
        // Base score from release cadence
        int cadenceScore = metrics.ReleasesPerYear switch
        {
            >= 6.0 => 100,
            >= 3.0 => 85,
            >= 1.0 => 65,
            >= 0.5 => 45,
            _ => 20,
        };

        // Penalty for single release author across 3+ releases
        if (repoInfo.RecentReleases.Count >= 3)
        {
            var distinctAuthors = repoInfo.RecentReleases
                .Where(r => !string.IsNullOrEmpty(r.AuthorLogin))
                .Select(r => r.AuthorLogin!)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .Count();

            if (distinctAuthors <= 1)
                cadenceScore = (int)(cadenceScore * 0.7); // 30% penalty
        }

        return Math.Clamp(cadenceScore, 0, 100);
    }

    /// <summary>
    /// Community Health: stars (log-scaled), issue/star ratio.
    /// 10k+ stars = 100, 1k+ = 80, 100+ = 60, 10+ = 40, &lt;10 = 20.
    /// Issue/star ratio &gt; 0.5 = -15, &gt; 0.2 = -5.
    /// </summary>
    private static int CalculateCommunityHealthScore(GitHubRepoInfo repoInfo)
    {
        int baseScore = repoInfo.Stars switch
        {
            >= 10000 => 100,
            >= 1000 => 80,
            >= 100 => 60,
            >= 10 => 40,
            _ => 20,
        };

        // Issue/star ratio penalty
        if (repoInfo.Stars > 0)
        {
            double ratio = (double)repoInfo.OpenIssues / repoInfo.Stars;
            if (ratio > 0.5) baseScore -= 15;
            else if (ratio > 0.2) baseScore -= 5;
        }

        return Math.Clamp(baseScore, 0, 100);
    }

    /// <summary>
    /// Security Posture: maintenance infrastructure signals.
    /// SECURITY.md = +50, not archived = +30, has license = +20.
    /// </summary>
    private static int CalculateSecurityPostureScore(GitHubRepoInfo repoInfo)
    {
        int score = 0;
        if (repoInfo.HasSecurityPolicy) score += 50;
        if (!repoInfo.IsArchived) score += 30;
        if (!string.IsNullOrEmpty(repoInfo.License)) score += 20;
        return Math.Clamp(score, 0, 100);
    }
}
```

**Step 2: Build and run tests**

Run: `dotnet test --nologo -v quiet`
Expected: All tests pass (12 new + 464 existing = 476)

**Step 3: Commit**

```
git add src/DepSafe/Scoring/MaintainerTrustCalculator.cs
git commit -m "feat: implement MaintainerTrustCalculator with 5-factor weighted scoring"
```

---

### Task 4: Extend GraphQL query and parse new fields

**Files:**
- Modify: `src/DepSafe/DataSources/GitHubApiClient.cs`

**Step 1: Write failing tests for GraphQL parsing**

Add to `tests/DepSafe.Tests/MaintainerTrustCalculatorTests.cs` (or a new test file if preferred):

Actually, `ParseRepoFromGraphQL` is `internal static` — add parsing tests to the existing test file or a new `GitHubApiClientParsingTests.cs`. The method takes a `JsonElement`, so we can test it directly.

Create `tests/DepSafe.Tests/GitHubRepoInfoParsingTests.cs`:

```csharp
using System.Text.Json;
using DepSafe.DataSources;

namespace DepSafe.Tests;

public class GitHubRepoInfoParsingTests
{
    [Fact]
    public void ParseRepoFromGraphQL_WithMaintainerFields_PopulatesNewProperties()
    {
        var json = JsonSerializer.Deserialize<JsonElement>("""
        {
            "nameWithOwner": "test/repo",
            "stargazerCount": 500,
            "forkCount": 50,
            "isArchived": false,
            "isFork": false,
            "pushedAt": "2026-02-01T00:00:00Z",
            "licenseInfo": { "spdxId": "MIT" },
            "issues": { "totalCount": 10 },
            "defaultBranchRef": {
                "target": {
                    "history": {
                        "nodes": [{ "committedDate": "2026-02-01T00:00:00Z" }],
                        "totalCount": 1234
                    }
                }
            },
            "securityPolicy": { "id": "abc" },
            "mentionableUsers": { "totalCount": 15 },
            "releases": {
                "totalCount": 42,
                "nodes": [
                    { "createdAt": "2026-01-15T00:00:00Z", "tagName": "v2.0.0", "author": { "login": "alice" } },
                    { "createdAt": "2026-01-01T00:00:00Z", "tagName": "v1.9.0", "author": { "login": "bob" } }
                ]
            }
        }
        """);

        var info = GitHubApiClient.ParseRepoFromGraphQL(json, "test", "repo");

        Assert.Equal(15, info.ContributorCount);
        Assert.Equal(1234, info.TotalCommits);
        Assert.Equal(42, info.TotalReleases);
        Assert.Equal(2, info.RecentReleases.Count);
        Assert.Equal("v2.0.0", info.RecentReleases[0].TagName);
        Assert.Equal("alice", info.RecentReleases[0].AuthorLogin);
        Assert.Equal("bob", info.RecentReleases[1].AuthorLogin);
    }

    [Fact]
    public void ParseRepoFromGraphQL_MissingNewFields_DefaultsToZeroAndEmpty()
    {
        var json = JsonSerializer.Deserialize<JsonElement>("""
        {
            "nameWithOwner": "test/repo",
            "stargazerCount": 100,
            "forkCount": 5,
            "isArchived": false,
            "isFork": false,
            "pushedAt": "2026-01-01T00:00:00Z",
            "issues": { "totalCount": 3 },
            "defaultBranchRef": {
                "target": {
                    "history": {
                        "nodes": [{ "committedDate": "2026-01-01T00:00:00Z" }]
                    }
                }
            }
        }
        """);

        var info = GitHubApiClient.ParseRepoFromGraphQL(json, "test", "repo");

        Assert.Equal(0, info.ContributorCount);
        Assert.Equal(0, info.TotalCommits);
        Assert.Equal(0, info.TotalReleases);
        Assert.Empty(info.RecentReleases);
    }

    [Fact]
    public void ParseRepoFromGraphQL_NullReleaseAuthor_HandlesGracefully()
    {
        var json = JsonSerializer.Deserialize<JsonElement>("""
        {
            "nameWithOwner": "test/repo",
            "stargazerCount": 100,
            "forkCount": 5,
            "isArchived": false,
            "isFork": false,
            "pushedAt": "2026-01-01T00:00:00Z",
            "issues": { "totalCount": 3 },
            "defaultBranchRef": {
                "target": {
                    "history": {
                        "nodes": [{ "committedDate": "2026-01-01T00:00:00Z" }],
                        "totalCount": 50
                    }
                }
            },
            "releases": {
                "totalCount": 1,
                "nodes": [
                    { "createdAt": "2026-01-01T00:00:00Z", "tagName": "v1.0.0", "author": null }
                ]
            }
        }
        """);

        var info = GitHubApiClient.ParseRepoFromGraphQL(json, "test", "repo");

        Assert.Single(info.RecentReleases);
        Assert.Null(info.RecentReleases[0].AuthorLogin);
    }
}
```

**Step 2: Extend the GraphQL query**

File: `src/DepSafe/DataSources/GitHubApiClient.cs`, line 164-184.

Replace the existing query template (lines 164-184) with this version that adds `mentionableUsers`, `releases`, and `history.totalCount`:

```csharp
                queryBuilder.Append($@"
                    repo{i}: repository(owner: ""{SanitizeGraphQLString(owner)}"", name: ""{SanitizeGraphQLString(repo)}"") {{
                        nameWithOwner
                        stargazerCount
                        forkCount
                        isArchived
                        isFork
                        pushedAt
                        licenseInfo {{ spdxId }}
                        issues(states: OPEN) {{ totalCount }}
                        defaultBranchRef {{
                            target {{
                                ... on Commit {{
                                    history(first: 1) {{
                                        nodes {{ committedDate }}
                                        totalCount
                                    }}
                                }}
                            }}
                        }}
                        securityPolicy: object(expression: ""HEAD:SECURITY.md"") {{ id }}
                        mentionableUsers {{ totalCount }}
                        releases(last: 5, orderBy: {{field: CREATED_AT, direction: DESC}}) {{
                            totalCount
                            nodes {{
                                createdAt
                                tagName
                                author {{ login }}
                            }}
                        }}
                    }}");
```

**Step 3: Update ParseRepoFromGraphQL to parse new fields**

File: `src/DepSafe/DataSources/GitHubApiClient.cs`, inside `ParseRepoFromGraphQL` method (line 274+).

After the `hasSecurityPolicy` parsing (line 319) and before the `return new GitHubRepoInfo` (line 321), add:

```csharp
        // Parse contributor count (mentionableUsers)
        var contributorCount = 0;
        if (repoData.TryGetProperty("mentionableUsers", out var mu) &&
            mu.TryGetProperty("totalCount", out var muCount))
        {
            contributorCount = muCount.GetInt32();
        }

        // Parse total commits from history.totalCount
        var totalCommits = 0;
        if (repoData.TryGetProperty("defaultBranchRef", out var dbr2) &&
            dbr2.ValueKind != JsonValueKind.Null &&
            dbr2.TryGetProperty("target", out var target2) &&
            target2.TryGetProperty("history", out var history2) &&
            history2.TryGetProperty("totalCount", out var historyCount))
        {
            totalCommits = historyCount.GetInt32();
        }

        // Parse releases
        var totalReleases = 0;
        var recentReleases = new List<ReleaseInfo>();
        if (repoData.TryGetProperty("releases", out var rel))
        {
            if (rel.TryGetProperty("totalCount", out var relCount))
                totalReleases = relCount.GetInt32();

            if (rel.TryGetProperty("nodes", out var relNodes))
            {
                foreach (var node in relNodes.EnumerateArray())
                {
                    var tagName = node.TryGetProperty("tagName", out var tn) ? tn.GetString() ?? "" : "";
                    var createdAt = DateTime.MinValue;
                    if (node.TryGetProperty("createdAt", out var ca) && ca.ValueKind == JsonValueKind.String)
                        DateTime.TryParse(ca.GetString(), out createdAt);

                    string? authorLogin = null;
                    if (node.TryGetProperty("author", out var auth) &&
                        auth.ValueKind != JsonValueKind.Null &&
                        auth.TryGetProperty("login", out var login))
                    {
                        authorLogin = login.GetString();
                    }

                    recentReleases.Add(new ReleaseInfo(tagName, createdAt, authorLogin));
                }
            }
        }
```

Then update the `return new GitHubRepoInfo` block to include:

```csharp
            CommitsLastYear = 0,
            HasSecurityPolicy = hasSecurityPolicy,
            ContributorCount = contributorCount,
            TotalCommits = totalCommits,
            TotalReleases = totalReleases,
            RecentReleases = recentReleases,
```

**Important:** The existing code at line 294-307 already parses `defaultBranchRef.target.history` for `committedDate`. The `totalCount` parse must reuse a compatible approach — use a second variable name (`dbr2`, `target2`, `history2`) or restructure. Actually, since we're within the same method, we can parse `totalCommits` from the same path. The cleanest approach is to extract `totalCount` alongside the existing `committedDate` parsing by adding after line 306:

Actually, the cleanest approach: add `totalCount` extraction inside the existing `history` parse block (after line 297). After the existing `nodes` parsing, add:

```csharp
            if (history.TryGetProperty("totalCount", out var historyTotalCount))
                totalCommits = historyTotalCount.GetInt32();
```

Declare `var totalCommits = 0;` at the top of the method (near line 276).

**Step 4: Add `using DepSafe.Models;`** if not already present at the top of GitHubApiClient.cs.

**Step 5: Build and run tests**

Run: `dotnet test --nologo -v quiet`
Expected: All tests pass (3 new parsing + 12 calculator + 464 existing = 479)

**Step 6: Commit**

```
git add src/DepSafe/DataSources/GitHubApiClient.cs tests/DepSafe.Tests/GitHubRepoInfoParsingTests.cs
git commit -m "feat: extend GraphQL query with contributor, release, and commit count fields"
```

---

### Task 5: Wire MaintainerTrustCalculator into HealthScoreCalculator

**Files:**
- Modify: `src/DepSafe/Scoring/HealthScoreCalculator.cs`

**Step 1: Add MaintainerTrust calculation to NuGet PackageHealth construction**

File: `src/DepSafe/Scoring/HealthScoreCalculator.cs`, inside the NuGet `Calculate` method (line 73-114).

After `var metrics = BuildMetrics(nugetInfo, repoInfo, activeVulnerabilities);` (line 87), add:

```csharp
        var maintainerTrust = MaintainerTrustCalculator.Calculate(repoInfo, metrics);
```

Then add to the `new PackageHealth { ... }` initializer (before the closing `};`):

```csharp
            MaintainerTrust = maintainerTrust,
```

**Step 2: Add MaintainerTrust calculation to npm PackageHealth construction**

File: `src/DepSafe/Scoring/HealthScoreCalculator.cs`, inside the npm `Calculate` method (line 119+).

Same pattern: after `var metrics = BuildMetrics(...)`, add:

```csharp
        var maintainerTrust = MaintainerTrustCalculator.Calculate(repoInfo, metrics);
```

And add `MaintainerTrust = maintainerTrust,` to the `new PackageHealth` initializer.

**Step 3: Build and run tests**

Run: `dotnet test --nologo -v quiet`
Expected: All tests pass

**Step 4: Commit**

```
git add src/DepSafe/Scoring/HealthScoreCalculator.cs
git commit -m "feat: wire MaintainerTrustCalculator into PackageHealth construction"
```

---

### Task 6: Add CRA compliance item for Maintainer Trust

**Files:**
- Modify: `src/DepSafe/Compliance/CraReportGenerator.cs`

**Step 1: Add weight entry**

File: `src/DepSafe/Compliance/CraReportGenerator.cs`, in the `s_craWeights` dictionary (line 563-583).

Add before the closing `}.ToFrozenDictionary(...)` line:

```csharp
        ["CRA Art. 13(5) - Maintainer Trust"] = 8,
```

**Step 2: Add compliance item generation**

File: `src/DepSafe/Compliance/CraReportGenerator.cs`, in the `Generate()` method.

Find the block after the Art. 14 compliance item (around line 501) and before the `// Calculate CRA Readiness Score` comment (line 503). Insert:

```csharp
        // CRA Art. 13(5) - Maintainer Trust (supply chain due diligence on maintainer reliability)
        {
            var criticalTrustPackages = packages
                .Where(p => p.MaintainerTrust is not null && p.MaintainerTrust.Score < 40)
                .Select(p => p.PackageId)
                .ToList();

            var lowTrustPackages = packages
                .Where(p => p.MaintainerTrust is not null && p.MaintainerTrust.Score < 60)
                .Select(p => p.PackageId)
                .ToList();

            var trustStatus = criticalTrustPackages.Count > 0
                ? CraComplianceStatus.NonCompliant
                : lowTrustPackages.Count > 0
                    ? CraComplianceStatus.ActionRequired
                    : CraComplianceStatus.Compliant;

            var trustEvidence = criticalTrustPackages.Count > 0
                ? $"{criticalTrustPackages.Count} package(s) with critical maintainer trust: {string.Join(", ", criticalTrustPackages.Take(5))}"
                : lowTrustPackages.Count > 0
                    ? $"{lowTrustPackages.Count} package(s) with low maintainer trust: {string.Join(", ", lowTrustPackages.Take(5))}"
                    : "All packages have adequate maintainer trust scores";

            complianceItems.Add(new CraComplianceItem
            {
                Requirement = "CRA Art. 13(5) - Maintainer Trust",
                Description = "Exercise due diligence on third-party component maintainer reliability: contributor diversity, release discipline, community health",
                Status = trustStatus,
                Evidence = trustEvidence,
                Recommendation = criticalTrustPackages.Count > 0
                    ? "Investigate alternatives for critical-trust packages. Single-maintainer packages with low activity pose supply chain risk."
                    : null
            });
        }
```

**Step 3: Build and run tests**

Run: `dotnet test --nologo -v quiet`
Expected: All tests pass

**Step 4: Commit**

```
git add src/DepSafe/Compliance/CraReportGenerator.cs
git commit -m "feat: add CRA Art. 13(5) Maintainer Trust compliance item"
```

---

### Task 7: Add Trust column to package table in HTML report

**Files:**
- Modify: `src/DepSafe/Compliance/CraReportGenerator.Sections.cs`
- Modify: `src/DepSafe/Compliance/CraReportGenerator.cs`

**Step 1: Add trust score rendering in package table**

File: `src/DepSafe/Compliance/CraReportGenerator.Sections.cs`

Find the package scores section (around line 249-258). After the CRA score `</div>` (line 257), before the closing `</div>` of `package-scores` (line 258), insert:

```csharp
            // Trust score (only when data available)
            if (pkg.MaintainerTrust is not null)
            {
                var trustScore = pkg.MaintainerTrust.Score;
                var trustClass = GetTrustScoreClass(trustScore);
                sb.AppendLine($"        <div class=\"package-score-item\" title=\"Maintainer Trust \u2014 contributor diversity, release discipline, community health\">");
                sb.AppendLine($"          <span class=\"score-label\">TRUST</span>");
                sb.AppendLine($"          <span class=\"score-value {trustClass}\">{trustScore}</span>");
                sb.AppendLine($"        </div>");
            }
```

**Step 2: Add GetTrustScoreClass helper**

In the same file (`CraReportGenerator.Sections.cs`), find the `GetScoreClass` or `GetCraScoreClass` helper methods. Add nearby:

```csharp
    private static string GetTrustScoreClass(int score) => score switch
    {
        >= 80 => "score-good",
        >= 60 => "score-moderate",
        >= 40 => "score-warning",
        _ => "score-critical"
    };
```

**Note:** Check existing class names first. The existing `GetScoreClass` likely uses `score-good`, `score-warning`, `score-critical` — reuse those CSS classes.

**Step 3: Build and run tests**

Run: `dotnet test --nologo -v quiet`
Expected: All tests pass

**Step 4: Commit**

```
git add src/DepSafe/Compliance/CraReportGenerator.Sections.cs src/DepSafe/Compliance/CraReportGenerator.cs
git commit -m "feat: add Trust score column to package health table"
```

---

### Task 8: Add Maintainer Trust summary section to HTML report

**Files:**
- Modify: `src/DepSafe/Compliance/CraReportGenerator.cs` (nav + section call + Set* method + field)
- Modify: `src/DepSafe/Compliance/CraReportGenerator.Sections.cs` (section rendering)
- Modify: `src/DepSafe/Resources/report-styles.css` (CSS)

**Step 1: Add field and setter to CraReportGenerator**

File: `src/DepSafe/Compliance/CraReportGenerator.cs`

Add field near other private fields:

```csharp
    private IReadOnlyList<PackageHealth>? _maintainerTrustPackages;
```

Add setter method after `SetAuditFindings`:

```csharp
    public void SetMaintainerTrustData(IReadOnlyList<PackageHealth> packages)
    {
        _maintainerTrustPackages = packages;
    }
```

**Step 2: Add nav item**

File: `src/DepSafe/Compliance/CraReportGenerator.cs`

After the audit simulation nav item (line 789), add:

```csharp
        if (_maintainerTrustPackages is not null)
        {
            var trustPackagesWithData = _maintainerTrustPackages.Where(p => p.MaintainerTrust is not null).ToList();
            var criticalTrustCount = trustPackagesWithData.Count(p => p.MaintainerTrust!.Tier == Models.MaintainerTrustTier.Critical);
            var lowTrustCount = trustPackagesWithData.Count(p => p.MaintainerTrust!.Tier == Models.MaintainerTrustTier.Low);
            var trustBadgeClass = criticalTrustCount > 0 ? "critical" : lowTrustCount > 0 ? "warning" : "success";
            var trustBadgeValue = criticalTrustCount + lowTrustCount;
            sb.AppendLine("        <li><a href=\"#\" onclick=\"showSection('maintainer-trust')\" data-section=\"maintainer-trust\">");
            sb.AppendLine("          <svg class=\"nav-icon\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\"><path d=\"M17 21v-2a4 4 0 00-4-4H5a4 4 0 00-4 4v2\"/><circle cx=\"9\" cy=\"7\" r=\"4\"/><path d=\"M23 21v-2a4 4 0 00-3-3.87\"/><path d=\"M16 3.13a4 4 0 010 7.75\"/></svg>");
            sb.AppendLine($"          Maintainer Trust<span class=\"nav-badge {trustBadgeClass}\">{trustBadgeValue}</span></a></li>");
        }
```

**Step 3: Add section call in GenerateHtml**

After the audit simulation section call (line 930), add:

```csharp
        if (_maintainerTrustPackages is not null)
        {
            sb.AppendLine("<section id=\"maintainer-trust\" class=\"section\">");
            GenerateMaintainerTrustSection(sb);
            sb.AppendLine("</section>");
        }
```

**Step 4: Add section rendering method**

File: `src/DepSafe/Compliance/CraReportGenerator.Sections.cs`

Add after the `GenerateAuditSimulationSection` method:

```csharp
    private void GenerateMaintainerTrustSection(StringBuilder sb)
    {
        sb.AppendLine("<div class=\"section-header\">");
        sb.AppendLine("  <h2>Maintainer Trust</h2>");
        sb.AppendLine("</div>");

        if (_maintainerTrustPackages is null) return;

        var packagesWithTrust = _maintainerTrustPackages
            .Where(p => p.MaintainerTrust is not null)
            .OrderBy(p => p.MaintainerTrust!.Score)
            .ToList();

        if (packagesWithTrust.Count == 0)
        {
            sb.AppendLine("<div class=\"card empty-state\">");
            sb.AppendLine("  <div class=\"empty-icon\">\u2139</div>");
            sb.AppendLine("  <h3>No Maintainer Data</h3>");
            sb.AppendLine("  <p>Trust scores require GitHub repository data. Run without --skip-github to enable.</p>");
            sb.AppendLine("</div>");
            return;
        }

        // Distribution summary
        int highCount = packagesWithTrust.Count(p => p.MaintainerTrust!.Tier == Models.MaintainerTrustTier.High);
        int moderateCount = packagesWithTrust.Count(p => p.MaintainerTrust!.Tier == Models.MaintainerTrustTier.Moderate);
        int lowCount = packagesWithTrust.Count(p => p.MaintainerTrust!.Tier == Models.MaintainerTrustTier.Low);
        int criticalCount = packagesWithTrust.Count(p => p.MaintainerTrust!.Tier == Models.MaintainerTrustTier.Critical);
        int avgScore = (int)Math.Round(packagesWithTrust.Average(p => p.MaintainerTrust!.Score));

        sb.AppendLine("<div class=\"card trust-summary\">");
        sb.AppendLine("  <div class=\"trust-distribution\">");
        sb.AppendLine($"    <div class=\"trust-avg\">Average Trust Score: <strong>{avgScore}</strong></div>");
        sb.AppendLine("    <div class=\"trust-counts\">");
        sb.AppendLine($"      <span class=\"trust-count high\">{highCount} High</span>");
        sb.AppendLine($"      <span class=\"trust-count moderate\">{moderateCount} Moderate</span>");
        sb.AppendLine($"      <span class=\"trust-count low\">{lowCount} Low</span>");
        sb.AppendLine($"      <span class=\"trust-count critical\">{criticalCount} Critical</span>");
        sb.AppendLine("    </div>");
        sb.AppendLine("  </div>");
        sb.AppendLine("</div>");

        // Bottom 5 lowest-trust packages
        var bottom5 = packagesWithTrust.Take(5).ToList();
        if (bottom5.Count > 0)
        {
            sb.AppendLine("<div class=\"card\">");
            sb.AppendLine("  <h3>Lowest Trust Packages</h3>");
            sb.AppendLine("  <table class=\"trust-table\">");
            sb.AppendLine("    <thead><tr>");
            sb.AppendLine("      <th>Package</th><th>Score</th><th>Tier</th><th>Contributors</th><th>Releases</th><th>Release Authors</th>");
            sb.AppendLine("    </tr></thead>");
            sb.AppendLine("    <tbody>");
            foreach (var pkg in bottom5)
            {
                var trust = pkg.MaintainerTrust!;
                var tierClass = trust.Tier.ToString().ToLowerInvariant();
                sb.AppendLine("    <tr>");
                sb.AppendLine($"      <td>{EscapeHtml(pkg.PackageId)}</td>");
                sb.AppendLine($"      <td><span class=\"trust-badge {tierClass}\">{trust.Score}</span></td>");
                sb.AppendLine($"      <td>{trust.Tier}</td>");
                sb.AppendLine($"      <td>{trust.ContributorCount}</td>");
                sb.AppendLine($"      <td>{trust.TotalReleases}</td>");
                sb.AppendLine($"      <td>{trust.ReleaseAuthorCount}{(trust.TopReleaseAuthor is not null ? $" ({EscapeHtml(trust.TopReleaseAuthor)})" : "")}</td>");
                sb.AppendLine("    </tr>");
            }
            sb.AppendLine("    </tbody>");
            sb.AppendLine("  </table>");
            sb.AppendLine("</div>");
        }
    }
```

**Step 5: Add CSS for maintainer trust section**

File: `src/DepSafe/Resources/report-styles.css`

Append after the last rule:

```css

    /* Maintainer Trust */
    .trust-summary {
      margin-bottom: 1rem;
    }

    .trust-distribution {
      display: flex;
      align-items: center;
      justify-content: space-between;
      flex-wrap: wrap;
      gap: 1rem;
    }

    .trust-avg {
      font-size: 1.1rem;
      color: var(--text-primary);
    }

    .trust-counts {
      display: flex;
      gap: 0.75rem;
      flex-wrap: wrap;
    }

    .trust-count {
      padding: 4px 12px;
      border-radius: 12px;
      font-size: 0.85rem;
      font-weight: 600;
    }

    .trust-count.high { background: rgba(39, 174, 96, 0.15); color: var(--success); }
    .trust-count.moderate { background: rgba(52, 152, 219, 0.15); color: var(--info, #3498db); }
    .trust-count.low { background: rgba(230, 126, 34, 0.15); color: #e67e22; }
    .trust-count.critical { background: rgba(231, 76, 60, 0.15); color: var(--danger); }

    .trust-table {
      width: 100%;
      border-collapse: collapse;
      margin-top: 0.5rem;
    }

    .trust-table th {
      text-align: left;
      padding: 8px 12px;
      border-bottom: 2px solid var(--border);
      font-size: 0.85rem;
      color: var(--text-secondary);
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }

    .trust-table td {
      padding: 8px 12px;
      border-bottom: 1px solid var(--border);
    }

    .trust-badge {
      display: inline-block;
      padding: 2px 8px;
      border-radius: 4px;
      font-weight: 600;
      font-size: 0.85rem;
    }

    .trust-badge.high { background: var(--success); color: white; }
    .trust-badge.moderate { background: var(--info, #3498db); color: white; }
    .trust-badge.low { background: #e67e22; color: white; }
    .trust-badge.critical { background: var(--danger); color: white; }

    .score-moderate { color: var(--info, #3498db); }
```

**Step 6: Build and run tests**

Run: `dotnet test --nologo -v quiet`
Expected: All tests pass

**Step 7: Commit**

```
git add src/DepSafe/Compliance/CraReportGenerator.cs src/DepSafe/Compliance/CraReportGenerator.Sections.cs src/DepSafe/Resources/report-styles.css
git commit -m "feat: add Maintainer Trust summary section and nav item to HTML report"
```

---

### Task 9: Wire data through CraReportCommand

**Files:**
- Modify: `src/DepSafe/Commands/CraReportCommand.cs`

**Step 1: Pass package data to SetMaintainerTrustData**

In all three code paths (`GenerateReportAsync` and `GenerateMixedReportAsync`), after existing `Set*` calls and before `Generate()`, add:

```csharp
        reportGenerator.SetMaintainerTrustData(allPackages);
```

Where `allPackages` is the `List<PackageHealth>` that is already being passed to the report generator. Find the exact variable name in each code path — it may be `allPackages`, `packages`, or similar.

Look for where `reportGenerator.SetAuditFindings(...)` is called — add `SetMaintainerTrustData` nearby, just before it.

**Step 2: Build and run tests**

Run: `dotnet test --nologo -v quiet`
Expected: All tests pass

**Step 3: Commit**

```
git add src/DepSafe/Commands/CraReportCommand.cs
git commit -m "feat: wire maintainer trust data through CraReportCommand pipeline"
```

---

### Task 10: Add Maintainer Trust check to AuditSimulator

**Files:**
- Modify: `src/DepSafe/Compliance/AuditSimulator.cs`
- Modify: `tests/DepSafe.Tests/AuditSimulatorTests.cs`

**Step 1: Write failing test**

Add to `tests/DepSafe.Tests/AuditSimulatorTests.cs`:

```csharp
    [Fact]
    public void LowMaintainerTrust_HighAuditFinding()
    {
        var packages = new[]
        {
            CreatePackage(score: 80, maintainerTrust: new MaintainerTrust(
                Score: 25, Tier: MaintainerTrustTier.Critical,
                ContributorCount: 1, TotalCommits: 50, TotalReleases: 3,
                ReleaseAuthorCount: 1, TopReleaseAuthor: "solo-dev"))
        };

        var result = AuditSimulator.Analyze(
            packages,
            new Dictionary<string, List<VulnerabilityInfo>>(),
            CreateMinimalCraReport(),
            CreateCleanSbomValidation(),
            [],
            CreateCleanAttackSurface(),
            hasSecurityPolicy: true,
            packagesWithSecurityPolicy: 1,
            packagesWithRepo: 1,
            config: new CraConfig { SecurityContact = "sec@test.com", SupportPeriodEnd = "2028-01-01" },
            hasReadme: true,
            hasChangelog: true);

        var finding = Assert.Single(result.Findings, f => f.ArticleReference.Contains("Art. 13(5)") && f.Finding.Contains("maintainer trust"));
        Assert.Equal(AuditSeverity.High, finding.Severity);
    }
```

**Note:** The `CreatePackage` helper may need a `maintainerTrust` parameter. Check the existing helper — if it doesn't have one, add an optional parameter.

**Step 2: Add the audit check**

File: `src/DepSafe/Compliance/AuditSimulator.cs`

After the existing Check 5 (Art. 13(5) — package health < 40) block, add Check 5b:

```csharp
        // 5b. Art. 13(5) — Maintainer trust due diligence
        CheckMaintainerTrust(allPackages, findings);
```

Add the private method:

```csharp
    /// <summary>
    /// Check 5b: Art. 13(5) — Third-party component maintainer due diligence.
    /// Packages with critical maintainer trust (score &lt; 40) indicate supply chain risk.
    /// </summary>
    private static void CheckMaintainerTrust(
        IReadOnlyList<PackageHealth> allPackages,
        List<AuditFinding> findings)
    {
        var criticalTrustPackages = allPackages
            .Where(p => p.MaintainerTrust is not null && p.MaintainerTrust.Score < 40)
            .Select(p => p.PackageId)
            .ToList();

        if (criticalTrustPackages.Count > 0)
        {
            findings.Add(new AuditFinding(
                ArticleReference: "CRA Art. 13(5) \u2014 Maintainer Due Diligence",
                Requirement: "Exercise due diligence regarding third-party component maintainer reliability",
                Finding: $"{criticalTrustPackages.Count} package(s) with critical maintainer trust score (< 40): single-maintainer risk, low community engagement, or stale maintenance",
                Severity: AuditSeverity.High,
                AffectedPackages: criticalTrustPackages));
        }
    }
```

**Step 3: Run tests**

Run: `dotnet test --nologo -v quiet`
Expected: All tests pass

**Step 4: Commit**

```
git add src/DepSafe/Compliance/AuditSimulator.cs tests/DepSafe.Tests/AuditSimulatorTests.cs
git commit -m "feat: add maintainer trust check to audit simulation"
```

---

### Task 11: Final verification and code review

**Step 1: Full build check**

Run: `dotnet build --nologo -v quiet`
Expected: 0 errors, 0 warnings

**Step 2: Full test suite**

Run: `dotnet test --nologo -v quiet`
Expected: All tests pass (464 existing + ~18 new)

**Step 3: Code review**

Dispatch two code reviewers (Opus + Sonnet) per CLAUDE.md rules.

**Step 4: Fix any review findings**

**Step 5: Final commit if needed**
