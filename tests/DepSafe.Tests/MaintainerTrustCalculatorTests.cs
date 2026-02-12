using DepSafe.Models;
using DepSafe.Scoring;

namespace DepSafe.Tests;

public class MaintainerTrustCalculatorTests
{
    [Fact]
    public void SingleContributor_LowBusFactorScore()
    {
        var repo = CreateRepoInfo(contributorCount: 1);
        var metrics = CreateMetrics();

        var result = MaintainerTrustCalculator.Calculate(repo, metrics);

        Assert.NotNull(result);
        // Single contributor = high bus factor risk, should not reach High tier
        Assert.NotEqual(MaintainerTrustTier.High, result.Tier);
        Assert.True(result.Score < 80);
    }

    [Fact]
    public void FivePlusContributors_HighBusFactorScore()
    {
        var repo = CreateRepoInfo(contributorCount: 5);
        var metrics = CreateMetrics();

        var result = MaintainerTrustCalculator.Calculate(repo, metrics);

        Assert.NotNull(result);
        Assert.True(result.Score >= 80);
        Assert.Equal(MaintainerTrustTier.High, result.Tier);
    }

    [Fact]
    public void ArchivedRepo_ZeroActivityContinuity()
    {
        var repo = CreateRepoInfo(isArchived: true);
        var metrics = CreateMetrics();

        var result = MaintainerTrustCalculator.Calculate(repo, metrics);

        Assert.NotNull(result);
        // Archived repos should be significantly penalized
        Assert.True(result.Score < 80);
    }

    [Fact]
    public void RecentCommit_FullActivityScore()
    {
        var repo = CreateRepoInfo(daysSinceLastCommit: 5);
        var metrics = CreateMetrics(daysSinceLastCommit: 5);

        var result = MaintainerTrustCalculator.Calculate(repo, metrics);

        Assert.NotNull(result);
        Assert.True(result.Score >= 80);
    }

    [Fact]
    public void StaleCommit_LowActivityScore()
    {
        var repo = CreateRepoInfo(
            daysSinceLastCommit: 400,
            stars: 50,
            contributorCount: 3);
        var metrics = CreateMetrics(
            daysSinceLastCommit: 400,
            stars: 50);

        var result = MaintainerTrustCalculator.Calculate(repo, metrics);

        Assert.NotNull(result);
        Assert.True(result.Score < 60);
    }

    [Fact]
    public void SingleReleaseAuthor_ReleaseDisciplinePenalty()
    {
        var repo = CreateRepoInfo(recentReleases: CreateSingleAuthorReleases());
        var metrics = CreateMetrics();

        var result = MaintainerTrustCalculator.Calculate(repo, metrics);

        Assert.NotNull(result);
        Assert.Equal(1, result.ReleaseAuthorCount);
    }

    [Fact]
    public void MultipleReleaseAuthors_NoPenalty()
    {
        var repo = CreateRepoInfo(recentReleases: CreateDiverseReleases());
        var metrics = CreateMetrics();

        var result = MaintainerTrustCalculator.Calculate(repo, metrics);

        Assert.NotNull(result);
        Assert.Equal(3, result.ReleaseAuthorCount);
    }

    [Fact]
    public void HighStars_GoodCommunityHealth()
    {
        var repo = CreateRepoInfo(stars: 15000);
        var metrics = CreateMetrics(stars: 15000);

        var result = MaintainerTrustCalculator.Calculate(repo, metrics);

        Assert.NotNull(result);
        Assert.True(result.Score >= 80);
    }

    [Fact]
    public void NoSecurityPolicy_SecurityPosturePenalty()
    {
        var repoWithPolicy = CreateRepoInfo(hasSecurityPolicy: true, license: "MIT");
        var repoNoPolicy = CreateRepoInfo(hasSecurityPolicy: false, license: null);
        var metrics = CreateMetrics();

        var withPolicy = MaintainerTrustCalculator.Calculate(repoWithPolicy, metrics);
        var noPolicy = MaintainerTrustCalculator.Calculate(repoNoPolicy, metrics);

        Assert.NotNull(withPolicy);
        Assert.NotNull(noPolicy);
        Assert.True(noPolicy.Score < withPolicy.Score);
    }

    [Fact]
    public void FullCleanInputs_HighTrustScore()
    {
        var repo = CreateRepoInfo();
        var metrics = CreateMetrics();

        var result = MaintainerTrustCalculator.Calculate(repo, metrics);

        Assert.NotNull(result);
        Assert.True(result.Score >= 80);
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
        var metrics = CreateMetrics();

        var result = MaintainerTrustCalculator.Calculate(null, metrics);

        Assert.Null(result);
    }

    // --- Helper methods ---

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
            Owner = "owner",
            Name = "repo",
            FullName = "owner/repo",
            Stars = stars,
            OpenIssues = openIssues,
            Forks = forks,
            LastCommitDate = DateTime.UtcNow.AddDays(-daysSinceLastCommit),
            LastPushDate = DateTime.UtcNow.AddDays(-daysSinceLastCommit),
            IsArchived = isArchived,
            IsFork = false,
            License = license,
            CommitsLastYear = 100,
            ContributorCount = contributorCount,
            TotalCommits = totalCommits,
            TotalReleases = totalReleases,
            RecentReleases = recentReleases ?? CreateDiverseReleases(),
            HasSecurityPolicy = hasSecurityPolicy
        };
    }

    private static PackageMetrics CreateMetrics(
        double releasesPerYear = 4.0,
        int daysSinceLastRelease = 30,
        int daysSinceLastCommit = 5,
        int stars = 1000,
        int openIssues = 10)
    {
        return new PackageMetrics
        {
            ReleasesPerYear = releasesPerYear,
            DaysSinceLastRelease = daysSinceLastRelease,
            DaysSinceLastCommit = daysSinceLastCommit,
            Stars = stars,
            OpenIssues = openIssues,
            TotalDownloads = 100000,
            DownloadTrend = 0.1
        };
    }

    private static List<ReleaseInfo> CreateDiverseReleases()
    {
        var now = DateTime.UtcNow;
        return
        [
            new ReleaseInfo("v1.5.0", now.AddDays(-10), "alice"),
            new ReleaseInfo("v1.4.0", now.AddDays(-40), "bob"),
            new ReleaseInfo("v1.3.0", now.AddDays(-80), "charlie"),
            new ReleaseInfo("v1.2.0", now.AddDays(-120), "alice"),
            new ReleaseInfo("v1.1.0", now.AddDays(-160), "bob")
        ];
    }

    private static List<ReleaseInfo> CreateSingleAuthorReleases()
    {
        var now = DateTime.UtcNow;
        return
        [
            new ReleaseInfo("v1.5.0", now.AddDays(-10), "solo-dev"),
            new ReleaseInfo("v1.4.0", now.AddDays(-40), "solo-dev"),
            new ReleaseInfo("v1.3.0", now.AddDays(-80), "solo-dev"),
            new ReleaseInfo("v1.2.0", now.AddDays(-120), "solo-dev"),
            new ReleaseInfo("v1.1.0", now.AddDays(-160), "solo-dev")
        ];
    }
}
