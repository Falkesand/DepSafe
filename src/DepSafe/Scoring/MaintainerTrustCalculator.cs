using DepSafe.Models;

namespace DepSafe.Scoring;

/// <summary>
/// Calculates a maintainer trust score (0-100) based on five weighted factors:
/// bus factor, activity continuity, release discipline, community health, and security posture.
/// </summary>
public static class MaintainerTrustCalculator
{
    // Weights sum to 1.0
    private const double BusFactorWeight = 0.30;
    private const double ActivityContinuityWeight = 0.25;
    private const double ReleaseDisciplineWeight = 0.20;
    private const double CommunityHealthWeight = 0.15;
    private const double SecurityPostureWeight = 0.10;

    /// <summary>
    /// Calculate a maintainer trust assessment for a package.
    /// Returns null when no GitHub repository data is available.
    /// </summary>
    public static MaintainerTrust? Calculate(GitHubRepoInfo? repoInfo, PackageMetrics metrics)
    {
        if (repoInfo is null)
            return null;

        var busFactorScore = CalculateBusFactorScore(repoInfo.ContributorCount);
        var activityScore = CalculateActivityContinuityScore(repoInfo, metrics);
        var releaseScore = CalculateReleaseDisciplineScore(repoInfo, metrics);
        var communityScore = CalculateCommunityHealthScore(repoInfo);
        var securityScore = CalculateSecurityPostureScore(repoInfo);

        var weightedScore =
            busFactorScore * BusFactorWeight +
            activityScore * ActivityContinuityWeight +
            releaseScore * ReleaseDisciplineWeight +
            communityScore * CommunityHealthWeight +
            securityScore * SecurityPostureWeight;

        var score = (int)Math.Round(Math.Clamp(weightedScore, 0, 100));
        var tier = GetTier(score);

        // Compute release author statistics
        var (releaseAuthorCount, topReleaseAuthor) = AnalyzeReleaseAuthors(repoInfo.RecentReleases);

        return new MaintainerTrust(
            Score: score,
            Tier: tier,
            ContributorCount: repoInfo.ContributorCount,
            TotalCommits: repoInfo.TotalCommits,
            TotalReleases: repoInfo.TotalReleases,
            ReleaseAuthorCount: releaseAuthorCount,
            TopReleaseAuthor: topReleaseAuthor);
    }

    /// <summary>
    /// Map a trust score to a tier.
    /// </summary>
    public static MaintainerTrustTier GetTier(int score) => score switch
    {
        >= 80 => MaintainerTrustTier.High,
        >= 60 => MaintainerTrustTier.Moderate,
        >= 40 => MaintainerTrustTier.Low,
        _ => MaintainerTrustTier.Critical
    };

    /// <summary>
    /// Bus factor: how many contributors share the maintenance burden.
    /// Single-maintainer projects carry critical risk.
    /// </summary>
    private static double CalculateBusFactorScore(int contributorCount) => contributorCount switch
    {
        <= 1 => 0,
        2 => 45,
        3 or 4 => 75,
        _ => 100
    };

    /// <summary>
    /// Activity continuity: is the project still actively maintained?
    /// Archived repos get 0; otherwise scored by days since last commit.
    /// </summary>
    private static double CalculateActivityContinuityScore(GitHubRepoInfo repoInfo, PackageMetrics metrics)
    {
        if (repoInfo.IsArchived)
            return 0;

        var daysSinceCommit = metrics.DaysSinceLastCommit
            ?? (int)(DateTime.UtcNow - repoInfo.LastCommitDate).TotalDays;

        return daysSinceCommit switch
        {
            < 30 => 100,
            < 90 => 80,
            < 180 => 60,
            < 365 => 40,
            _ => 10
        };
    }

    /// <summary>
    /// Release discipline: regular, multi-author releases indicate healthy process.
    /// Combines cadence and recency, with a penalty for single-author release patterns.
    /// </summary>
    private static double CalculateReleaseDisciplineScore(GitHubRepoInfo repoInfo, PackageMetrics metrics)
    {
        var cadenceScore = metrics.ReleasesPerYear switch
        {
            >= 6 => 90,
            >= 3 => 70,
            >= 1 => 50,
            >= 0.5 => 30,
            _ => 10
        };

        var recencyScore = metrics.DaysSinceLastRelease switch
        {
            null => 40,
            <= 14 => 100,
            <= 60 => 70,
            <= 180 => 50,
            <= 365 => 30,
            _ => 10
        };

        var combined = (cadenceScore + recencyScore) / 2.0;

        // Penalty: if a single author is responsible for 3+ releases, reduce by 30%
        var (authorCount, _) = AnalyzeReleaseAuthors(repoInfo.RecentReleases);
        if (authorCount == 1 && repoInfo.RecentReleases.Count >= 3)
        {
            combined *= 0.70;
        }

        return Math.Clamp(combined, 0, 100);
    }

    /// <summary>
    /// Community health: stars as a log-scaled popularity proxy, with an issue ratio penalty.
    /// </summary>
    private static double CalculateCommunityHealthScore(GitHubRepoInfo repoInfo)
    {
        // Log-scaled star score: log10(stars) * 20, capped at 100
        var starScore = repoInfo.Stars > 0
            ? Math.Min(100, Math.Log10(repoInfo.Stars) * 20)
            : 0;

        // Issue ratio penalty: high open-issue-to-star ratio signals neglect
        var issuePenalty = 0.0;
        if (repoInfo.Stars > 0 && repoInfo.OpenIssues > 0)
        {
            var issueRatio = (double)repoInfo.OpenIssues / repoInfo.Stars;
            issuePenalty = issueRatio switch
            {
                > 0.5 => 20,
                > 0.2 => 10,
                > 0.1 => 5,
                _ => 0
            };
        }

        return Math.Clamp(starScore - issuePenalty, 0, 100);
    }

    /// <summary>
    /// Security posture: presence of SECURITY.md, active maintenance status, and license.
    /// </summary>
    private static double CalculateSecurityPostureScore(GitHubRepoInfo repoInfo)
    {
        var score = 0.0;

        if (repoInfo.HasSecurityPolicy)
            score += 50;

        if (!repoInfo.IsArchived)
            score += 30;

        if (!string.IsNullOrWhiteSpace(repoInfo.License))
            score += 20;

        return Math.Clamp(score, 0, 100);
    }

    /// <summary>
    /// Analyze release authors to determine concentration risk.
    /// Returns the distinct author count and the most prolific release author.
    /// </summary>
    private static (int AuthorCount, string? TopAuthor) AnalyzeReleaseAuthors(List<ReleaseInfo> releases)
    {
        if (releases.Count == 0)
            return (0, null);

        var authorCounts = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        foreach (var release in releases)
        {
            if (string.IsNullOrWhiteSpace(release.AuthorLogin))
                continue;

            if (!authorCounts.TryAdd(release.AuthorLogin, 1))
                authorCounts[release.AuthorLogin]++;
        }

        if (authorCounts.Count == 0)
            return (0, null);

        var topAuthor = authorCounts.MaxBy(kv => kv.Value).Key;
        return (authorCounts.Count, topAuthor);
    }
}
