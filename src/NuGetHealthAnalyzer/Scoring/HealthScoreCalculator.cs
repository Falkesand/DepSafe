using NuGetHealthAnalyzer.Models;

namespace NuGetHealthAnalyzer.Scoring;

/// <summary>
/// Calculates health scores for NuGet packages based on various metrics.
/// </summary>
public sealed class HealthScoreCalculator
{
    private readonly ScoreWeights _weights;

    public HealthScoreCalculator(ScoreWeights? weights = null)
    {
        _weights = weights ?? ScoreWeights.Default;
    }

    /// <summary>
    /// Calculate health score and status for a package.
    /// </summary>
    public PackageHealth Calculate(
        string packageId,
        string version,
        NuGetPackageInfo nugetInfo,
        GitHubRepoInfo? repoInfo,
        List<VulnerabilityInfo> vulnerabilities)
    {
        var metrics = BuildMetrics(nugetInfo, repoInfo, vulnerabilities);
        var score = CalculateScore(metrics);
        var status = GetStatus(score);
        var recommendations = GenerateRecommendations(metrics, nugetInfo, repoInfo);

        return new PackageHealth
        {
            PackageId = packageId,
            Version = version,
            Score = score,
            Status = status,
            Metrics = metrics,
            RepositoryUrl = repoInfo is not null ? $"https://github.com/{repoInfo.FullName}" : nugetInfo.RepositoryUrl,
            License = nugetInfo.License,
            Vulnerabilities = vulnerabilities.Count > 0
                ? vulnerabilities.Select(v => v.Id).ToList()
                : [],
            Recommendations = recommendations
        };
    }

    private PackageMetrics BuildMetrics(
        NuGetPackageInfo nugetInfo,
        GitHubRepoInfo? repoInfo,
        List<VulnerabilityInfo> vulnerabilities)
    {
        var versions = nugetInfo.Versions
            .Where(v => v.IsListed && !v.IsPrerelease)
            .OrderByDescending(v => v.PublishedDate)
            .ToList();

        var daysSinceLastRelease = versions.Count > 0
            ? (int)(DateTime.UtcNow - versions[0].PublishedDate).TotalDays
            : 9999;

        var releasesPerYear = CalculateReleasesPerYear(versions);
        var downloadTrend = CalculateDownloadTrend(versions);

        return new PackageMetrics
        {
            DaysSinceLastRelease = daysSinceLastRelease,
            ReleasesPerYear = releasesPerYear,
            DownloadTrend = downloadTrend,
            TotalDownloads = nugetInfo.TotalDownloads,
            DaysSinceLastCommit = repoInfo is not null
                ? (int)(DateTime.UtcNow - repoInfo.LastCommitDate).TotalDays
                : null,
            OpenIssues = repoInfo?.OpenIssues,
            Stars = repoInfo?.Stars,
            VulnerabilityCount = vulnerabilities.Count
        };
    }

    private static double CalculateReleasesPerYear(List<VersionInfo> versions)
    {
        if (versions.Count < 2) return versions.Count;

        var oldest = versions[^1].PublishedDate;
        var newest = versions[0].PublishedDate;
        var years = (newest - oldest).TotalDays / 365.0;

        return years > 0 ? versions.Count / years : versions.Count;
    }

    private static double CalculateDownloadTrend(List<VersionInfo> versions)
    {
        // Compare recent versions' download rates to older versions
        if (versions.Count < 4) return 0;

        var midpoint = versions.Count / 2;

        // Calculate averages without allocating new lists
        var recentSum = 0L;
        var olderSum = 0L;

        for (int i = 0; i < midpoint; i++)
            recentSum += versions[i].Downloads;

        for (int i = midpoint; i < versions.Count; i++)
            olderSum += versions[i].Downloads;

        var recentAvg = (double)recentSum / midpoint;
        var olderAvg = (double)olderSum / (versions.Count - midpoint);

        if (olderAvg == 0) return recentAvg > 0 ? 1.0 : 0;

        // Normalize to -1 to 1 range
        var ratio = recentAvg / olderAvg;
        return Math.Clamp(ratio - 1.0, -1.0, 1.0);
    }

    private int CalculateScore(PackageMetrics metrics)
    {
        var freshnessScore = CalculateFreshnessScore(metrics.DaysSinceLastRelease);
        var cadenceScore = CalculateCadenceScore(metrics.ReleasesPerYear);
        var trendScore = CalculateTrendScore(metrics.DownloadTrend);
        var activityScore = CalculateActivityScore(metrics);
        var vulnScore = CalculateVulnerabilityScore(metrics.VulnerabilityCount);

        var weightedScore =
            freshnessScore * _weights.Freshness +
            cadenceScore * _weights.ReleaseCadence +
            trendScore * _weights.DownloadTrend +
            activityScore * _weights.RepositoryActivity +
            vulnScore * _weights.Vulnerabilities;

        return (int)Math.Round(Math.Clamp(weightedScore, 0, 100));
    }

    private static double CalculateFreshnessScore(int daysSinceLastRelease)
    {
        // 100 if released within 30 days, decreasing thereafter
        // 0 if no release in 3+ years
        return daysSinceLastRelease switch
        {
            <= 30 => 100,
            <= 90 => 90,
            <= 180 => 80,
            <= 365 => 70,
            <= 730 => 50,
            <= 1095 => 30,
            _ => 10
        };
    }

    private static double CalculateCadenceScore(double releasesPerYear)
    {
        // Ideal: 2-12 releases per year
        return releasesPerYear switch
        {
            >= 2 and <= 12 => 100,
            >= 1 and < 2 => 70,
            > 12 and <= 24 => 80, // Very active but not excessive
            > 24 => 60, // Might indicate instability
            _ => 40 // Less than 1 release per year
        };
    }

    private static double CalculateTrendScore(double downloadTrend)
    {
        // -1 to 1 range, map to 0-100
        return (downloadTrend + 1.0) * 50.0;
    }

    private static double CalculateActivityScore(PackageMetrics metrics)
    {
        if (!metrics.DaysSinceLastCommit.HasValue)
        {
            // No repo info, assume moderate score
            return 50;
        }

        var daysSinceCommit = metrics.DaysSinceLastCommit.Value;
        var commitScore = daysSinceCommit switch
        {
            <= 7 => 100,
            <= 30 => 90,
            <= 90 => 80,
            <= 180 => 60,
            <= 365 => 40,
            _ => 20
        };

        // Adjust for stars (popularity indicator)
        var starBonus = metrics.Stars switch
        {
            >= 10000 => 10,
            >= 1000 => 5,
            >= 100 => 2,
            _ => 0
        };

        // Penalty for too many open issues relative to stars
        var issuePenalty = 0;
        if (metrics.Stars > 0 && metrics.OpenIssues > 0)
        {
            var issueRatio = (double)metrics.OpenIssues / metrics.Stars;
            issuePenalty = issueRatio > 0.5 ? 10 : issueRatio > 0.2 ? 5 : 0;
        }

        return Math.Clamp(commitScore + starBonus - issuePenalty, 0, 100);
    }

    private static double CalculateVulnerabilityScore(int vulnerabilityCount)
    {
        return vulnerabilityCount switch
        {
            0 => 100,
            1 => 50,
            2 => 25,
            _ => 0
        };
    }

    private static HealthStatus GetStatus(int score)
    {
        return score switch
        {
            >= 80 => HealthStatus.Healthy,
            >= 60 => HealthStatus.Watch,
            >= 40 => HealthStatus.Warning,
            _ => HealthStatus.Critical
        };
    }

    private static List<string> GenerateRecommendations(
        PackageMetrics metrics,
        NuGetPackageInfo nugetInfo,
        GitHubRepoInfo? repoInfo)
    {
        var recommendations = new List<string>();

        if (nugetInfo.IsDeprecated)
        {
            recommendations.Add($"Package is deprecated: {nugetInfo.DeprecationReason ?? "No reason provided"}");
        }

        if (metrics.DaysSinceLastRelease > 730)
        {
            recommendations.Add($"No releases in {metrics.DaysSinceLastRelease / 365} years - consider alternatives");
        }

        if (metrics.VulnerabilityCount > 0)
        {
            recommendations.Add($"{metrics.VulnerabilityCount} known vulnerabilities - update or replace urgently");
        }

        if (repoInfo?.IsArchived == true)
        {
            recommendations.Add("Repository is archived - package is no longer maintained");
        }

        if (metrics.DownloadTrend < -0.5)
        {
            recommendations.Add("Download trend declining significantly - community may be migrating away");
        }

        if (metrics.DaysSinceLastCommit > 365)
        {
            recommendations.Add("No repository activity in over a year");
        }

        return recommendations;
    }

    /// <summary>
    /// Calculate aggregate score for a project.
    /// </summary>
    public static int CalculateProjectScore(IEnumerable<PackageHealth> packages)
    {
        var packageList = packages.ToList();
        if (packageList.Count == 0) return 100;

        // Weight critical packages more heavily
        var weightedSum = 0.0;
        var totalWeight = 0.0;

        foreach (var pkg in packageList)
        {
            var weight = pkg.Status switch
            {
                HealthStatus.Critical => 3.0,
                HealthStatus.Warning => 2.0,
                HealthStatus.Watch => 1.5,
                _ => 1.0
            };
            weightedSum += pkg.Score * weight;
            totalWeight += weight;
        }

        return (int)Math.Round(weightedSum / totalWeight);
    }
}
