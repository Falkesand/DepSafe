using DepSafe.Models;
using DepSafe.Scoring;

namespace DepSafe.Tests;

public class HealthScoreCalculatorTests
{
    private readonly HealthScoreCalculator _calculator = new();

    [Fact]
    public void Calculate_HealthyPackage_ReturnsHighScore()
    {
        // Arrange
        var nugetInfo = CreateNuGetInfo(
            daysSinceLastRelease: 30,
            releasesPerYear: 4,
            totalDownloads: 10_000_000);

        var repoInfo = CreateRepoInfo(
            daysSinceLastCommit: 7,
            stars: 5000,
            openIssues: 50);

        // Act
        var result = _calculator.Calculate(
            "TestPackage",
            "1.0.0",
            nugetInfo,
            repoInfo,
            []);

        // Assert
        Assert.True(result.Score >= 80);
        Assert.Equal(HealthStatus.Healthy, result.Status);
    }

    [Fact]
    public void Calculate_AbandonedPackage_ReturnsLowScore()
    {
        // Arrange
        var nugetInfo = CreateNuGetInfo(
            daysSinceLastRelease: 1500, // 4+ years
            releasesPerYear: 0.2,
            totalDownloads: 1000);

        // Act
        var result = _calculator.Calculate(
            "OldPackage",
            "1.0.0",
            nugetInfo,
            null, // No repo info
            []);

        // Assert
        // Score should be low (Warning or Critical) due to lack of freshness
        Assert.True(result.Score < 60);
        Assert.True(result.Status == HealthStatus.Warning || result.Status == HealthStatus.Critical);
    }

    [Fact]
    public void Calculate_PackageWithVulnerabilities_PenalizesScore()
    {
        // Arrange
        var nugetInfo = CreateNuGetInfo(
            daysSinceLastRelease: 30,
            releasesPerYear: 4,
            totalDownloads: 10_000_000);

        var vulnerabilities = new List<VulnerabilityInfo>
        {
            new VulnerabilityInfo
            {
                Id = "GHSA-1234",
                Severity = "HIGH",
                Summary = "Test vulnerability",
                PackageId = "TestPackage",
                VulnerableVersionRange = "< 2.0.0"
            }
        };

        // Act
        var result = _calculator.Calculate(
            "TestPackage",
            "1.0.0",
            nugetInfo,
            null,
            vulnerabilities);

        // Assert
        Assert.Equal(1, result.Metrics.VulnerabilityCount);
        Assert.Contains("GHSA-1234", result.Vulnerabilities);
    }

    [Fact]
    public void Calculate_DeprecatedPackage_GeneratesRecommendation()
    {
        // Arrange
        var nugetInfo = CreateNuGetInfo(
            daysSinceLastRelease: 100,
            isDeprecated: true,
            deprecationReason: "Use NewPackage instead");

        // Act
        var result = _calculator.Calculate(
            "DeprecatedPackage",
            "1.0.0",
            nugetInfo,
            null,
            []);

        // Assert
        Assert.Contains(result.Recommendations, r => r.Contains("deprecated"));
    }

    [Fact]
    public void Calculate_ArchivedRepository_GeneratesRecommendation()
    {
        // Arrange
        var nugetInfo = CreateNuGetInfo(daysSinceLastRelease: 100);
        var repoInfo = CreateRepoInfo(isArchived: true);

        // Act
        var result = _calculator.Calculate(
            "ArchivedPackage",
            "1.0.0",
            nugetInfo,
            repoInfo,
            []);

        // Assert
        Assert.Contains(result.Recommendations, r => r.Contains("archived"));
    }

    [Fact]
    public void Calculate_HighScore_ReturnsHealthyStatus()
    {
        // All metrics maxed out → score ≥ 80 → Healthy
        var calc = new HealthScoreCalculator(new ScoreWeights
        {
            Freshness = 1.0, ReleaseCadence = 0, DownloadTrend = 0,
            RepositoryActivity = 0, Vulnerabilities = 0
        });
        var nugetInfo = CreateNuGetInfo(daysSinceLastRelease: 10); // freshness = 100

        var result = calc.Calculate("Pkg", "1.0.0", nugetInfo, null, []);

        Assert.True(result.Score >= 80);
        Assert.Equal(HealthStatus.Healthy, result.Status);
    }

    [Fact]
    public void Calculate_MediumScore_ReturnsWatchStatus()
    {
        // Freshness only, 365 days → freshness score = 70 → Watch
        var calc = new HealthScoreCalculator(new ScoreWeights
        {
            Freshness = 1.0, ReleaseCadence = 0, DownloadTrend = 0,
            RepositoryActivity = 0, Vulnerabilities = 0
        });
        var nugetInfo = CreateNuGetInfo(daysSinceLastRelease: 365);

        var result = calc.Calculate("Pkg", "1.0.0", nugetInfo, null, []);

        Assert.InRange(result.Score, 60, 79);
        Assert.Equal(HealthStatus.Watch, result.Status);
    }

    [Fact]
    public void Calculate_LowScore_ReturnsWarningStatus()
    {
        // Freshness only, 730 days → freshness score = 50 → Warning
        var calc = new HealthScoreCalculator(new ScoreWeights
        {
            Freshness = 1.0, ReleaseCadence = 0, DownloadTrend = 0,
            RepositoryActivity = 0, Vulnerabilities = 0
        });
        var nugetInfo = CreateNuGetInfo(daysSinceLastRelease: 730);

        var result = calc.Calculate("Pkg", "1.0.0", nugetInfo, null, []);

        Assert.InRange(result.Score, 40, 59);
        Assert.Equal(HealthStatus.Warning, result.Status);
    }

    [Fact]
    public void Calculate_VeryLowScore_ReturnsCriticalStatus()
    {
        // Freshness only, 1500 days → freshness score = 10 → Critical
        var calc = new HealthScoreCalculator(new ScoreWeights
        {
            Freshness = 1.0, ReleaseCadence = 0, DownloadTrend = 0,
            RepositoryActivity = 0, Vulnerabilities = 0
        });
        var nugetInfo = CreateNuGetInfo(daysSinceLastRelease: 1500);

        var result = calc.Calculate("Pkg", "1.0.0", nugetInfo, null, []);

        Assert.True(result.Score < 40);
        Assert.Equal(HealthStatus.Critical, result.Status);
    }

    [Fact]
    public void CalculateProjectScore_MultiplePackages_WeightsProblematicPackagesMore()
    {
        // Arrange
        var packages = new List<PackageHealth>
        {
            CreatePackageHealth(95, HealthStatus.Healthy),
            CreatePackageHealth(90, HealthStatus.Healthy),
            CreatePackageHealth(30, HealthStatus.Critical) // This should drag down the score
        };

        // Act
        var projectScore = HealthScoreCalculator.CalculateProjectScore(packages);

        // Assert
        // Without weighting, average would be ~72
        // With weighting for critical, it should be lower
        Assert.True(projectScore < 72);
    }

    [Fact]
    public void CalculateProjectScore_EmptyList_Returns100()
    {
        var score = HealthScoreCalculator.CalculateProjectScore([]);
        Assert.Equal(100, score);
    }

    private static NuGetPackageInfo CreateNuGetInfo(
        int daysSinceLastRelease = 30,
        double releasesPerYear = 4,
        long totalDownloads = 100000,
        bool isDeprecated = false,
        string? deprecationReason = null)
    {
        var versions = new List<VersionInfo>();
        var now = DateTime.UtcNow;

        // Create version history based on release cadence
        var versionCount = (int)(releasesPerYear * 3); // 3 years of history
        for (int i = 0; i < Math.Max(versionCount, 1); i++)
        {
            var daysAgo = daysSinceLastRelease + (int)(i * 365.0 / Math.Max(releasesPerYear, 0.5));
            versions.Add(new VersionInfo
            {
                Version = $"1.{versionCount - i}.0",
                PublishedDate = now.AddDays(-daysAgo),
                Downloads = totalDownloads / Math.Max(versionCount, 1),
                IsPrerelease = false,
                IsListed = true
            });
        }

        return new NuGetPackageInfo
        {
            PackageId = "TestPackage",
            LatestVersion = versions.First().Version,
            Versions = versions,
            TotalDownloads = totalDownloads,
            IsDeprecated = isDeprecated,
            DeprecationReason = deprecationReason
        };
    }

    private static GitHubRepoInfo CreateRepoInfo(
        int daysSinceLastCommit = 7,
        int stars = 1000,
        int openIssues = 50,
        bool isArchived = false)
    {
        return new GitHubRepoInfo
        {
            Owner = "owner",
            Name = "repo",
            FullName = "owner/repo",
            Stars = stars,
            OpenIssues = openIssues,
            Forks = 100,
            LastCommitDate = DateTime.UtcNow.AddDays(-daysSinceLastCommit),
            LastPushDate = DateTime.UtcNow.AddDays(-daysSinceLastCommit),
            IsArchived = isArchived,
            IsFork = false,
            CommitsLastYear = 100
        };
    }

    private static PackageHealth CreatePackageHealth(int score, HealthStatus status)
    {
        return new PackageHealth
        {
            PackageId = "TestPackage",
            Version = "1.0.0",
            Score = score,
            Status = status,
            Metrics = new PackageMetrics
            {
                DaysSinceLastRelease = 30,
                ReleasesPerYear = 4,
                DownloadTrend = 0.1,
                TotalDownloads = 100000
            }
        };
    }
}
