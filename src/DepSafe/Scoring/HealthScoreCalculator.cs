using DepSafe.Models;

namespace DepSafe.Scoring;

/// <summary>
/// Calculates health scores for NuGet packages based on various metrics.
/// </summary>
public sealed class HealthScoreCalculator
{
    private readonly ScoreWeights _weights;

    /// <summary>
    /// License overrides from .cra-config.json.
    /// Key: Package name (case-insensitive), Value: SPDX license identifier.
    /// </summary>
    public Dictionary<string, string>? LicenseOverrides { get; set; }

    public HealthScoreCalculator(ScoreWeights? weights = null)
    {
        _weights = weights ?? ScoreWeights.Default;
    }

    private static List<string> GetNpmAuthors(string packageName)
    {
        // Extract scope owner as publisher (e.g., @tanstack/router → tanstack)
        if (packageName.StartsWith('@') && packageName.Contains('/'))
        {
            var scope = packageName[1..packageName.IndexOf('/')];
            return [scope];
        }
        return [];
    }

    private string? GetEffectiveLicense(string packageId, string? detectedLicense)
    {
        if (LicenseOverrides is not null &&
            LicenseOverrides.TryGetValue(packageId, out var overrideLicense))
        {
            return overrideLicense;
        }
        return detectedLicense;
    }

    /// <summary>
    /// Calculate health score and status for a NuGet package.
    /// </summary>
    public PackageHealth Calculate(
        string packageId,
        string version,
        NuGetPackageInfo nugetInfo,
        GitHubRepoInfo? repoInfo,
        List<VulnerabilityInfo> vulnerabilities,
        DependencyType dependencyType = DependencyType.Direct)
    {
        // Filter to only vulnerabilities that actually affect this version
        var activeVulnerabilities = FilterActiveVulnerabilities(version, vulnerabilities);

        // Apply license override if configured
        var effectiveLicense = GetEffectiveLicense(packageId, nugetInfo.License);

        var metrics = BuildMetrics(nugetInfo, repoInfo, activeVulnerabilities);
        var score = CalculateScore(metrics);
        var status = GetStatus(score);
        var (craScore, craStatus) = CalculateCraScore(activeVulnerabilities, effectiveLicense, packageId, version);
        var recommendations = GenerateRecommendations(metrics, nugetInfo, repoInfo);

        return new PackageHealth
        {
            PackageId = packageId,
            Version = version,
            Score = score,
            Status = status,
            CraScore = craScore,
            CraStatus = craStatus,
            Metrics = metrics,
            RepositoryUrl = repoInfo is not null ? $"https://github.com/{repoInfo.FullName}" : nugetInfo.RepositoryUrl,
            License = effectiveLicense,
            Vulnerabilities = activeVulnerabilities.Count > 0
                ? activeVulnerabilities.Select(v => v.Id).ToList()
                : [],
            Authors = nugetInfo.Authors,
            Recommendations = recommendations,
            Dependencies = nugetInfo.Dependencies,
            DependencyType = dependencyType,
            LatestVersion = nugetInfo.LatestVersion,
            PeerDependencies = [] // NuGet doesn't have peer dependencies concept
        };
    }

    /// <summary>
    /// Calculate health score and status for an npm package.
    /// </summary>
    public PackageHealth Calculate(
        string packageName,
        string version,
        NpmPackageInfo npmInfo,
        GitHubRepoInfo? repoInfo,
        List<VulnerabilityInfo> vulnerabilities,
        DependencyType dependencyType = DependencyType.Direct)
    {
        // Filter to only vulnerabilities that actually affect this version
        var activeVulnerabilities = FilterActiveVulnerabilities(version, vulnerabilities);

        // Apply license override if configured
        var effectiveLicense = GetEffectiveLicense(packageName, npmInfo.License);

        var metrics = BuildMetrics(npmInfo, repoInfo, activeVulnerabilities);
        var score = CalculateScore(metrics);
        var status = GetStatus(score);
        var (craScore, craStatus) = CalculateCraScore(activeVulnerabilities, effectiveLicense, packageName, version);
        var recommendations = GenerateRecommendations(metrics, npmInfo, repoInfo);

        // Convert npm dependencies to PackageDependency format
        var dependencies = npmInfo.Dependencies
            .Select(d => new PackageDependency
            {
                PackageId = d.Key,
                VersionRange = d.Value
            })
            .ToList();

        return new PackageHealth
        {
            PackageId = packageName,
            Version = version,
            Score = score,
            Status = status,
            CraScore = craScore,
            CraStatus = craStatus,
            Metrics = metrics,
            RepositoryUrl = repoInfo is not null ? $"https://github.com/{repoInfo.FullName}" : npmInfo.RepositoryUrl,
            License = effectiveLicense,
            Vulnerabilities = activeVulnerabilities.Count > 0
                ? activeVulnerabilities.Select(v => v.Id).ToList()
                : [],
            Authors = GetNpmAuthors(packageName),
            Recommendations = recommendations,
            Dependencies = dependencies,
            DependencyType = dependencyType,
            Ecosystem = PackageEcosystem.Npm,
            LatestVersion = npmInfo.LatestVersion,
            PeerDependencies = npmInfo.PeerDependencies
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

        // Calculate days since last release, but only if we have a valid publish date
        // DateTime.MinValue or dates before 2000 indicate missing data
        int? daysSinceLastRelease = null;
        if (versions.Count > 0 && versions[0].PublishedDate > new DateTime(2000, 1, 1))
        {
            daysSinceLastRelease = (int)(DateTime.UtcNow - versions[0].PublishedDate).TotalDays;
        }

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

    private PackageMetrics BuildMetrics(
        NpmPackageInfo npmInfo,
        GitHubRepoInfo? repoInfo,
        List<VulnerabilityInfo> vulnerabilities)
    {
        var versions = npmInfo.Versions
            .Where(v => !v.IsDeprecated)
            .OrderByDescending(v => v.PublishedDate)
            .ToList();

        int? daysSinceLastRelease = null;
        if (versions.Count > 0 && versions[0].PublishedDate > new DateTime(2000, 1, 1))
        {
            daysSinceLastRelease = (int)(DateTime.UtcNow - versions[0].PublishedDate).TotalDays;
        }

        var releasesPerYear = CalculateNpmReleasesPerYear(versions);

        // Estimate annual downloads from weekly downloads
        var estimatedAnnualDownloads = npmInfo.WeeklyDownloads * 52;

        return new PackageMetrics
        {
            DaysSinceLastRelease = daysSinceLastRelease,
            ReleasesPerYear = releasesPerYear,
            DownloadTrend = 0, // npm API doesn't provide historical download data for trend
            TotalDownloads = estimatedAnnualDownloads,
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

    private static double CalculateNpmReleasesPerYear(List<NpmVersionInfo> versions)
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

    /// <summary>
    /// Calculate CRA compliance score based on regulatory requirements.
    /// Focuses on: vulnerabilities, license identification, package identifiability.
    /// </summary>
    private static (int Score, CraComplianceStatus Status) CalculateCraScore(
        List<VulnerabilityInfo> vulnerabilities,
        string? license,
        string packageId,
        string version)
    {
        // CRA compliance scoring:
        // - No vulnerabilities: 60 points (critical requirement)
        // - License identified: 25 points (Article 10(9))
        // - Package identifiable (name + version): 15 points (Article 10 SBOM)

        var score = 0;

        // Vulnerability assessment (60 points max)
        // CRA Article 11 - Vulnerability handling
        var criticalVulns = vulnerabilities.Count(v =>
            v.Severity?.Equals("CRITICAL", StringComparison.OrdinalIgnoreCase) == true);
        var highVulns = vulnerabilities.Count(v =>
            v.Severity?.Equals("HIGH", StringComparison.OrdinalIgnoreCase) == true);
        var otherVulns = vulnerabilities.Count - criticalVulns - highVulns;

        if (vulnerabilities.Count == 0)
        {
            score += 60;
        }
        else if (criticalVulns > 0)
        {
            score += 0; // Critical vulns = 0 points for this section
        }
        else if (highVulns > 0)
        {
            score += 15; // High vulns = partial credit
        }
        else
        {
            score += 30; // Only low/medium vulns = more credit
        }

        // License identification (25 points max)
        // CRA Article 10(9) - License information
        if (!string.IsNullOrWhiteSpace(license))
        {
            var normalizedLicense = license.Trim().ToUpperInvariant();
            // Well-known SPDX licenses get full credit
            if (IsKnownSpdxLicense(normalizedLicense))
            {
                score += 25;
            }
            else
            {
                // Some license info, but not standard SPDX
                score += 15;
            }
        }
        // No license = 0 points for this section

        // Package identifiability (15 points max)
        // CRA Article 10 - SBOM requirements
        if (!string.IsNullOrWhiteSpace(packageId) && !string.IsNullOrWhiteSpace(version))
        {
            score += 15;
        }
        else if (!string.IsNullOrWhiteSpace(packageId))
        {
            score += 10; // Name but no version
        }

        // Determine status
        var status = (score, criticalVulns, highVulns) switch
        {
            ( >= 90, 0, 0) => CraComplianceStatus.Compliant,
            ( >= 70, 0, _) => CraComplianceStatus.Review,
            (_, > 0, _) => CraComplianceStatus.NonCompliant, // Critical vulns
            (_, _, > 0) => CraComplianceStatus.ActionRequired, // High vulns
            ( < 50, _, _) => CraComplianceStatus.NonCompliant,
            _ => CraComplianceStatus.ActionRequired
        };

        return (score, status);
    }

    private static bool IsKnownSpdxLicense(string license)
    {
        // Handle SPDX expressions with OR/AND/WITH operators
        // e.g., "(MIT OR Apache-2.0)", "GPL-3.0 WITH Classpath-exception-2.0"
        var normalized = license.Trim().TrimStart('(').TrimEnd(')').Trim();

        // Split on OR, AND, WITH and check each part
        var separators = new[] { " OR ", " AND ", " WITH " };
        var parts = normalized.Split(separators, StringSplitOptions.RemoveEmptyEntries);

        // If we have multiple parts, check if all license parts are known
        if (parts.Length > 1)
        {
            return parts.All(p => IsKnownSingleLicense(p.Trim().TrimStart('(').TrimEnd(')').Trim().ToUpperInvariant()));
        }

        return IsKnownSingleLicense(normalized);
    }

    private static bool IsKnownSingleLicense(string license)
    {
        // Common SPDX license identifiers
        return license switch
        {
            "MIT" or "MIT-0" => true,
            "APACHE-2.0" or "APACHE 2.0" or "APACHE2" => true,
            "BSD-2-CLAUSE" or "BSD-3-CLAUSE" or "0BSD" => true,
            "ISC" => true,
            "GPL-2.0" or "GPL-3.0" or "GPL-2.0-ONLY" or "GPL-3.0-ONLY" or "GPL-2.0-OR-LATER" or "GPL-3.0-OR-LATER" => true,
            "LGPL-2.1" or "LGPL-3.0" or "LGPL-2.1-ONLY" or "LGPL-3.0-ONLY" or "LGPL-2.1-OR-LATER" or "LGPL-3.0-OR-LATER" => true,
            "MPL-2.0" => true,
            "UNLICENSE" or "UNLICENSED" => true,
            "CC0-1.0" or "CC-BY-4.0" => true,
            "BSL-1.0" => true,
            "WTFPL" => true,
            "ZLIB" => true,
            "MS-PL" or "MS-RL" => true,
            // WITH exceptions (these come after "WITH" in expressions)
            "CLASSPATH-EXCEPTION-2.0" or "LLVM-EXCEPTION" => true,
            _ => false
        };
    }

    private static double CalculateFreshnessScore(int? daysSinceLastRelease)
    {
        // If release date is unknown, give a neutral score
        if (!daysSinceLastRelease.HasValue)
            return 60; // "Watch" level - unknown doesn't mean bad

        // 100 if released within 30 days, decreasing thereafter
        return daysSinceLastRelease.Value switch
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

    /// <summary>
    /// Filter vulnerabilities to only those that actually affect the given version.
    /// </summary>
    private static List<VulnerabilityInfo> FilterActiveVulnerabilities(string version, List<VulnerabilityInfo> vulnerabilities)
    {
        if (vulnerabilities.Count == 0) return [];

        var active = new List<VulnerabilityInfo>();
        foreach (var vuln in vulnerabilities)
        {
            // FIRST check if version is in vulnerable range
            bool inVulnerableRange;
            if (!string.IsNullOrEmpty(vuln.VulnerableVersionRange))
            {
                inVulnerableRange = IsVersionInVulnerableRange(version, vuln.VulnerableVersionRange);
            }
            else
            {
                // No range specified, conservatively assume vulnerable
                inVulnerableRange = true;
            }

            if (!inVulnerableRange)
            {
                continue; // Not in vulnerable range, skip
            }

            // THEN check if version is patched (only matters if we're in the vulnerable range)
            if (!string.IsNullOrEmpty(vuln.PatchedVersion))
            {
                try
                {
                    var current = NuGet.Versioning.NuGetVersion.Parse(version);
                    var patched = NuGet.Versioning.NuGetVersion.Parse(vuln.PatchedVersion);
                    if (current >= patched)
                    {
                        continue; // Patched in current version
                    }
                }
                catch { /* Version parsing failed, assume still vulnerable */ }
            }

            // Version is in vulnerable range and not patched
            active.Add(vuln);
        }

        return active;
    }

    private static bool IsVersionInVulnerableRange(string version, string range)
    {
        try
        {
            var current = NuGet.Versioning.NuGetVersion.Parse(version);
            var parts = range.Split(',').Select(p => p.Trim()).ToArray();

            // Track whether we have any range constraints
            bool hasRangeConstraint = false;
            bool hasExactMatch = false;

            foreach (var part in parts)
            {
                if (part.StartsWith(">="))
                {
                    hasRangeConstraint = true;
                    var v = NuGet.Versioning.NuGetVersion.Parse(part[2..].Trim());
                    if (current < v) return false;
                }
                else if (part.StartsWith(">"))
                {
                    hasRangeConstraint = true;
                    var v = NuGet.Versioning.NuGetVersion.Parse(part[1..].Trim());
                    if (current <= v) return false;
                }
                else if (part.StartsWith("<="))
                {
                    hasRangeConstraint = true;
                    var v = NuGet.Versioning.NuGetVersion.Parse(part[2..].Trim());
                    if (current > v) return false;
                }
                else if (part.StartsWith("<"))
                {
                    hasRangeConstraint = true;
                    var v = NuGet.Versioning.NuGetVersion.Parse(part[1..].Trim());
                    if (current >= v) return false;
                }
                else if (!string.IsNullOrWhiteSpace(part))
                {
                    // Exact version match (e.g., "4.4.2" from OSV's versions list)
                    try
                    {
                        var v = NuGet.Versioning.NuGetVersion.Parse(part);
                        if (current == v)
                        {
                            hasExactMatch = true;
                        }
                    }
                    catch
                    {
                        // Not a parseable version, ignore
                    }
                }
            }

            // If we only have exact version matches, check if current matches any
            if (!hasRangeConstraint)
            {
                return hasExactMatch;
            }

            // Range constraints passed
            return true;
        }
        catch
        {
            // If we can't parse, assume affected (conservative for security)
            // May result in false positives - user should verify
            return true;
        }
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

        if (metrics.DaysSinceLastRelease.HasValue && metrics.DaysSinceLastRelease > 730)
        {
            recommendations.Add("No releases in 2+ years - consider alternatives");
        }
        else if (!metrics.DaysSinceLastRelease.HasValue)
        {
            recommendations.Add("Release date unknown - verify package is actively maintained");
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

    private static List<string> GenerateRecommendations(
        PackageMetrics metrics,
        NpmPackageInfo npmInfo,
        GitHubRepoInfo? repoInfo)
    {
        var recommendations = new List<string>();

        if (npmInfo.IsDeprecated)
        {
            recommendations.Add($"Package is deprecated: {npmInfo.DeprecationMessage ?? "No reason provided"}");
        }

        if (metrics.DaysSinceLastRelease.HasValue && metrics.DaysSinceLastRelease > 730)
        {
            recommendations.Add("No releases in 2+ years - consider alternatives");
        }
        else if (!metrics.DaysSinceLastRelease.HasValue)
        {
            recommendations.Add("Release date unknown - verify package is actively maintained");
        }

        if (metrics.VulnerabilityCount > 0)
        {
            recommendations.Add($"{metrics.VulnerabilityCount} known vulnerabilities - update or replace urgently");
        }

        if (repoInfo?.IsArchived == true)
        {
            recommendations.Add("Repository is archived - package is no longer maintained");
        }

        if (metrics.DaysSinceLastCommit > 365)
        {
            recommendations.Add("No repository activity in over a year");
        }

        // npm-specific: check for peer dependency warnings
        if (npmInfo.PeerDependencies.Count > 0)
        {
            recommendations.Add($"Has {npmInfo.PeerDependencies.Count} peer dependencies - ensure compatibility");
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
