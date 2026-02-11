using DepSafe.Compliance;
using DepSafe.Models;
using NuGet.Versioning;

namespace DepSafe.Scoring;

/// <summary>
/// Ranks vulnerable packages by CRA compliance impact to produce a prioritized remediation roadmap.
/// Only considers vulnerabilities that actually affect the installed package version.
/// </summary>
public static class RemediationPrioritizer
{
    private const int MaxItems = 20;
    private static readonly string[] s_severityOrder = ["CRITICAL", "HIGH", "MODERATE", "MEDIUM", "LOW"];

    /// <summary>
    /// Prioritize package updates by CRA score improvement potential.
    /// </summary>
    /// <param name="allPackages">All packages with health data.</param>
    /// <param name="allVulnerabilities">Vulnerability data keyed by package ID.</param>
    /// <param name="currentCraScore">Current CRA readiness score for baseline comparison.</param>
    /// <param name="currentComplianceItems">Current compliance items for score simulation.</param>
    /// <returns>Top 20 prioritized remediation items.</returns>
    public static List<RemediationRoadmapItem> PrioritizeUpdates(
        IReadOnlyList<PackageHealth> allPackages,
        IReadOnlyDictionary<string, List<VulnerabilityInfo>> allVulnerabilities,
        int currentCraScore,
        List<CraComplianceItem> currentComplianceItems,
        IReadOnlyDictionary<string, List<string>>? availableVersions = null)
    {
        var items = new List<RemediationRoadmapItem>(Math.Min(allPackages.Count, MaxItems));

        foreach (var pkg in allPackages)
        {
            if (!allVulnerabilities.TryGetValue(pkg.PackageId, out var vulns) || vulns.Count == 0)
                continue;

            // Collect CVEs only from vulnerabilities that actually affect the installed version
            var allCves = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var affectedVulns = new List<VulnerabilityInfo>(vulns.Count);
            string? recommendedVersion = null;
            int maxPatchAgeDays = 0;
            double maxEpss = 0.0;

            foreach (var vuln in vulns)
            {
                // Skip vulnerabilities that don't affect the installed version
                if (!HealthScoreCalculator.IsAffected(pkg.Version, vuln))
                    continue;

                affectedVulns.Add(vuln);

                foreach (var cve in vuln.Cves)
                    allCves.Add(cve);

                // Use PatchedVersion if available, otherwise fall back to LatestVersion
                if (!string.IsNullOrEmpty(vuln.PatchedVersion))
                {
                    if (recommendedVersion is null)
                    {
                        recommendedVersion = vuln.PatchedVersion;
                    }
                    else if (NuGetVersion.TryParse(vuln.PatchedVersion, out var pv) &&
                             NuGetVersion.TryParse(recommendedVersion, out var rv) &&
                             pv > rv)
                    {
                        recommendedVersion = vuln.PatchedVersion;
                    }
                }

                if (vuln.PublishedAt.HasValue)
                {
                    int days = (int)(DateTime.UtcNow - vuln.PublishedAt.Value).TotalDays;
                    if (days > maxPatchAgeDays)
                        maxPatchAgeDays = days;
                }

                if (vuln.EpssProbability.HasValue && vuln.EpssProbability.Value > maxEpss)
                    maxEpss = vuln.EpssProbability.Value;
            }

            // Fallback to package's LatestVersion
            recommendedVersion ??= pkg.LatestVersion ?? pkg.Version;

            if (allCves.Count == 0)
                continue;

            // Determine upgrade effort
            var effort = DetermineEffort(pkg.Version, recommendedVersion);

            // Simulate score lift using only affected vulnerabilities
            int scoreLift = EstimateScoreLift(pkg, affectedVulns, currentCraScore, currentComplianceItems);

            // Priority scoring
            int priority = 0;
            if (pkg.HasKevVulnerability) priority += 10000;
            if (maxEpss >= 0.5) priority += 5000;

            var highestSeverity = GetHighestSeverity(affectedVulns);
            priority += highestSeverity switch
            {
                "CRITICAL" => 500,
                "HIGH" => 250,
                "MODERATE" or "MEDIUM" => 100,
                _ => 25
            };
            priority += scoreLift * 10;

            // Compute upgrade tiers if version list is available
            List<UpgradeTier> upgradeTiers = [];
            if (availableVersions is not null &&
                availableVersions.TryGetValue(pkg.PackageId, out var versionList) &&
                versionList.Count > 0)
            {
                upgradeTiers = ComputeUpgradeTiers(pkg.Version, affectedVulns, versionList);
            }

            items.Add(new RemediationRoadmapItem
            {
                PackageId = pkg.PackageId,
                CurrentVersion = pkg.Version,
                RecommendedVersion = recommendedVersion,
                CveCount = allCves.Count,
                CveIds = allCves.ToList(),
                ScoreLift = scoreLift,
                Effort = effort,
                HasKevVulnerability = pkg.HasKevVulnerability,
                MaxEpssProbability = maxEpss,
                MaxPatchAgeDays = maxPatchAgeDays,
                PriorityScore = priority,
                UpgradeTiers = upgradeTiers,
            });
        }

        items.Sort((a, b) => b.PriorityScore.CompareTo(a.PriorityScore));
        return items.Count > MaxItems ? items.GetRange(0, MaxItems) : items;
    }

    private static UpgradeEffort DetermineEffort(string currentVersion, string recommendedVersion)
    {
        if (!NuGetVersion.TryParse(currentVersion, out var current) ||
            !NuGetVersion.TryParse(recommendedVersion, out var recommended))
            return UpgradeEffort.Major; // Can't parse — assume worst case

        if (recommended.Major != current.Major)
            return UpgradeEffort.Major;
        if (recommended.Minor != current.Minor)
            return UpgradeEffort.Minor;
        return UpgradeEffort.Patch;
    }

    private static int EstimateScoreLift(
        PackageHealth pkg,
        List<VulnerabilityInfo> vulns,
        int currentCraScore,
        List<CraComplianceItem> currentItems)
    {
        int vulnCount = vulns.Count;
        bool hasKev = pkg.HasKevVulnerability;
        bool hasHighEpss = pkg.MaxEpssProbability.HasValue && pkg.MaxEpssProbability.Value >= 0.5;

        // Start with a base lift proportional to vulnerability count
        int baseLift = Math.Min(vulnCount * 2, 10);

        // KEV and EPSS compliance items have high weight, so fixing them gives big lift
        if (hasKev) baseLift += 8;
        if (hasHighEpss) baseLift += 4;

        // Cap at reasonable maximum
        return Math.Min(baseLift, 25);
    }

    private static string GetHighestSeverity(List<VulnerabilityInfo> vulns)
    {
        int best = s_severityOrder.Length;
        foreach (var vuln in vulns)
        {
            int idx = FindSeverityIndex(vuln.Severity);
            if (idx >= 0 && idx < best) best = idx;
        }
        return best < s_severityOrder.Length ? s_severityOrder[best] : "LOW";
    }

    private static int FindSeverityIndex(string? severity)
    {
        for (int i = 0; i < s_severityOrder.Length; i++)
        {
            if (string.Equals(s_severityOrder[i], severity, StringComparison.OrdinalIgnoreCase))
                return i;
        }
        return -1;
    }

    /// <summary>
    /// Compute upgrade tiers for a vulnerable package by testing candidate versions against all affected CVEs.
    /// Returns distinct tiers ordered by effort (Patch -> Minor -> Major), deduplicated.
    /// </summary>
    private static List<UpgradeTier> ComputeUpgradeTiers(
        string currentVersion,
        List<VulnerabilityInfo> affectedVulns,
        List<string> candidateVersions)
    {
        if (!NuGetVersion.TryParse(currentVersion, out var current))
            return [];

        int totalCves = affectedVulns.SelectMany(v => v.Cves).Distinct(StringComparer.OrdinalIgnoreCase).Count();

        // Parse and filter candidates: must be > current, stable, parseable
        var candidates = new List<(NuGetVersion Parsed, string Raw)>();
        foreach (var ver in candidateVersions)
        {
            if (NuGetVersion.TryParse(ver, out var parsed) && parsed > current && !parsed.IsPrerelease)
                candidates.Add((parsed, ver));
        }

        candidates.Sort((a, b) => a.Parsed.CompareTo(b.Parsed));

        // For each tier, find the lowest version that fixes the most CVEs
        var tierBest = new Dictionary<UpgradeEffort, (string Version, int CvesFixed)>();

        foreach (var (parsed, raw) in candidates)
        {
            var effort = DetermineEffort(currentVersion, raw);

            // Count distinct CVEs fixed by this version
            var fixedCveIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var vuln in affectedVulns)
            {
                if (!HealthScoreCalculator.IsAffected(raw, vuln))
                {
                    foreach (var cve in vuln.Cves)
                        fixedCveIds.Add(cve);
                }
            }

            int cvesFixed = fixedCveIds.Count;
            if (cvesFixed == 0)
                continue;

            // Keep the LOWEST version per tier that fixes the MOST CVEs
            if (!tierBest.TryGetValue(effort, out var existing) || cvesFixed > existing.CvesFixed)
            {
                tierBest[effort] = (raw, cvesFixed);
            }
        }

        // Build tiers ordered by effort, dedup by version
        var tiers = new List<UpgradeTier>();
        var effortOrder = new[] { UpgradeEffort.Patch, UpgradeEffort.Minor, UpgradeEffort.Major };
        var seenVersions = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var effort in effortOrder)
        {
            if (tierBest.TryGetValue(effort, out var best) && seenVersions.Add(best.Version))
            {
                tiers.Add(new UpgradeTier(
                    TargetVersion: best.Version,
                    Effort: effort,
                    CvesFixed: best.CvesFixed,
                    TotalCves: totalCves,
                    IsRecommended: tiers.Count == 0));
            }
        }

        return tiers;
    }
}
