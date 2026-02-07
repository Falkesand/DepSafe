using DepSafe.DataSources;
using DepSafe.Models;
using DepSafe.Scoring;

namespace DepSafe.Compliance;

/// <summary>
/// Analyzes vulnerabilities for CRA Art. 14 reporting obligations.
/// Detects vulnerabilities requiring CSIRT notification based on active exploitation
/// (CISA KEV) or high exploitation probability (EPSS >= 0.5).
/// Only considers vulnerabilities that actually affect the installed package version.
/// </summary>
public static class ReportingObligationAnalyzer
{
    private const double EpssReportingThreshold = 0.5;

    private static readonly string[] s_severityOrder = ["CRITICAL", "HIGH", "MODERATE", "MEDIUM", "LOW"];

    /// <summary>
    /// Analyze packages for CRA Art. 14 reporting obligations.
    /// </summary>
    /// <param name="allPackages">All packages (direct + transitive) with health data.</param>
    /// <param name="allVulnerabilities">Vulnerability data keyed by package ID.</param>
    /// <param name="kevCves">Set of CVE IDs in the CISA KEV catalog.</param>
    /// <param name="epssScores">EPSS scores keyed by CVE ID.</param>
    /// <returns>Reportable obligations sorted by severity (critical first).</returns>
    public static List<ReportingObligation> Analyze(
        IReadOnlyList<PackageHealth> allPackages,
        IReadOnlyDictionary<string, List<VulnerabilityInfo>> allVulnerabilities,
        IReadOnlySet<string> kevCves,
        IReadOnlyDictionary<string, EpssScore> epssScores)
    {
        var obligations = new List<ReportingObligation>();

        foreach (var pkg in allPackages)
        {
            if (!allVulnerabilities.TryGetValue(pkg.PackageId, out var vulns))
                continue;

            // Collect CVEs that trigger reporting for this package
            var reportableCves = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            bool hasKev = false;
            double maxEpss = 0.0;
            int highestRank = s_severityOrder.Length - 1; // index of LOW
            DateTime? earliestPublished = null;

            foreach (var vuln in vulns)
            {
                // Skip vulnerabilities that don't affect the installed version
                if (!HealthScoreCalculator.IsAffected(pkg.Version, vuln))
                    continue;

                foreach (var cve in vuln.Cves)
                {
                    bool cveIsKev = kevCves.Contains(cve);
                    double cveEpss = epssScores.TryGetValue(cve, out var score) ? score.Probability : 0.0;

                    if (!cveIsKev && cveEpss < EpssReportingThreshold)
                        continue;

                    reportableCves.Add(cve);
                    if (cveIsKev) hasKev = true;
                    if (cveEpss > maxEpss) maxEpss = cveEpss;

                    // Track highest severity
                    int vulnRank = FindSeverityIndex(vuln.Severity);
                    if (vulnRank >= 0 && vulnRank < highestRank)
                        highestRank = vulnRank;
                }

                // Track earliest published date (only for affected vulns)
                if (vuln.PublishedAt.HasValue && (!earliestPublished.HasValue || vuln.PublishedAt.Value < earliestPublished.Value))
                    earliestPublished = vuln.PublishedAt;
            }

            if (reportableCves.Count == 0)
                continue;

            var highestSeverity = s_severityOrder[highestRank];

            var trigger = (hasKev, maxEpss >= EpssReportingThreshold) switch
            {
                (true, true) => ReportingTrigger.Both,
                (true, false) => ReportingTrigger.KevExploitation,
                _ => ReportingTrigger.HighEpss
            };

            obligations.Add(new ReportingObligation
            {
                PackageId = pkg.PackageId,
                Version = pkg.Version,
                CveIds = reportableCves.ToList(),
                Severity = highestSeverity,
                Trigger = trigger,
                DiscoveryDate = earliestPublished ?? DateTime.UtcNow,
                EpssProbability = maxEpss > 0 ? maxEpss : null,
                IsKevVulnerability = hasKev
            });
        }

        // Sort by severity: Critical > High > Medium > Low, then by trigger (Both > KEV > EPSS)
        obligations.Sort((a, b) =>
        {
            int aSev = FindSeverityIndex(a.Severity);
            int bSev = FindSeverityIndex(b.Severity);
            if (aSev < 0) aSev = s_severityOrder.Length;
            if (bSev < 0) bSev = s_severityOrder.Length;
            int cmp = aSev.CompareTo(bSev);
            if (cmp != 0) return cmp;
            return b.Trigger.CompareTo(a.Trigger); // Both > KEV > EPSS
        });

        return obligations;
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
}
