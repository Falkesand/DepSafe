using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using DepSafe.DataSources;
using DepSafe.Models;

namespace DepSafe.Compliance;

/// <summary>
/// Generates comprehensive CRA compliance reports combining SBOM, VEX, and health data.
/// </summary>
public sealed partial class CraReportGenerator
{
    private readonly SbomGenerator _sbomGenerator;
    private readonly VexGenerator _vexGenerator;

    // Compiled regex for parsing PURLs (used repeatedly in FormatPurlForSbom)
    [GeneratedRegex(@"pkg:nuget/([^@]+)", RegexOptions.Compiled)]
    private static partial Regex PurlRegex();

    // Static JsonSerializerOptions to avoid per-call allocations
    private static readonly JsonSerializerOptions CamelCaseOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase
    };

    public CraReportGenerator(SbomGenerator? sbomGenerator = null, VexGenerator? vexGenerator = null)
    {
        _sbomGenerator = sbomGenerator ?? new SbomGenerator();
        _vexGenerator = vexGenerator ?? new VexGenerator();
    }

    /// <summary>
    /// Generate complete CRA compliance report.
    /// </summary>
    /// <param name="healthReport">The health report data.</param>
    /// <param name="vulnerabilities">Vulnerability data by package.</param>
    /// <param name="startTime">Optional start time for calculating generation duration.</param>
    public CraReport Generate(
        ProjectReport healthReport,
        IReadOnlyDictionary<string, List<VulnerabilityInfo>> vulnerabilities,
        DateTime? startTime = null)
    {
        // Build reverse dependency lookup for "Required by" information
        BuildParentLookup();

        // Include both direct and transitive packages in SBOM for CRA compliance
        var allPackagesForSbom = healthReport.Packages.AsEnumerable();
        if (_transitiveDataCache is not null)
        {
            allPackagesForSbom = allPackagesForSbom.Concat(_transitiveDataCache);
        }

        var sbom = _sbomGenerator.Generate(healthReport.ProjectPath, allPackagesForSbom);

        // Apply package checksums from provenance data (extracted from NuGet registration API)
        if (_provenanceResults.Count > 0)
        {
            var hashLookup = _provenanceResults
                .Where(r => r.ContentHash is not null)
                .ToDictionary(r => r.PackageId, r => r, StringComparer.OrdinalIgnoreCase);

            foreach (var pkg in sbom.Packages)
            {
                if (hashLookup.TryGetValue(pkg.Name, out var prov))
                {
                    pkg.Checksums =
                    [
                        new SbomChecksum
                        {
                            Algorithm = prov.ContentHashAlgorithm ?? "SHA512",
                            ChecksumValue = prov.ContentHash!
                        }
                    ];
                }
            }
        }

        // VEX should include both direct and transitive packages for proper vulnerability counting
        var vex = _vexGenerator.Generate(allPackagesForSbom, vulnerabilities);

        var complianceItems = new List<CraComplianceItem>();

        // Vulnerability documentation - only count ACTIVE vulnerabilities (affecting current versions)
        var activeVulnCount = vex.Statements.Count(s => s.Status == VexStatus.Affected);
        var fixedVulnCount = vex.Statements.Count(s => s.Status == VexStatus.Fixed);
        var totalVulnStatements = vex.Statements.Count;

        // ============================================
        // CRA ARTICLE 10 - Product Requirements
        // ============================================

        // Art. 10 - SBOM
        complianceItems.Add(new CraComplianceItem
        {
            Requirement = "CRA Art. 10 - Software Bill of Materials",
            Description = "Machine-readable inventory of software components",
            Status = sbom.Packages.Count > 0 ? CraComplianceStatus.Compliant : CraComplianceStatus.NonCompliant,
            Evidence = $"SBOM generated with {sbom.Packages.Count} components in SPDX 3.0 format",
            Recommendation = null
        });

        // Art. 10(4) - No known exploitable vulnerabilities (CISA KEV)
        var kevCount = _kevCvePackages.Count;
        var kevEvidence = kevCount == 0
            ? "No CVEs found in CISA Known Exploited Vulnerabilities catalog"
            : string.Join("; ", _kevCvePackages.Take(5).Select(k => $"{k.Cve} in {k.PackageId}")) + (kevCount > 5 ? "; ..." : "");
        complianceItems.Add(new CraComplianceItem
        {
            Requirement = "CRA Art. 10(4) - Exploited Vulnerabilities (CISA KEV)",
            Description = kevCount == 0
                ? "No known actively exploited vulnerabilities"
                : $"{kevCount} actively exploited vulnerability(ies) detected",
            Status = kevCount == 0 ? CraComplianceStatus.Compliant : CraComplianceStatus.NonCompliant,
            Evidence = kevEvidence,
            Recommendation = kevCount > 0
                ? "CRITICAL: Update packages with actively exploited vulnerabilities immediately"
                : null
        });

        // Art. 10(4) - Exploit Probability (EPSS)
        var highEpssPackages = (_healthDataCache ?? []).Concat(_transitiveDataCache ?? [])
            .Where(p => p.MaxEpssProbability >= 0.1)
            .OrderByDescending(p => p.MaxEpssProbability)
            .ToList();
        var epssEvidence = highEpssPackages.Count == 0
            ? "No packages with high exploit probability (EPSS >= 10%)"
            : string.Join("; ", highEpssPackages.Take(5).Select(p => $"{p.PackageId} ({p.MaxEpssProbability * 100:F1}%)")) + (highEpssPackages.Count > 5 ? "; ..." : "");
        complianceItems.Add(new CraComplianceItem
        {
            Requirement = "CRA Art. 10(4) - Exploit Probability (EPSS)",
            Description = highEpssPackages.Count == 0
                ? "No packages with high exploit probability"
                : $"{highEpssPackages.Count} package(s) with EPSS >= 10% (likely to be exploited)",
            Status = highEpssPackages.Count == 0 ? CraComplianceStatus.Compliant : CraComplianceStatus.ActionRequired,
            Evidence = epssEvidence,
            Recommendation = highEpssPackages.Count > 0
                ? "Prioritize patching packages with high EPSS scores - these vulnerabilities are likely to be exploited"
                : null
        });

        // Art. 10(6) - Security Updates (data-driven using repo maintenance data)
        {
            var archivedCount = _archivedPackageNames.Count;
            var staleCount = _stalePackageNames.Count;
            var stalePercent = _totalWithRepoData > 0 ? (int)Math.Round(100.0 * staleCount / _totalWithRepoData) : 0;
            var updateStatus = archivedCount == 0 && stalePercent <= 10
                ? CraComplianceStatus.Compliant
                : CraComplianceStatus.ActionRequired;

            var evidence = _totalWithRepoData > 0
                ? $"{_totalWithRepoData} packages with repo data analyzed. " +
                  (archivedCount > 0 ? $"{archivedCount} archived: {string.Join(", ", _archivedPackageNames.Take(3))}{(archivedCount > 3 ? "..." : "")}. " : "") +
                  (staleCount > 0 ? $"{staleCount} stale (no commits >365 days, {stalePercent}%): {string.Join(", ", _stalePackageNames.Take(3))}{(staleCount > 3 ? "..." : "")}" : "All packages actively maintained.")
                : $"SBOM tracks {sbom.Packages.Count} components. VEX documents {totalVulnStatements} vulnerability assessments.";

            complianceItems.Add(new CraComplianceItem
            {
                Requirement = "CRA Art. 10(6) - Security Updates",
                Description = "Mechanism to ensure timely security updates",
                Status = updateStatus,
                Evidence = evidence,
                Recommendation = updateStatus != CraComplianceStatus.Compliant
                    ? "Replace archived packages and evaluate alternatives for stale dependencies"
                    : null
            });
        }

        // Art. 10(9) - License Information
        var noLicensePackages = healthReport.Packages.Count(p =>
            string.IsNullOrEmpty(p.License) || p.License == "NOASSERTION");
        complianceItems.Add(new CraComplianceItem
        {
            Requirement = "CRA Art. 10(9) - License Information",
            Description = "License information for all components",
            Status = noLicensePackages == 0 ? CraComplianceStatus.Compliant :
                noLicensePackages > healthReport.Packages.Count / 4 ?
                    CraComplianceStatus.ActionRequired : CraComplianceStatus.Compliant,
            Evidence = $"{healthReport.Packages.Count - noLicensePackages} of {healthReport.Packages.Count} packages have license information",
            Recommendation = noLicensePackages > 0
                ? "Investigate and document licenses for packages without license information"
                : null
        });

        // Art. 10 - Deprecated Components
        complianceItems.Add(new CraComplianceItem
        {
            Requirement = "CRA Art. 10 - No Deprecated Components",
            Description = "Components should not be deprecated or abandoned",
            Status = _deprecatedPackageCount == 0 ? CraComplianceStatus.Compliant :
                _deprecatedPackageCount > 2 ? CraComplianceStatus.ActionRequired : CraComplianceStatus.Review,
            Evidence = _deprecatedPackageCount == 0
                ? "No deprecated packages found"
                : $"{_deprecatedPackageCount} deprecated package(s): {string.Join(", ", _deprecatedPackages.Take(3))}{(_deprecatedPackageCount > 3 ? "..." : "")}",
            Recommendation = _deprecatedPackageCount > 0
                ? "Replace deprecated packages with maintained alternatives"
                : null
        });

        // Art. 10 - Cryptographic Compliance
        var cryptoIssueCount = _cryptoCompliance?.Issues.Count ?? 0;
        complianceItems.Add(new CraComplianceItem
        {
            Requirement = "CRA Art. 10 - Cryptographic Compliance",
            Description = "No deprecated cryptographic algorithms or libraries",
            Status = cryptoIssueCount == 0 ? CraComplianceStatus.Compliant : CraComplianceStatus.Review,
            Evidence = cryptoIssueCount == 0
                ? $"No deprecated crypto libraries. {_cryptoCompliance?.CryptoPackagesFound.Count ?? 0} crypto-related packages reviewed."
                : $"{cryptoIssueCount} potential crypto issue(s) found",
            Recommendation = cryptoIssueCount > 0
                ? "Review flagged cryptographic packages for compliance"
                : null
        });

        // Art. 10 - Supply Chain Integrity (Typosquatting)
        if (_typosquatChecked)
        {
            var typosquatCount = _typosquatResults.Count;
            var highRiskCount = _typosquatResults.Count(r => r.RiskLevel >= TyposquatRiskLevel.High);
            complianceItems.Add(new CraComplianceItem
            {
                Requirement = "CRA Art. 10 - Supply Chain Integrity",
                Description = "Dependencies verified against known package typosquatting attacks",
                Status = typosquatCount == 0 ? CraComplianceStatus.Compliant :
                    highRiskCount > 0 ? CraComplianceStatus.ActionRequired : CraComplianceStatus.Review,
                Evidence = typosquatCount == 0
                    ? "No potential typosquatting issues detected in project dependencies"
                    : $"{typosquatCount} potential typosquatting issue(s) found ({highRiskCount} high/critical risk)",
                Recommendation = typosquatCount > 0
                    ? "Verify flagged dependencies are legitimate packages and not typosquatting attacks"
                    : null
            });
        }

        // ============================================
        // CRA ARTICLE 11 - Vulnerability Handling
        // ============================================

        // Art. 11 - Vulnerability Handling
        complianceItems.Add(new CraComplianceItem
        {
            Requirement = "CRA Art. 11 - Vulnerability Handling",
            Description = "Documentation of known vulnerabilities and their status",
            Status = activeVulnCount == 0 ? CraComplianceStatus.Compliant : CraComplianceStatus.ActionRequired,
            Evidence = activeVulnCount == 0
                ? $"No active vulnerabilities. {fixedVulnCount} vulnerabilities addressed in current versions."
                : $"{activeVulnCount} active vulnerabilities require attention. {fixedVulnCount} already addressed.",
            Recommendation = activeVulnCount > 0
                ? "Update affected packages to patched versions"
                : null
        });

        // Art. 11(5) - Coordinated Vulnerability Disclosure (Security Policy)
        var totalPackageCount = healthReport.Packages.Count + (_transitiveDataCache?.Count ?? 0);
        var securityPolicyPercent = _totalPackagesWithRepo > 0
            ? (int)Math.Round(100.0 * _packagesWithSecurityPolicy / _totalPackagesWithRepo)
            : 0;
        var coveragePercent = totalPackageCount > 0
            ? (int)Math.Round(100.0 * _totalPackagesWithRepo / totalPackageCount)
            : 0;
        complianceItems.Add(new CraComplianceItem
        {
            Requirement = "CRA Art. 11(5) - Security Policy",
            Description = "Coordinated vulnerability disclosure policy (SECURITY.md)",
            Status = securityPolicyPercent >= 50 ? CraComplianceStatus.Compliant :
                securityPolicyPercent >= 25 ? CraComplianceStatus.Review : CraComplianceStatus.ActionRequired,
            Evidence = _totalPackagesWithRepo > 0
                ? $"{_packagesWithSecurityPolicy} of {_totalPackagesWithRepo} packages with GitHub repos have SECURITY.md ({securityPolicyPercent}%)" +
                  (coveragePercent < 50 ? $". Note: Only {_totalPackagesWithRepo} of {totalPackageCount} packages ({coveragePercent}%) have GitHub repo data. Use -d flag for full coverage." : "")
                : "No packages with GitHub repositories to check",
            Recommendation = securityPolicyPercent < 50
                ? "Consider using packages with documented security policies"
                : null
        });

        // ============================================
        // CRA ARTICLE 13 - Obligations of Manufacturers
        // ============================================

        // Art. 13(8) - Support Period / Active Maintenance
        {
            var unmaintainedCount = _unmaintainedPackageNames.Count;
            var supportStatus = unmaintainedCount == 0 ? CraComplianceStatus.Compliant :
                unmaintainedCount <= 2 ? CraComplianceStatus.Review : CraComplianceStatus.ActionRequired;
            var supportEvidence = unmaintainedCount == 0
                ? "All packages with repository data show active maintenance"
                : $"{unmaintainedCount} package(s) may lack ongoing support: {string.Join(", ", _unmaintainedPackageNames.Take(5))}{(unmaintainedCount > 5 ? "..." : "")}";

            complianceItems.Add(new CraComplianceItem
            {
                Requirement = "CRA Art. 13(8) - Support Period",
                Description = "Components must have ongoing support (active maintenance)",
                Status = supportStatus,
                Evidence = supportEvidence,
                Recommendation = unmaintainedCount > 0
                    ? "Evaluate unmaintained dependencies and plan migration to actively supported alternatives"
                    : null
            });
        }

        // Art. 13(5) - Package Provenance
        if (_provenanceResults.Count > 0)
        {
            var verifiedCount = _provenanceResults.Count(r => r.IsVerified);
            var totalCount = _provenanceResults.Count;
            var verifiedPercent = totalCount > 0 ? (int)Math.Round(100.0 * verifiedCount / totalCount) : 0;
            complianceItems.Add(new CraComplianceItem
            {
                Requirement = "CRA Art. 13(5) - Package Provenance",
                Description = "Due diligence when integrating third-party components (signature verification)",
                Status = verifiedPercent >= 90 ? CraComplianceStatus.Compliant :
                    verifiedPercent >= 50 ? CraComplianceStatus.Review : CraComplianceStatus.ActionRequired,
                Evidence = $"{verifiedCount} of {totalCount} packages ({verifiedPercent}%) have verified provenance (repository signature)",
                Recommendation = verifiedPercent < 90
                    ? "Investigate unsigned packages and verify their provenance through alternative means"
                    : null
            });
        }

        // ============================================
        // CRA ANNEX I - Essential Cybersecurity Requirements
        // ============================================

        // Annex I Part I(1) - Release Readiness (no known exploitable vulnerabilities)
        {
            var kevReady = kevCount == 0;
            var vulnReady = activeVulnCount == 0;
            var readinessStatus = kevReady && vulnReady ? CraComplianceStatus.Compliant :
                !kevReady ? CraComplianceStatus.NonCompliant : CraComplianceStatus.ActionRequired;
            complianceItems.Add(new CraComplianceItem
            {
                Requirement = "CRA Annex I Part I(1) - Release Readiness",
                Description = "Products must ship without known exploitable vulnerabilities",
                Status = readinessStatus,
                Evidence = kevReady && vulnReady
                    ? "No known exploitable vulnerabilities in dependencies"
                    : $"{kevCount} CISA KEV vulnerabilities, {activeVulnCount} active advisories",
                Recommendation = readinessStatus != CraComplianceStatus.Compliant
                    ? "Resolve all known vulnerabilities before release, prioritizing CISA KEV entries"
                    : null
            });
        }

        // Annex I Part I(10) - Attack Surface Minimization
        if (_attackSurface is not null)
        {
            var ratio = _attackSurface.TransitiveToDirectRatio;
            var depth = _attackSurface.MaxDepth;
            var heavyCount = _attackSurface.HeavyPackages.Count;
            var surfaceStatus = ratio < 5.0 && depth < 8
                ? CraComplianceStatus.Compliant
                : ratio >= 10.0 || depth >= 12
                    ? CraComplianceStatus.ActionRequired
                    : CraComplianceStatus.Review;

            var evidence = $"Transitive-to-direct ratio: {ratio}:1, max depth: {depth}";
            if (heavyCount > 0)
            {
                evidence += $", {heavyCount} heavy package(s): {string.Join(", ", _attackSurface.HeavyPackages.Take(3).Select(h => $"{h.PackageId} ({h.TransitiveCount} deps)"))}";
            }

            complianceItems.Add(new CraComplianceItem
            {
                Requirement = "CRA Annex I Part I(10) - Attack Surface",
                Description = "Minimize attack surface including external interfaces and dependencies",
                Status = surfaceStatus,
                Evidence = evidence,
                Recommendation = surfaceStatus != CraComplianceStatus.Compliant
                    ? "Review dependency tree depth and consider replacing heavy packages with lighter alternatives"
                    : null
            });
        }

        // Annex I Part II(1) - SBOM Completeness (BSI TR-03183-2)
        if (_sbomValidation is not null)
        {
            var completeness = _sbomValidation.CompletenessPercent;
            var sbomStatus = completeness >= 90 ? CraComplianceStatus.Compliant :
                completeness >= 70 ? CraComplianceStatus.Review : CraComplianceStatus.ActionRequired;

            var missing = new List<string>();
            if (!_sbomValidation.HasTimestamp) missing.Add("timestamp");
            if (!_sbomValidation.HasCreator) missing.Add("creator");
            if (_sbomValidation.TotalPackages > 0)
            {
                if (_sbomValidation.WithSupplier < _sbomValidation.TotalPackages) missing.Add($"supplier ({_sbomValidation.WithSupplier}/{_sbomValidation.TotalPackages})");
                if (_sbomValidation.WithPurl < _sbomValidation.TotalPackages) missing.Add($"PURL ({_sbomValidation.WithPurl}/{_sbomValidation.TotalPackages})");
                if (_sbomValidation.WithChecksum < _sbomValidation.TotalPackages) missing.Add($"checksum ({_sbomValidation.WithChecksum}/{_sbomValidation.TotalPackages})");
            }

            complianceItems.Add(new CraComplianceItem
            {
                Requirement = "CRA Annex I Part II(1) - SBOM Completeness",
                Description = "SBOM must contain required fields per BSI TR-03183-2",
                Status = sbomStatus,
                Evidence = $"Field completeness: {completeness}%" + (missing.Count > 0 ? $". Missing: {string.Join(", ", missing)}" : ""),
                Recommendation = sbomStatus != CraComplianceStatus.Compliant
                    ? "Improve SBOM data quality by ensuring supplier, PURL, and checksum fields are populated"
                    : null
            });
        }

        // ============================================
        // CRA ANNEX II - Documentation Requirements
        // ============================================

        // Annex II - Documentation
        {
            var docChecks = new List<string>();
            if (_hasReadme) docChecks.Add("README");
            if (_hasSecurityContact) docChecks.Add("Security contact");
            if (_hasSupportPeriod) docChecks.Add("Support period");
            if (_hasChangelog) docChecks.Add("Changelog");

            var docCount = docChecks.Count;
            var docStatus = _hasReadme && _hasSecurityContact && _hasSupportPeriod
                ? CraComplianceStatus.Compliant
                : docCount >= 2 ? CraComplianceStatus.Review : CraComplianceStatus.ActionRequired;

            complianceItems.Add(new CraComplianceItem
            {
                Requirement = "CRA Annex II - Documentation",
                Description = "Required project documentation (README, security contact, support period, changelog)",
                Status = docStatus,
                Evidence = docCount > 0
                    ? $"Found: {string.Join(", ", docChecks)}. Missing: {string.Join(", ", new[] { "README", "Security contact", "Support period", "Changelog" }.Except(docChecks))}"
                    : "No required documentation found",
                Recommendation = docStatus != CraComplianceStatus.Compliant
                    ? "Add missing documentation: README.md, SECURITY.md or security contact in .cra-config.json, and declare support period"
                    : null
            });
        }

        // Art. 11(4) - Vulnerability Remediation Timeliness
        {
            var patchableCount = _remediationData.Count;
            var oldestDays = patchableCount > 0 ? _remediationData.Max(r => r.DaysSince) : 0;
            var remediationStatus = patchableCount == 0 ? CraComplianceStatus.Compliant :
                oldestDays >= 30 ? CraComplianceStatus.NonCompliant : CraComplianceStatus.ActionRequired;

            var evidence = patchableCount == 0
                ? "No vulnerabilities with available patches pending application"
                : $"{patchableCount} vulnerability(ies) with patches available but not applied. Oldest: {oldestDays} days. " +
                  string.Join("; ", _remediationData.OrderByDescending(r => r.DaysSince).Take(3)
                      .Select(r => $"{r.PackageId} ({r.VulnId}, {r.DaysSince}d, patch: {r.PatchVersion})"));

            complianceItems.Add(new CraComplianceItem
            {
                Requirement = "CRA Art. 11(4) - Remediation Timeliness",
                Description = "Remediate vulnerabilities without delay when patches are available",
                Status = remediationStatus,
                Evidence = evidence,
                Recommendation = patchableCount > 0
                    ? "Apply available security patches immediately to meet CRA remediation requirements"
                    : null
            });
        }

        // Calculate CRA Readiness Score
        var craReadinessScore = CalculateCraReadinessScore(complianceItems);

        // Collect dependency issues from all trees
        var versionConflictCount = _dependencyTrees.Sum(t => t.VersionConflictCount);
        var allDependencyIssues = _dependencyTrees.SelectMany(t => t.Issues).ToList();

        return new CraReport
        {
            GeneratedAt = DateTime.UtcNow,
            GenerationDuration = startTime.HasValue ? DateTime.UtcNow - startTime.Value : null,
            ProjectPath = healthReport.ProjectPath,
            HealthScore = healthReport.OverallScore,
            HealthStatus = healthReport.OverallStatus,
            ComplianceItems = complianceItems,
            OverallComplianceStatus = DetermineOverallStatus(complianceItems),
            Sbom = sbom,
            Vex = vex,
            PackageCount = healthReport.Packages.Count,
            TransitivePackageCount = _transitiveDataCache?.Count ?? 0,
            VulnerabilityCount = activeVulnCount,
            CriticalPackageCount = healthReport.Summary.CriticalCount,
            VersionConflictCount = versionConflictCount,
            DependencyIssues = allDependencyIssues,
            CraReadinessScore = craReadinessScore
        };
    }

    /// <summary>
    /// Calculate weighted CRA readiness score (0-100) across all compliance items.
    /// </summary>
    public static int CalculateCraReadinessScore(List<CraComplianceItem> items)
    {
        // Weights by CRA importance (should sum to 100)
        var weights = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase)
        {
            ["CRA Art. 10(4) - Exploited Vulnerabilities (CISA KEV)"] = 15,
            ["CRA Art. 11 - Vulnerability Handling"] = 15,
            ["CRA Art. 10 - Software Bill of Materials"] = 10,
            ["CRA Annex I Part I(1) - Release Readiness"] = 10,
            ["CRA Art. 11(4) - Remediation Timeliness"] = 8,
            ["CRA Art. 10(4) - Exploit Probability (EPSS)"] = 7,
            ["CRA Art. 10(6) - Security Updates"] = 6,
            ["CRA Art. 13(8) - Support Period"] = 5,
            ["CRA Annex I Part I(10) - Attack Surface"] = 5,
            ["CRA Annex I Part II(1) - SBOM Completeness"] = 5,
            ["CRA Art. 13(5) - Package Provenance"] = 4,
            ["CRA Annex II - Documentation"] = 3,
            ["CRA Art. 10(9) - License Information"] = 2,
            ["CRA Art. 11(5) - Security Policy"] = 2,
            ["CRA Art. 10 - No Deprecated Components"] = 1,
            ["CRA Art. 10 - Cryptographic Compliance"] = 1,
            ["CRA Art. 10 - Supply Chain Integrity"] = 1,
        };

        double totalWeight = 0;
        double earnedWeight = 0;

        foreach (var item in items)
        {
            var weight = weights.GetValueOrDefault(item.Requirement, 2); // default weight for unknown items
            totalWeight += weight;
            var multiplier = item.Status switch
            {
                CraComplianceStatus.Compliant => 1.0,
                CraComplianceStatus.Review => 0.5,
                CraComplianceStatus.ActionRequired => 0.25,
                CraComplianceStatus.NonCompliant => 0.0,
                _ => 0.0
            };
            earnedWeight += weight * multiplier;
        }

        return totalWeight > 0 ? (int)Math.Round(100.0 * earnedWeight / totalWeight) : 0;
    }

    private static CraComplianceStatus DetermineOverallStatus(List<CraComplianceItem> items)
    {
        if (items.Any(i => i.Status == CraComplianceStatus.NonCompliant))
            return CraComplianceStatus.NonCompliant;
        if (items.Any(i => i.Status == CraComplianceStatus.ActionRequired))
            return CraComplianceStatus.ActionRequired;
        return CraComplianceStatus.Compliant;
    }

    /// <summary>
    /// Generate interactive HTML report with drill-down capabilities.
    /// </summary>
    public string GenerateHtml(CraReport report, string? licenseFilePath = null, bool darkMode = true)
    {
        var sb = new StringBuilder();
        var packages = report.Sbom.Packages.Skip(1).ToList(); // Skip root package
        var licenseFileName = licenseFilePath is not null ? Path.GetFileName(licenseFilePath) : null;
        var version = System.Reflection.Assembly.GetExecutingAssembly().GetName().Version;
        var versionString = version is not null ? $"{version.Major}.{version.Minor}.{version.Build}" : "1.0.0";
        var totalPackages = report.PackageCount + report.TransitivePackageCount;

        sb.AppendLine("<!DOCTYPE html>");
        sb.AppendLine(darkMode ? "<html lang=\"en\" data-theme=\"dark\">" : "<html lang=\"en\">");
        sb.AppendLine("<head>");
        sb.AppendLine("  <meta charset=\"UTF-8\">");
        sb.AppendLine("  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">");
        sb.AppendLine($"  <title>CRA Compliance Report - {EscapeHtml(Path.GetFileName(report.ProjectPath))}</title>");
        sb.AppendLine("  <link href=\"https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@300;400;500;600;700&family=IBM+Plex+Mono:wght@400;500&display=swap\" rel=\"stylesheet\">");
        sb.Append(GetHtmlStyles());
        sb.AppendLine("</head>");
        sb.AppendLine("<body>");
        sb.AppendLine("<div class=\"app-container\">");

        // Sidebar Navigation
        sb.AppendLine("<nav class=\"sidebar\">");
        sb.AppendLine("  <div class=\"sidebar-header\">");
        sb.AppendLine("    <div class=\"logo\">");
        sb.AppendLine("      <svg class=\"logo-icon\" width=\"36\" height=\"36\" viewBox=\"0 0 36 36\" fill=\"none\" xmlns=\"http://www.w3.org/2000/svg\">");
        sb.AppendLine("        <path d=\"M18 6L6 12l12 6 12-6L18 6z\" fill=\"var(--accent)\" fill-opacity=\"0.3\"/>");
        sb.AppendLine("        <path d=\"M6 16l12 6 12-6\" stroke=\"var(--accent)\" stroke-width=\"1.5\" fill=\"none\"/>");
        sb.AppendLine("        <path d=\"M6 22l12 6 12-6\" stroke=\"var(--accent)\" stroke-width=\"1.5\" stroke-opacity=\"0.6\" fill=\"none\"/>");
        sb.AppendLine("        <rect x=\"14\" y=\"14\" width=\"8\" height=\"7\" rx=\"1\" fill=\"var(--success)\"/>");
        sb.AppendLine("        <path d=\"M16 14v-2a2 2 0 114 0v2\" stroke=\"var(--success)\" stroke-width=\"1.5\" fill=\"none\"/>");
        sb.AppendLine("        <circle cx=\"18\" cy=\"17.5\" r=\"1\" fill=\"var(--bg-primary)\"/>");
        sb.AppendLine("      </svg>");
        sb.AppendLine("      <span class=\"logo-text\">DepSafe</span>");
        sb.AppendLine($"      <span class=\"logo-badge\">v{versionString}</span>");
        sb.AppendLine("    </div>");
        sb.AppendLine("  </div>");
        sb.AppendLine("  <div class=\"sidebar-content\">");
        sb.AppendLine("    <div class=\"nav-section\">");
        sb.AppendLine("      <div class=\"nav-label\">Analysis</div>");
        sb.AppendLine("      <ul class=\"nav-links\">");
        sb.AppendLine("        <li><a href=\"#\" onclick=\"showSection('overview')\" class=\"active\" data-section=\"overview\">");
        sb.AppendLine("          <svg class=\"nav-icon\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\"><rect x=\"3\" y=\"3\" width=\"7\" height=\"7\"/><rect x=\"14\" y=\"3\" width=\"7\" height=\"7\"/><rect x=\"3\" y=\"14\" width=\"7\" height=\"7\"/><rect x=\"14\" y=\"14\" width=\"7\" height=\"7\"/></svg>");
        sb.AppendLine("          Overview</a></li>");
        sb.AppendLine("        <li><a href=\"#\" onclick=\"showSection('packages')\" data-section=\"packages\">");
        sb.AppendLine("          <svg class=\"nav-icon\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\"><path d=\"M21 16V8a2 2 0 00-1-1.73l-7-4a2 2 0 00-2 0l-7 4A2 2 0 003 8v8a2 2 0 001 1.73l7 4a2 2 0 002 0l7-4A2 2 0 0021 16z\"/></svg>");
        sb.AppendLine($"          Packages<span class=\"nav-badge\">{totalPackages}</span></a></li>");
        sb.AppendLine("        <li><a href=\"#\" onclick=\"showSection('vulnerabilities')\" data-section=\"vulnerabilities\">");
        sb.AppendLine("          <svg class=\"nav-icon\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\"><path d=\"M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z\"/></svg>");
        sb.AppendLine($"          Vulnerabilities<span class=\"nav-badge\">{report.VulnerabilityCount}</span></a></li>");
        sb.AppendLine("        <li><a href=\"#\" onclick=\"showSection('licenses')\" data-section=\"licenses\">");
        sb.AppendLine("          <svg class=\"nav-icon\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\"><path d=\"M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z\"/><path d=\"M14 2v6h6\"/></svg>");
        sb.AppendLine("          Licenses</a></li>");
        sb.AppendLine("      </ul>");
        sb.AppendLine("    </div>");
        sb.AppendLine("    <div class=\"nav-section\">");
        sb.AppendLine("      <div class=\"nav-label\">Compliance</div>");
        sb.AppendLine("      <ul class=\"nav-links\">");
        sb.AppendLine("        <li><a href=\"#\" onclick=\"showSection('compliance')\" data-section=\"compliance\">");
        sb.AppendLine("          <svg class=\"nav-icon\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\"><path d=\"M22 11.08V12a10 10 0 11-5.93-9.14\"/><path d=\"M22 4L12 14.01l-3-3\"/></svg>");
        sb.AppendLine("          CRA Status</a></li>");
        sb.AppendLine("        <li><a href=\"#\" onclick=\"showSection('sbom')\" data-section=\"sbom\">");
        sb.AppendLine("          <svg class=\"nav-icon\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\"><path d=\"M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z\"/><path d=\"M14 2v6h6\"/><path d=\"M16 13H8\"/><path d=\"M16 17H8\"/><path d=\"M10 9H8\"/></svg>");
        sb.AppendLine("          SBOM</a></li>");
        sb.AppendLine("        <li><a href=\"#\" onclick=\"showSection('tree')\" data-section=\"tree\">");
        sb.AppendLine("          <svg class=\"nav-icon\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\"><circle cx=\"12\" cy=\"12\" r=\"10\"/><path d=\"M12 6v6l4 2\"/></svg>");
        sb.AppendLine("          Dependency Tree</a></li>");
        sb.AppendLine("        <li><a href=\"#\" onclick=\"showSection('issues')\" data-section=\"issues\">");
        sb.AppendLine("          <svg class=\"nav-icon\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\"><circle cx=\"12\" cy=\"12\" r=\"10\"/><line x1=\"12\" y1=\"8\" x2=\"12\" y2=\"12\"/><line x1=\"12\" y1=\"16\" x2=\"12.01\" y2=\"16\"/></svg>");
        sb.AppendLine("          Dependency Issues</a></li>");
        if (_typosquatChecked)
        {
            var typosquatBadge = _typosquatResults.Count > 0
                ? $"<span class=\"nav-badge warning\">{_typosquatResults.Count}</span>"
                : "";
            sb.AppendLine("        <li><a href=\"#\" onclick=\"showSection('supply-chain')\" data-section=\"supply-chain\">");
            sb.AppendLine("          <svg class=\"nav-icon\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\"><path d=\"M20 7l-8-4-8 4m16 0l-8 4m8-4v10l-8 4m0-10L4 7m8 4v10M4 7v10l8 4\"/></svg>");
            sb.AppendLine($"          Supply Chain{typosquatBadge}</a></li>");
        }
        if (licenseFileName is not null)
        {
            sb.AppendLine("        <li class=\"external-link-item\"><a href=\"" + licenseFileName + "\" target=\"_blank\" class=\"external\">");
            sb.AppendLine("          <svg class=\"nav-icon\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\"><path d=\"M18 13v6a2 2 0 01-2 2H5a2 2 0 01-2-2V8a2 2 0 012-2h6\"/><polyline points=\"15 3 21 3 21 9\"/><line x1=\"10\" y1=\"14\" x2=\"21\" y2=\"3\"/></svg>");
            sb.AppendLine("          License File</a></li>");
        }
        sb.AppendLine("      </ul>");
        sb.AppendLine("    </div>");
        // CRA Details nav group
        sb.AppendLine("    <div class=\"nav-section\">");
        sb.AppendLine("      <div class=\"nav-label\">CRA Details</div>");
        sb.AppendLine("      <ul class=\"nav-links\">");
        if (_remediationData.Count > 0)
        {
            sb.AppendLine("        <li><a href=\"#\" onclick=\"showSection('remediation')\" data-section=\"remediation\">");
            sb.AppendLine("          <svg class=\"nav-icon\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\"><path d=\"M12 22c5.523 0 10-4.477 10-10S17.523 2 12 2 2 6.477 2 12s4.477 10 10 10z\"/><path d=\"M12 6v6l4 2\"/></svg>");
            sb.AppendLine($"          Remediation<span class=\"nav-badge warning\">{_remediationData.Count}</span></a></li>");
        }
        if (_attackSurface is not null)
        {
            sb.AppendLine("        <li><a href=\"#\" onclick=\"showSection('attack-surface')\" data-section=\"attack-surface\">");
            sb.AppendLine("          <svg class=\"nav-icon\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\"><path d=\"M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z\"/></svg>");
            sb.AppendLine("          Attack Surface</a></li>");
        }
        if (_sbomValidation is not null)
        {
            sb.AppendLine("        <li><a href=\"#\" onclick=\"showSection('sbom-quality')\" data-section=\"sbom-quality\">");
            sb.AppendLine("          <svg class=\"nav-icon\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\"><path d=\"M9 11l3 3L22 4\"/><path d=\"M21 12v7a2 2 0 01-2 2H5a2 2 0 01-2-2V5a2 2 0 012-2h11\"/></svg>");
            sb.AppendLine("          SBOM Quality</a></li>");
        }
        if (_provenanceResults.Count > 0)
        {
            sb.AppendLine("        <li><a href=\"#\" onclick=\"showSection('provenance')\" data-section=\"provenance\">");
            sb.AppendLine("          <svg class=\"nav-icon\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\"><rect x=\"3\" y=\"11\" width=\"18\" height=\"11\" rx=\"2\" ry=\"2\"/><path d=\"M7 11V7a5 5 0 0110 0v4\"/></svg>");
            sb.AppendLine("          Provenance</a></li>");
        }
        if (_archivedPackageNames.Count > 0 || _stalePackageNames.Count > 0 || _unmaintainedPackageNames.Count > 0)
        {
            sb.AppendLine("        <li><a href=\"#\" onclick=\"showSection('maintenance')\" data-section=\"maintenance\">");
            sb.AppendLine("          <svg class=\"nav-icon\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\"><circle cx=\"12\" cy=\"12\" r=\"3\"/><path d=\"M19.4 15a1.65 1.65 0 00.33 1.82l.06.06a2 2 0 010 2.83 2 2 0 01-2.83 0l-.06-.06a1.65 1.65 0 00-1.82-.33 1.65 1.65 0 00-1 1.51V21a2 2 0 01-4 0v-.09A1.65 1.65 0 009 19.4a1.65 1.65 0 00-1.82.33l-.06.06a2 2 0 01-2.83-2.83l.06-.06A1.65 1.65 0 004.68 15a1.65 1.65 0 00-1.51-1H3a2 2 0 010-4h.09A1.65 1.65 0 004.6 9a1.65 1.65 0 00-.33-1.82l-.06-.06a2 2 0 012.83-2.83l.06.06A1.65 1.65 0 009 4.68a1.65 1.65 0 001-1.51V3a2 2 0 014 0v.09a1.65 1.65 0 001 1.51 1.65 1.65 0 001.82-.33l.06-.06a2 2 0 012.83 2.83l-.06.06A1.65 1.65 0 0019.4 9a1.65 1.65 0 001.51 1H21a2 2 0 010 4h-.09a1.65 1.65 0 00-1.51 1z\"/></svg>");
            sb.AppendLine("          Maintenance</a></li>");
        }
        sb.AppendLine("      </ul>");
        sb.AppendLine("    </div>");
        sb.AppendLine("  </div>");
        sb.AppendLine("  <div class=\"theme-section\">");
        sb.AppendLine("    <div class=\"theme-toggle\">");
        sb.AppendLine("      <div class=\"theme-info\">");
        sb.AppendLine("        <svg class=\"theme-icon\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\"><path d=\"M21 12.79A9 9 0 1111.21 3 7 7 0 0021 12.79z\"/></svg>");
        sb.AppendLine("        <span class=\"theme-label\">Dark Mode</span>");
        sb.AppendLine("      </div>");
        sb.AppendLine(darkMode
            ? "      <div class=\"toggle-switch active\" id=\"themeToggle\" onclick=\"toggleTheme()\"></div>"
            : "      <div class=\"toggle-switch\" id=\"themeToggle\" onclick=\"toggleTheme()\"></div>");
        sb.AppendLine("    </div>");
        sb.AppendLine("  </div>");
        sb.AppendLine("  <div class=\"sidebar-footer\">");
        sb.AppendLine($"    <span class=\"version-info\">DepSafe v{versionString}</span>");
        sb.AppendLine("  </div>");
        sb.AppendLine("</nav>");

        // Main Content
        sb.AppendLine("<main class=\"main-content\">");

        // Header
        sb.AppendLine("<header class=\"main-header\">");
        sb.AppendLine("  <div class=\"header-left\">");
        sb.AppendLine($"    <h1>{EscapeHtml(Path.GetFileName(report.ProjectPath))}</h1>");
        sb.AppendLine("    <div class=\"breadcrumb\">");
        sb.AppendLine("      <span>CRA Report</span>");
        sb.AppendLine("      <span class=\"breadcrumb-sep\">/</span>");
        var durationText = report.GenerationDuration.HasValue
            ? $" in {FormatDuration(report.GenerationDuration.Value)}"
            : "";
        sb.AppendLine($"      <span>Generated {report.GeneratedAt:MMMM dd, yyyy 'at' HH:mm} UTC{durationText}</span>");
        sb.AppendLine("    </div>");
        sb.AppendLine("  </div>");
        sb.AppendLine("</header>");

        // Overview Section
        sb.AppendLine("<section id=\"overview\" class=\"section active\">");
        GenerateOverviewSection(sb, report);
        sb.AppendLine("</section>");

        // Packages Section
        sb.AppendLine("<section id=\"packages\" class=\"section\">");
        GeneratePackagesSection(sb, report);
        sb.AppendLine("</section>");

        // Licenses Section
        sb.AppendLine("<section id=\"licenses\" class=\"section\">");
        GenerateLicensesSection(sb, report);
        sb.AppendLine("</section>");

        // SBOM Section
        sb.AppendLine("<section id=\"sbom\" class=\"section\">");
        GenerateSbomSection(sb, report, packages);
        sb.AppendLine("</section>");

        // Vulnerabilities Section
        sb.AppendLine("<section id=\"vulnerabilities\" class=\"section\">");
        GenerateVulnerabilitiesSection(sb, report);
        sb.AppendLine("</section>");

        // Dependency Tree Section
        sb.AppendLine("<section id=\"tree\" class=\"section\">");
        GenerateDependencyTreeSection(sb);
        sb.AppendLine("</section>");

        // Dependency Issues Section
        sb.AppendLine("<section id=\"issues\" class=\"section\">");
        GenerateDependencyIssuesSection(sb, report);
        sb.AppendLine("</section>");

        // Supply Chain Section
        if (_typosquatChecked)
        {
            sb.AppendLine("<section id=\"supply-chain\" class=\"section\">");
            GenerateSupplyChainSection(sb);
            sb.AppendLine("</section>");
        }

        // CRA Detail Sections (v1.2)
        if (_remediationData.Count > 0)
        {
            sb.AppendLine("<section id=\"remediation\" class=\"section\">");
            GenerateRemediationSection(sb);
            sb.AppendLine("</section>");
        }

        if (_attackSurface is not null)
        {
            sb.AppendLine("<section id=\"attack-surface\" class=\"section\">");
            GenerateAttackSurfaceSection(sb);
            sb.AppendLine("</section>");
        }

        if (_sbomValidation is not null)
        {
            sb.AppendLine("<section id=\"sbom-quality\" class=\"section\">");
            GenerateSbomQualitySection(sb);
            sb.AppendLine("</section>");
        }

        if (_provenanceResults.Count > 0)
        {
            sb.AppendLine("<section id=\"provenance\" class=\"section\">");
            GenerateProvenanceSection(sb);
            sb.AppendLine("</section>");
        }

        if (_archivedPackageNames.Count > 0 || _stalePackageNames.Count > 0 || _unmaintainedPackageNames.Count > 0)
        {
            sb.AppendLine("<section id=\"maintenance\" class=\"section\">");
            GenerateMaintenanceSection(sb);
            sb.AppendLine("</section>");
        }

        // Compliance Section
        sb.AppendLine("<section id=\"compliance\" class=\"section\">");
        GenerateComplianceSection(sb, report);
        sb.AppendLine("</section>");

        sb.AppendLine("</main>");
        sb.AppendLine("</div>"); // Close app-container

        // Footer with disclaimer - visible on all views
        sb.AppendLine("<footer class=\"disclaimer-footer\">");
        sb.AppendLine("  <p>This report assists with EU Cyber Resilience Act compliance assessment. It is not legal advice. Consult legal counsel for authoritative compliance guidance.</p>");
        sb.AppendLine("</footer>");

        // JavaScript
        sb.Append(GetHtmlScripts(report, darkMode));

        sb.AppendLine("</body>");
        sb.AppendLine("</html>");

        return sb.ToString();
    }

    private void GenerateOverviewSection(StringBuilder sb, CraReport report)
    {
        // SBOM completeness warning
        if (_hasIncompleteTransitive || _hasUnresolvedVersions)
        {
            sb.AppendLine("<div class=\"sbom-warning\">");
            sb.AppendLine("  <h4>⚠️ SBOM Completeness Warning</h4>");
            sb.AppendLine("  <p>This report may be incomplete for full CRA compliance:</p>");
            sb.AppendLine("  <ul>");
            if (_hasIncompleteTransitive)
            {
                sb.AppendLine("    <li><strong>Transitive dependencies not fully resolved</strong> - Deep dependency tree may be incomplete</li>");
            }
            if (_hasUnresolvedVersions)
            {
                sb.AppendLine("    <li><strong>Unresolved MSBuild variables</strong> - Some package versions could not be determined</li>");
            }
            sb.AppendLine("  </ul>");
            sb.AppendLine("  <p><strong>To fix:</strong> Run <code>dotnet restore</code> in your project directory before generating the report.</p>");
            sb.AppendLine("</div>");
        }

        var statusClass = report.OverallComplianceStatus switch
        {
            CraComplianceStatus.Compliant => "healthy",
            CraComplianceStatus.ActionRequired => "warning",
            _ => "critical"
        };

        sb.AppendLine("<div class=\"overview-grid\">");

        // Health Score Card - based on freshness, activity, popularity
        sb.AppendLine("  <div class=\"card score-card\" title=\"Average health of your dependencies based on repository freshness, commit activity, community engagement, and maintenance status.\">");
        sb.AppendLine("    <h3>Health Score</h3>");
        sb.AppendLine($"    <div class=\"score-gauge {GetScoreClass(report.HealthScore)}\">");
        sb.AppendLine($"      <svg viewBox=\"0 0 100 50\">");
        sb.AppendLine($"        <path class=\"gauge-bg\" d=\"M 10 50 A 40 40 0 0 1 90 50\" />");
        var angle = 180 * (report.HealthScore / 100.0);
        sb.AppendLine($"        <path class=\"gauge-fill\" d=\"M 10 50 A 40 40 0 0 1 90 50\" style=\"stroke-dasharray: {angle * 1.26}, 226\" />");
        sb.AppendLine($"      </svg>");
        sb.AppendLine($"      <div class=\"score-value\">{report.HealthScore}</div>");
        sb.AppendLine("    </div>");
        sb.AppendLine($"    <div class=\"score-label {GetScoreClass(report.HealthScore)}\">Freshness + Activity</div>");
        sb.AppendLine("  </div>");

        // CRA Readiness Score Card
        sb.AppendLine($"  <div class=\"card score-card\" title=\"Weighted compliance score across all EU Cyber Resilience Act requirements. Critical items like known exploited vulnerabilities carry more weight than documentation checks.\">");
        sb.AppendLine("    <h3>CRA Readiness</h3>");
        sb.AppendLine($"    <div class=\"score-gauge {GetScoreClass(report.CraReadinessScore)}\">");
        sb.AppendLine($"      <svg viewBox=\"0 0 100 50\">");
        sb.AppendLine($"        <path class=\"gauge-bg\" d=\"M 10 50 A 40 40 0 0 1 90 50\" />");
        var readinessAngle = 180 * (report.CraReadinessScore / 100.0);
        sb.AppendLine($"        <path class=\"gauge-fill\" d=\"M 10 50 A 40 40 0 0 1 90 50\" style=\"stroke-dasharray: {readinessAngle * 1.26}, 226\" />");
        sb.AppendLine($"      </svg>");
        sb.AppendLine($"      <div class=\"score-value\">{report.CraReadinessScore}</div>");
        sb.AppendLine("    </div>");
        sb.AppendLine($"    <div class=\"score-label {GetScoreClass(report.CraReadinessScore)}\">Weighted Compliance</div>");
        sb.AppendLine("  </div>");

        // Compliance Status Card
        sb.AppendLine($"  <div class=\"card status-card {statusClass}\" title=\"Overall compliance status based on EU Cyber Resilience Act Articles 10, 11, 13 and Annexes I, II. ActionRequired means one or more items need attention before the product can be considered CRA-compliant.\">");
        sb.AppendLine("    <h3>CRA Compliance</h3>");
        sb.AppendLine($"    <div class=\"big-status\">{report.OverallComplianceStatus}</div>");
        var compliantCount = report.ComplianceItems.Count(i => i.Status == CraComplianceStatus.Compliant);
        sb.AppendLine($"    <div class=\"status-detail\">{compliantCount}/{report.ComplianceItems.Count} requirements met</div>");
        sb.AppendLine("  </div>");

        // Summary Cards
        var totalPackages = report.PackageCount + report.TransitivePackageCount;
        sb.AppendLine("  <div class=\"card metric-card\" title=\"Total number of direct and transitive (indirect) dependencies in your project. Each package increases your supply chain attack surface.\">");
        sb.AppendLine($"    <div class=\"metric-value\">{totalPackages}</div>");
        sb.AppendLine($"    <div class=\"metric-label\">Total Packages</div>");
        sb.AppendLine($"    <div class=\"metric-detail\">{report.PackageCount} direct + {report.TransitivePackageCount} transitive</div>");
        sb.AppendLine("  </div>");

        sb.AppendLine("  <div class=\"card metric-card\" title=\"Known security vulnerabilities found in your dependencies by scanning the OSV (Open Source Vulnerabilities) database.\">");
        sb.AppendLine($"    <div class=\"metric-value {(report.VulnerabilityCount > 0 ? "critical" : "")}\">{report.VulnerabilityCount}</div>");
        sb.AppendLine("    <div class=\"metric-label\">Vulnerabilities</div>");
        sb.AppendLine("  </div>");

        sb.AppendLine("  <div class=\"card metric-card\" title=\"Packages with severe issues: known exploited vulnerabilities (CISA KEV), critical CVSS scores, or high EPSS exploit probability.\">");
        sb.AppendLine($"    <div class=\"metric-value {(report.CriticalPackageCount > 0 ? "critical" : "")}\">{report.CriticalPackageCount}</div>");
        sb.AppendLine("    <div class=\"metric-label\">Critical Packages</div>");
        sb.AppendLine("  </div>");

        sb.AppendLine("  <div class=\"card metric-card\" title=\"Cases where different packages require different versions of the same dependency, which can cause runtime issues.\">");
        sb.AppendLine($"    <div class=\"metric-value {(report.VersionConflictCount > 0 ? "warning" : "")}\">{report.VersionConflictCount}</div>");
        sb.AppendLine("    <div class=\"metric-label\">Version Conflicts</div>");
        sb.AppendLine("  </div>");

        // License Summary Card (using cached license data)
        var licenseReport = LicenseCompatibility.AnalyzeLicenses(GetPackageLicenses());
        var licenseStatusClass = licenseReport.OverallStatus switch
        {
            "Compatible" => "healthy",
            "Review Recommended" => "warning",
            _ => "critical"
        };
        var unknownCount = licenseReport.CategoryDistribution.GetValueOrDefault(LicenseCompatibility.LicenseCategory.Unknown, 0);

        sb.AppendLine($"  <div class=\"card metric-card license-card\" onclick=\"showSection('licenses')\" style=\"cursor: pointer;\" title=\"License compatibility analysis across all dependencies. Checks for copyleft conflicts, unknown licenses, and compliance risks. Click to view details.\">");
        sb.AppendLine($"    <div class=\"metric-value {licenseStatusClass}\">{(licenseReport.ErrorCount == 0 ? "✓" : licenseReport.ErrorCount.ToString())}</div>");
        sb.AppendLine($"    <div class=\"metric-label\">License Status</div>");
        sb.AppendLine($"    <div class=\"metric-detail\">{licenseReport.OverallStatus}{(unknownCount > 0 ? $" ({unknownCount} unknown)" : "")}</div>");
        sb.AppendLine("  </div>");

        sb.AppendLine("</div>");

        // Quick Actions
        if (report.ComplianceItems.Any(i => i.Status != CraComplianceStatus.Compliant))
        {
            sb.AppendLine("<div class=\"card recommendations-card\">");
            sb.AppendLine("  <h3>Recommended Actions</h3>");
            sb.AppendLine("  <ul class=\"action-list\">");
            foreach (var item in report.ComplianceItems.Where(i => !string.IsNullOrEmpty(i.Recommendation)))
            {
                sb.AppendLine($"    <li><strong>{EscapeHtml(item.Requirement)}:</strong> {EscapeHtml(item.Recommendation!)}</li>");
            }
            sb.AppendLine("  </ul>");
            sb.AppendLine("</div>");
        }
    }

    private void GeneratePackagesSection(StringBuilder sb, CraReport report)
    {
        sb.AppendLine("<div class=\"section-header\">");
        sb.AppendLine("  <h2>Package Health</h2>");
        sb.AppendLine("  <input type=\"text\" id=\"package-search\" class=\"search-input\" placeholder=\"Search packages...\" onkeyup=\"filterPackages()\">");
        sb.AppendLine("</div>");

        sb.AppendLine("<div class=\"filter-bar\">");
        sb.AppendLine("  <span class=\"filter-group\">");
        sb.AppendLine("    <span class=\"filter-label\">Status:</span>");
        sb.AppendLine("    <button class=\"filter-btn active\" onclick=\"filterByStatus('all')\">All</button>");
        sb.AppendLine("    <button class=\"filter-btn healthy\" onclick=\"filterByStatus('healthy')\">Healthy</button>");
        sb.AppendLine("    <button class=\"filter-btn watch\" onclick=\"filterByStatus('watch')\">Watch</button>");
        sb.AppendLine("    <button class=\"filter-btn warning\" onclick=\"filterByStatus('warning')\">Warning</button>");
        sb.AppendLine("    <button class=\"filter-btn critical\" onclick=\"filterByStatus('critical')\">Critical</button>");
        sb.AppendLine("  </span>");
        sb.AppendLine("  <span class=\"filter-group\">");
        sb.AppendLine("    <span class=\"filter-label\">Ecosystem:</span>");
        sb.AppendLine("    <button class=\"filter-btn ecosystem-btn active\" onclick=\"filterByEcosystem('all')\">All</button>");
        sb.AppendLine("    <button class=\"filter-btn ecosystem-btn nuget\" onclick=\"filterByEcosystem('nuget')\">NuGet</button>");
        sb.AppendLine("    <button class=\"filter-btn ecosystem-btn npm\" onclick=\"filterByEcosystem('npm')\">npm</button>");
        sb.AppendLine("  </span>");
        sb.AppendLine("  <span class=\"filter-group\">");
        sb.AppendLine("    <span class=\"filter-label\">Sort:</span>");
        sb.AppendLine("    <button class=\"filter-btn sort-btn\" onclick=\"sortPackages('name')\">Name</button>");
        sb.AppendLine("    <button class=\"filter-btn sort-btn active\" onclick=\"sortPackages('health')\">Health</button>");
        sb.AppendLine("  </span>");
        sb.AppendLine("</div>");

        // Check for unresolved MSBuild variables
        var unresolvedVersions = report.Sbom.Packages
            .Where(p => p.VersionInfo?.Contains("$(") == true)
            .Select(p => p.VersionInfo)
            .Distinct()
            .ToList();

        if (unresolvedVersions.Count > 0)
        {
            sb.AppendLine("<div class=\"msb-warning\">");
            sb.AppendLine("  <h4>&#9888; Unresolved MSBuild Variables</h4>");
            sb.AppendLine("  <p>Some package versions contain MSBuild variables that couldn't be resolved:</p>");
            sb.AppendLine("  <p style=\"margin-top: 8px;\">");
            foreach (var v in unresolvedVersions.Take(5))
            {
                sb.AppendLine($"    <code>{EscapeHtml(v)}</code> ");
            }
            if (unresolvedVersions.Count > 5)
                sb.AppendLine($"    <em>and {unresolvedVersions.Count - 5} more...</em>");
            sb.AppendLine("  </p>");
            sb.AppendLine("  <p style=\"margin-top: 10px;\"><strong>To resolve:</strong> Run <code>dotnet restore</code> first, or check your <code>Directory.Build.props</code> / <code>Directory.Packages.props</code> files.</p>");
            sb.AppendLine("</div>");
        }

        sb.AppendLine("<div id=\"packages-list\" class=\"packages-list\">");

        // Build set of all package IDs in the report for internal linking
        var allPackageIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var pkg in report.Sbom.Packages.Skip(1))
            allPackageIds.Add(pkg.Name);
        if (_transitiveDataCache != null)
            foreach (var t in _transitiveDataCache)
                allPackageIds.Add(t.PackageId);

        // Build set of direct package IDs for filtering
        var directPackageIds = new HashSet<string>(
            _healthDataCache?.Select(h => h.PackageId) ?? [],
            StringComparer.OrdinalIgnoreCase);

        // Only render direct packages here (transitives are shown in separate section)
        foreach (var pkg in report.Sbom.Packages.Skip(1).Where(p => directPackageIds.Contains(p.Name)).OrderBy(p => p.Name, StringComparer.OrdinalIgnoreCase))
        {
            var pkgName = pkg.Name;
            var version = pkg.VersionInfo;
            var score = 70; // Default score
            var status = "watch";

            // Find matching health data
            var healthData = _healthDataCache?.FirstOrDefault(h => h.PackageId == pkgName);
            var ecosystemAttr = "nuget"; // Default for data attribute
            if (healthData != null)
            {
                score = healthData.Score;
                status = healthData.Status.ToString().ToLowerInvariant();
                ecosystemAttr = healthData.Ecosystem == PackageEcosystem.Npm ? "npm" : "nuget";
            }

            var hasKev = _kevPackageIds.Contains(pkgName);
            var kevClass = hasKev ? " has-kev" : "";
            sb.AppendLine($"  <div class=\"package-card{kevClass}\" id=\"pkg-{EscapeHtml(pkgName)}\" data-status=\"{status}\" data-name=\"{EscapeHtml(pkgName.ToLowerInvariant())}\" data-ecosystem=\"{ecosystemAttr}\" data-health=\"{score}\">");
            sb.AppendLine("    <div class=\"package-header\" onclick=\"togglePackage(this)\">");
            sb.AppendLine($"      <div class=\"package-info\">");
            sb.AppendLine($"        <span class=\"package-name\">{EscapeHtml(pkgName)}</span>");
            if (hasKev && healthData?.KevCves.Count > 0)
            {
                var kevCve = healthData.KevCves[0];
                var kevUrl = $"https://osv.dev/vulnerability/{Uri.EscapeDataString(kevCve)}";
                var kevTooltip = $"{kevCve} - Known Exploited Vulnerability (click for details)";
                sb.AppendLine($"        <a href=\"{EscapeHtml(kevUrl)}\" target=\"_blank\" class=\"kev-badge\" title=\"{EscapeHtml(kevTooltip)}\" onclick=\"event.stopPropagation()\">{EscapeHtml(kevCve)}</a>");
            }
            else if (hasKev)
            {
                sb.AppendLine($"        <span class=\"kev-badge\" title=\"Known Exploited Vulnerability - actively exploited in the wild\">KEV</span>");
            }
            if (healthData?.MaxEpssProbability is > 0 and var epssDirect)
            {
                var epssClass = GetEpssBadgeClass(epssDirect);
                var epssPct = (epssDirect * 100).ToString("F1");
                sb.AppendLine($"        <span class=\"epss-badge {epssClass}\" title=\"EPSS: {epssPct}% probability of exploitation in 30 days\">EPSS {epssPct}%</span>");
            }
            sb.AppendLine($"        <span class=\"package-version\">{FormatVersion(version, pkgName)}</span>");
            sb.AppendLine($"        <span class=\"dep-type-badge direct\" title=\"Direct dependency - referenced in your project file\">direct</span>");
            sb.AppendLine($"      </div>");
            sb.AppendLine($"      <div class=\"package-scores\">");
            sb.AppendLine($"        <div class=\"package-score-item\" title=\"Health Score - freshness, activity, and maintenance\">");
            sb.AppendLine($"          <span class=\"score-label\">HEALTH</span>");
            sb.AppendLine($"          <span class=\"score-value {GetScoreClass(score)}\">{score}</span>");
            sb.AppendLine($"        </div>");
            sb.AppendLine($"      </div>");
            sb.AppendLine($"      <span class=\"expand-icon\">+</span>");
            sb.AppendLine("    </div>");
            // Empty details container - content loaded lazily via JavaScript from packageData
            sb.AppendLine("    <div class=\"package-details\"></div>");
            sb.AppendLine("  </div>");
        }

        sb.AppendLine("</div>");

        // Transitive Dependencies Section (exclude sub-dependencies - they're only for tree navigation)
        var actualTransitives = _transitiveDataCache?.Where(h => h.DependencyType != DependencyType.SubDependency).ToList() ?? [];
        if (actualTransitives.Count > 0)
        {
            sb.AppendLine("<div class=\"transitive-section\">");
            sb.AppendLine("  <div class=\"transitive-header\" onclick=\"toggleTransitive()\">");
            sb.AppendLine($"    <h3>Transitive Dependencies ({actualTransitives.Count})</h3>");
            sb.AppendLine("    <span class=\"transitive-toggle\" id=\"transitive-toggle\">Show</span>");
            sb.AppendLine("  </div>");
            sb.AppendLine("  <div id=\"transitive-list\" class=\"packages-list transitive-list\" style=\"display: none;\">");

            foreach (var healthData in actualTransitives.OrderBy(h => h.PackageId, StringComparer.OrdinalIgnoreCase))
            {
                var pkgName = healthData.PackageId;
                var version = healthData.Version;
                var score = healthData.Score;
                var status = healthData.Status.ToString().ToLowerInvariant();

                var ecosystemName = healthData.Ecosystem == PackageEcosystem.Npm ? "npm" : "NuGet";
                var depTypeBadge = $"<span class=\"dep-type-badge transitive\" title=\"Transitive dependency - pulled in by {ecosystemName} dependency resolution\">transitive</span>";

                var ecosystemAttr = healthData.Ecosystem == PackageEcosystem.Npm ? "npm" : "nuget";

                // Check if we have real health data (not just defaults)
                var hasRealHealthData = healthData.Metrics.TotalDownloads > 0 ||
                                        healthData.Metrics.DaysSinceLastRelease.HasValue ||
                                        healthData.Metrics.ReleasesPerYear > 0;

                var hasKevTrans = _kevPackageIds.Contains(pkgName);
                var kevClassTrans = hasKevTrans ? " has-kev" : "";
                sb.AppendLine($"  <div class=\"package-card transitive{kevClassTrans}\" id=\"pkg-{EscapeHtml(pkgName)}\" data-status=\"{status}\" data-name=\"{EscapeHtml(pkgName.ToLowerInvariant())}\" data-ecosystem=\"{ecosystemAttr}\" data-health=\"{score}\">");
                sb.AppendLine("    <div class=\"package-header\" onclick=\"togglePackage(this)\">");
                sb.AppendLine($"      <div class=\"package-info\">");
                sb.AppendLine($"        <span class=\"package-name\">{EscapeHtml(pkgName)}</span>");
                if (hasKevTrans && healthData.KevCves.Count > 0)
                {
                    var kevCve = healthData.KevCves[0];
                    var kevUrl = $"https://osv.dev/vulnerability/{Uri.EscapeDataString(kevCve)}";
                    var kevTooltip = $"{kevCve} - Known Exploited Vulnerability (click for details)";
                    sb.AppendLine($"        <a href=\"{EscapeHtml(kevUrl)}\" target=\"_blank\" class=\"kev-badge\" title=\"{EscapeHtml(kevTooltip)}\" onclick=\"event.stopPropagation()\">{EscapeHtml(kevCve)}</a>");
                }
                else if (hasKevTrans)
                {
                    sb.AppendLine($"        <span class=\"kev-badge\" title=\"Known Exploited Vulnerability - actively exploited in the wild\">KEV</span>");
                }
                if (healthData.MaxEpssProbability is > 0 and var epssTrans)
                {
                    var epssClass = GetEpssBadgeClass(epssTrans);
                    var epssPct = (epssTrans * 100).ToString("F1");
                    sb.AppendLine($"        <span class=\"epss-badge {epssClass}\" title=\"EPSS: {epssPct}% probability of exploitation in 30 days\">EPSS {epssPct}%</span>");
                }
                sb.AppendLine($"        <span class=\"package-version\">{FormatVersion(version, pkgName)}</span>");
                sb.AppendLine($"        {depTypeBadge}");
                sb.AppendLine($"      </div>");
                sb.AppendLine($"      <div class=\"package-scores\">");
                if (hasRealHealthData)
                {
                    sb.AppendLine($"        <div class=\"package-score-item\" title=\"Health Score - freshness &amp; activity\">");
                    sb.AppendLine($"          <span class=\"score-label\">HEALTH</span>");
                    sb.AppendLine($"          <span class=\"score-value {GetScoreClass(score)}\">{score}</span>");
                    sb.AppendLine($"        </div>");
                }
                else
                {
                    sb.AppendLine($"        <div class=\"package-score-item\" title=\"Health Score not available - use --deep for full analysis\">");
                    sb.AppendLine($"          <span class=\"score-label\">HEALTH</span>");
                    sb.AppendLine($"          <span class=\"score-value na\">—</span>");
                    sb.AppendLine($"        </div>");
                }
                sb.AppendLine($"      </div>");
                sb.AppendLine($"      <span class=\"expand-icon\">+</span>");
                sb.AppendLine("    </div>");
                // Empty details container - content loaded lazily via JavaScript from packageData
                sb.AppendLine("    <div class=\"package-details\"></div>");
                sb.AppendLine("  </div>");
            }

            sb.AppendLine("  </div>");
            sb.AppendLine("</div>");
        }
    }

    private void GenerateSbomSection(StringBuilder sb, CraReport report, List<SbomPackage> packages)
    {
        sb.AppendLine("<div class=\"section-header\">");
        sb.AppendLine("  <h2>Software Bill of Materials (SBOM)</h2>");
        sb.AppendLine("  <div class=\"sbom-meta\">");
        sb.AppendLine($"    <span class=\"meta-item\">Format: SPDX {report.Sbom.SpdxVersion}</span>");
        sb.AppendLine($"    <span class=\"meta-item\">Components: {packages.Count}</span>");
        sb.AppendLine("  </div>");
        sb.AppendLine("</div>");

        sb.AppendLine("<div class=\"card\">");
        sb.AppendLine("  <input type=\"text\" id=\"sbom-search\" class=\"search-input\" placeholder=\"Search components...\" onkeyup=\"filterSbom()\">");
        sb.AppendLine("  <table class=\"sbom-table\" id=\"sbom-table\">");
        sb.AppendLine("    <thead>");
        sb.AppendLine("      <tr>");
        sb.AppendLine("        <th>Component</th>");
        sb.AppendLine("        <th>Version</th>");
        sb.AppendLine("        <th>License</th>");
        sb.AppendLine("        <th>PURL</th>");
        sb.AppendLine("      </tr>");
        sb.AppendLine("    </thead>");
        sb.AppendLine("    <tbody>");

        foreach (var pkg in packages)
        {
            var purl = pkg.ExternalRefs?.FirstOrDefault(r => r.ReferenceType == "purl")?.ReferenceLocator ?? "";
            var versionDisplay = FormatVersionForSbom(pkg.VersionInfo);
            var purlDisplay = FormatPurlForSbom(purl);

            var registryName = pkg.Ecosystem == PackageEcosystem.Npm ? "npm" : "NuGet";
            sb.AppendLine($"    <tr data-name=\"{EscapeHtml(pkg.Name.ToLowerInvariant())}\">");
            sb.AppendLine($"      <td class=\"component-name\">");
            sb.AppendLine($"        <strong>{EscapeHtml(pkg.Name)}</strong>");
            sb.AppendLine($"        <a href=\"{EscapeHtml(pkg.DownloadLocation)}\" target=\"_blank\" class=\"external-link\">View on {registryName}</a>");
            sb.AppendLine($"      </td>");
            sb.AppendLine($"      <td>{versionDisplay}</td>");
            sb.AppendLine($"      <td><span class=\"license-badge\">{FormatLicense(pkg.LicenseDeclared)}</span></td>");
            sb.AppendLine($"      <td class=\"purl\"><code>{purlDisplay}</code></td>");
            sb.AppendLine($"    </tr>");
        }

        sb.AppendLine("    </tbody>");
        sb.AppendLine("  </table>");
        sb.AppendLine("</div>");

        // SBOM Export
        sb.AppendLine("<div class=\"export-section\">");
        sb.AppendLine("  <button onclick=\"exportSbom('spdx')\" class=\"export-btn\">Export SPDX JSON</button>");
        sb.AppendLine("  <button onclick=\"exportSbom('cyclonedx')\" class=\"export-btn\">Export CycloneDX</button>");
        sb.AppendLine("</div>");
    }

    private void GenerateLicensesSection(StringBuilder sb, CraReport report)
    {
        sb.AppendLine("<div class=\"section-header\">");
        sb.AppendLine("  <h2>License Compatibility</h2>");
        sb.AppendLine("  <p>Analysis of license types and potential compatibility issues</p>");
        sb.AppendLine("</div>");

        // Use cached license data
        var licenseReport = LicenseCompatibility.AnalyzeLicenses(GetPackageLicenses());

        // Status banner
        var statusClass = licenseReport.OverallStatus switch
        {
            "Compatible" => "healthy",
            "Review Recommended" => "warning",
            _ => "critical"
        };
        sb.AppendLine($"<div class=\"license-status {statusClass}\">");
        sb.AppendLine($"  <span class=\"status-icon\">{(licenseReport.ErrorCount == 0 ? "✓" : "⚠")}</span>");
        sb.AppendLine($"  <span class=\"status-text\">{licenseReport.OverallStatus}</span>");
        if (licenseReport.ErrorCount > 0)
            sb.AppendLine($"  <span class=\"status-detail\">{licenseReport.ErrorCount} potential issues found</span>");
        sb.AppendLine("</div>");

        // License distribution chart (stacked horizontal bar)
        sb.AppendLine("<div class=\"license-distribution\">");
        sb.AppendLine("  <h3>License Distribution</h3>");

        var total = licenseReport.CategoryDistribution.Values.Sum();
        if (total > 0)
        {
            // Stacked bar
            sb.AppendLine("  <div class=\"distribution-stacked-bar\">");
            foreach (var (category, count) in licenseReport.CategoryDistribution.OrderByDescending(x => x.Value))
            {
                if (count == 0) continue;
                var percent = (count * 100.0) / total;
                var categoryClass = category switch
                {
                    LicenseCompatibility.LicenseCategory.Permissive => "permissive",
                    LicenseCompatibility.LicenseCategory.WeakCopyleft => "weak-copyleft",
                    LicenseCompatibility.LicenseCategory.StrongCopyleft => "strong-copyleft",
                    LicenseCompatibility.LicenseCategory.PublicDomain => "public-domain",
                    _ => "unknown"
                };
                // Only show label if segment is wide enough (>10%)
                var label = percent >= 10 ? $"<span class=\"segment-label\">{category}</span>" : "";
                sb.AppendLine($"    <div class=\"bar-segment {categoryClass}\" style=\"width: {percent:F1}%\" title=\"{category}: {count} packages ({percent:F1}%)\">{label}</div>");
            }
            sb.AppendLine("  </div>");

            // Legend below the bar
            sb.AppendLine("  <div class=\"distribution-legend\">");
            foreach (var (category, count) in licenseReport.CategoryDistribution.OrderByDescending(x => x.Value))
            {
                if (count == 0) continue;
                var percent = (count * 100.0) / total;
                var categoryClass = category switch
                {
                    LicenseCompatibility.LicenseCategory.Permissive => "permissive",
                    LicenseCompatibility.LicenseCategory.WeakCopyleft => "weak-copyleft",
                    LicenseCompatibility.LicenseCategory.StrongCopyleft => "strong-copyleft",
                    LicenseCompatibility.LicenseCategory.PublicDomain => "public-domain",
                    _ => "unknown"
                };
                sb.AppendLine($"    <div class=\"legend-item\">");
                sb.AppendLine($"      <span class=\"legend-color {categoryClass}\"></span>");
                sb.AppendLine($"      <span class=\"legend-label\">{category}</span>");
                sb.AppendLine($"      <span class=\"legend-count\">{count}</span>");
                sb.AppendLine($"      <span class=\"legend-percent\">({percent:F1}%)</span>");
                sb.AppendLine($"    </div>");
            }
            sb.AppendLine("  </div>");
        }
        sb.AppendLine("</div>");

        // License table
        sb.AppendLine("<div class=\"license-table-container\">");
        sb.AppendLine("  <h3>Packages by License</h3>");
        sb.AppendLine("  <table class=\"license-table\">");
        sb.AppendLine("    <thead>");
        sb.AppendLine("      <tr><th>License</th><th>Category</th><th>Packages</th></tr>");
        sb.AppendLine("    </thead>");
        sb.AppendLine("    <tbody>");

        foreach (var (license, count) in licenseReport.LicenseDistribution.OrderByDescending(x => x.Value))
        {
            var info = LicenseCompatibility.GetLicenseInfo(license);
            var category = info?.Category.ToString() ?? "Unknown";
            var categoryClass = info?.Category switch
            {
                LicenseCompatibility.LicenseCategory.Permissive => "permissive",
                LicenseCompatibility.LicenseCategory.WeakCopyleft => "weak-copyleft",
                LicenseCompatibility.LicenseCategory.StrongCopyleft => "strong-copyleft",
                LicenseCompatibility.LicenseCategory.PublicDomain => "public-domain",
                _ => "unknown"
            };
            sb.AppendLine($"      <tr>");
            sb.AppendLine($"        <td>{FormatLicense(license)}</td>");
            sb.AppendLine($"        <td><span class=\"category-badge {categoryClass}\">{category}</span></td>");
            sb.AppendLine($"        <td>{count}</td>");
            sb.AppendLine($"      </tr>");
        }

        sb.AppendLine("    </tbody>");
        sb.AppendLine("  </table>");
        sb.AppendLine("</div>");

        // Compatibility issues
        if (licenseReport.CompatibilityResults.Count > 0)
        {
            var issues = licenseReport.CompatibilityResults.Where(r => !r.IsCompatible).ToList();
            if (issues.Count > 0)
            {
                sb.AppendLine("<div class=\"license-issues\">");
                sb.AppendLine("  <h3>Compatibility Issues</h3>");
                foreach (var issue in issues)
                {
                    var issueClass = issue.Severity.ToLowerInvariant();
                    sb.AppendLine($"  <div class=\"issue-item {issueClass}\">");
                    sb.AppendLine($"    <span class=\"issue-severity\">{issue.Severity}</span>");
                    sb.AppendLine($"    <span class=\"issue-message\">{EscapeHtml(issue.Message)}</span>");
                    if (!string.IsNullOrEmpty(issue.Recommendation))
                        sb.AppendLine($"    <span class=\"issue-recommendation\">{EscapeHtml(issue.Recommendation)}</span>");
                    sb.AppendLine("  </div>");
                }
                sb.AppendLine("</div>");
            }
        }

        // Unknown licenses
        if (licenseReport.UnknownLicenses.Count > 0)
        {
            sb.AppendLine("<div class=\"unknown-licenses\">");
            sb.AppendLine("  <h3>Unrecognized Licenses</h3>");
            sb.AppendLine("  <p>The following licenses could not be automatically categorized:</p>");
            sb.AppendLine("  <ul>");
            foreach (var license in licenseReport.UnknownLicenses.Take(20))
            {
                sb.AppendLine($"    <li><code>{EscapeHtml(license)}</code></li>");
            }
            if (licenseReport.UnknownLicenses.Count > 20)
                sb.AppendLine($"    <li><em>...and {licenseReport.UnknownLicenses.Count - 20} more</em></li>");
            sb.AppendLine("  </ul>");
            sb.AppendLine("</div>");
        }
    }

    private void GenerateVulnerabilitiesSection(StringBuilder sb, CraReport report)
    {
        sb.AppendLine("<div class=\"section-header\">");
        sb.AppendLine("  <h2>Vulnerability Status (VEX)</h2>");
        sb.AppendLine("</div>");

        var statements = report.Vex.Statements;
        // Single pass partition instead of dual Where() filters
        var affectedStatements = new List<VexStatement>();
        var safeStatements = new List<VexStatement>();
        foreach (var s in statements)
        {
            (s.Status == VexStatus.Affected ? affectedStatements : safeStatements).Add(s);
        }

        // Summary: focus on what needs action
        if (affectedStatements.Count == 0)
        {
            sb.AppendLine("<div class=\"card empty-state success\">");
            sb.AppendLine("  <div class=\"empty-icon\">&#10003;</div>");
            sb.AppendLine("  <h3>No Vulnerabilities Requiring Action</h3>");
            if (safeStatements.Count > 0)
            {
                sb.AppendLine($"  <p>{safeStatements.Count} vulnerabilities were checked - your package versions are safe.</p>");
            }
            else
            {
                sb.AppendLine("  <p>No known vulnerabilities found in your packages.</p>");
            }
            sb.AppendLine("</div>");

            // Show reviewed items in collapsible section for audit
            if (safeStatements.Count > 0)
            {
                sb.AppendLine("<div class=\"reviewed-vulns-section\">");
                sb.AppendLine("  <div class=\"reviewed-header\" onclick=\"toggleReviewedVulns()\">");
                sb.AppendLine($"    <span>Show {safeStatements.Count} reviewed vulnerabilities (for audit)</span>");
                sb.AppendLine("    <span id=\"reviewed-toggle\">+</span>");
                sb.AppendLine("  </div>");
                sb.AppendLine("  <div id=\"reviewed-vulns-list\" class=\"vulnerabilities-list\" style=\"display:none;\">");
                foreach (var stmt in safeStatements)
                {
                    GenerateVulnerabilityCard(sb, stmt);
                }
                sb.AppendLine("  </div>");
                sb.AppendLine("</div>");
            }
            return;
        }

        // Show count of vulnerabilities needing action
        sb.AppendLine("<div class=\"vuln-alert\">");
        sb.AppendLine($"  <span class=\"vuln-alert-icon\">&#9888;</span>");
        sb.AppendLine($"  <span class=\"vuln-alert-text\"><strong>{affectedStatements.Count}</strong> vulnerabilit{(affectedStatements.Count == 1 ? "y requires" : "ies require")} action</span>");
        if (safeStatements.Count > 0)
        {
            sb.AppendLine($"  <span class=\"vuln-safe-note\">({safeStatements.Count} others checked and safe)</span>");
        }
        sb.AppendLine("</div>");

        // Show affected vulnerabilities
        sb.AppendLine("<div class=\"vulnerabilities-list\">");
        foreach (var stmt in affectedStatements)
        {
            GenerateVulnerabilityCard(sb, stmt);
        }
        sb.AppendLine("</div>");

        // Show reviewed items in collapsible section
        if (safeStatements.Count > 0)
        {
            sb.AppendLine("<div class=\"reviewed-vulns-section\">");
            sb.AppendLine("  <div class=\"reviewed-header\" onclick=\"toggleReviewedVulns()\">");
            sb.AppendLine($"    <span>Show {safeStatements.Count} reviewed vulnerabilities (safe)</span>");
            sb.AppendLine("    <span id=\"reviewed-toggle\">+</span>");
            sb.AppendLine("  </div>");
            sb.AppendLine("  <div id=\"reviewed-vulns-list\" class=\"vulnerabilities-list\" style=\"display:none;\">");
            foreach (var stmt in safeStatements)
            {
                GenerateVulnerabilityCard(sb, stmt);
            }
            sb.AppendLine("  </div>");
            sb.AppendLine("</div>");
        }
    }

    private void GenerateVulnerabilityCard(StringBuilder sb, VexStatement stmt)
    {
        var statusClass = stmt.Status switch
        {
            VexStatus.Affected => "affected",
            VexStatus.Fixed => "fixed",
            _ => "not-affected"
        };

        var statusLabel = stmt.Status switch
        {
            VexStatus.Affected => "ACTION REQUIRED",
            VexStatus.Fixed => "PATCHED",
            _ => "NOT APPLICABLE"
        };

        sb.AppendLine($"  <div class=\"vuln-card {statusClass}\">");
        sb.AppendLine("    <div class=\"vuln-header\">");
        sb.AppendLine($"      <a href=\"{EscapeHtml(stmt.Vulnerability.Id)}\" target=\"_blank\" class=\"vuln-id\">{EscapeHtml(stmt.Vulnerability.Name)}</a>");
        sb.AppendLine($"      <span class=\"vuln-status {statusClass}\">{statusLabel}</span>");
        sb.AppendLine("    </div>");

        var description = !string.IsNullOrWhiteSpace(stmt.Vulnerability.Description)
            ? stmt.Vulnerability.Description
            : "No description available. Click the vulnerability ID above for details.";
        sb.AppendLine($"    <p class=\"vuln-description\">{EscapeHtml(description)}</p>");

        sb.AppendLine("    <div class=\"vuln-products\">");
        foreach (var product in stmt.Products)
        {
            sb.AppendLine($"      <div class=\"vuln-package-info\">");
            sb.AppendLine($"        <strong>Package:</strong> <code>{EscapeHtml(product.Identifiers.Purl)}</code>");
            if (stmt.Status == VexStatus.Fixed)
            {
                sb.AppendLine($"        <span class=\"vuln-patched-note\">&#10003; Your version includes the fix</span>");
            }
            else if (stmt.Status == VexStatus.Affected)
            {
                sb.AppendLine($"        <span class=\"vuln-affected-note\">&#9888; Your version is vulnerable</span>");
                if (!string.IsNullOrEmpty(stmt.PatchedVersion))
                {
                    sb.AppendLine($"        <span class=\"vuln-fixed-in\">Fixed in {EscapeHtml(stmt.PatchedVersion)}</span>");
                }
            }
            sb.AppendLine($"      </div>");
        }
        sb.AppendLine("    </div>");

        if (!string.IsNullOrEmpty(stmt.ActionStatement) && stmt.Status == VexStatus.Affected)
        {
            sb.AppendLine($"    <div class=\"vuln-action\"><strong>Recommended Action:</strong> {EscapeHtml(stmt.ActionStatement)}</div>");
        }
        if (stmt.Vulnerability.Aliases?.Count > 0)
        {
            sb.AppendLine($"    <div class=\"vuln-aliases\"><strong>CVEs:</strong> {string.Join(", ", stmt.Vulnerability.Aliases.Select(EscapeHtml))}</div>");

            // EPSS scores for each CVE
            var cveEpssEntries = stmt.Vulnerability.Aliases
                .Where(cve => _epssScores.ContainsKey(cve) && _epssScores[cve].Probability > 0)
                .Select(cve => _epssScores[cve])
                .OrderByDescending(s => s.Probability)
                .ToList();

            if (cveEpssEntries.Count > 0)
            {
                sb.AppendLine("    <div class=\"vuln-epss\">");
                sb.AppendLine("      <strong>EPSS (Exploit Probability):</strong>");
                foreach (var epss in cveEpssEntries)
                {
                    var pct = (epss.Probability * 100).ToString("F1");
                    var percentile = (int)(epss.Percentile * 100);
                    var badgeClass = GetEpssBadgeClass(epss.Probability);
                    sb.AppendLine($"      <span class=\"epss-badge {badgeClass}\" title=\"{EscapeHtml(epss.Cve)}: {pct}% chance of exploitation in 30 days (percentile: {percentile})\">{EscapeHtml(epss.Cve)} {pct}% <small>p{percentile}</small></span>");
                }
                sb.AppendLine("    </div>");
            }
        }
        sb.AppendLine("  </div>");
    }

    // =============================================
    // v1.2 CRA Detail Sections
    // =============================================

    private void GenerateRemediationSection(StringBuilder sb)
    {
        sb.AppendLine("<div class=\"section-header\">");
        sb.AppendLine("  <h2>Remediation Actions</h2>");
        sb.AppendLine("</div>");

        sb.AppendLine("<div class=\"info-box\">");
        sb.AppendLine("  <div class=\"info-box-title\">What is this?</div>");
        sb.AppendLine("  <p>These are known security vulnerabilities in your dependencies that already have a fix available &mdash; you just need to update the package version. The <strong>Days Overdue</strong> column shows how long the fix has been available but not applied.</p>");
        sb.AppendLine("  <p style=\"margin-top:8px;\"><strong>What to do:</strong> Run <code>dotnet add package [name] --version [patch version]</code> or update your <code>package.json</code> to the patched version shown below. Prioritize packages marked in red first.</p>");
        sb.AppendLine("</div>");

        var sorted = _remediationData.OrderByDescending(r => r.DaysSince).ToList();

        sb.AppendLine("<table class=\"detail-table\">");
        sb.AppendLine("  <thead><tr>");
        sb.AppendLine("    <th title=\"The package that contains the vulnerability\">Package</th>");
        sb.AppendLine("    <th title=\"The vulnerability identifier &mdash; search this on osv.dev for full details\">Vulnerability</th>");
        sb.AppendLine("    <th title=\"Update to this version to fix the vulnerability\">Update To</th>");
        sb.AppendLine("    <th title=\"How many days this fix has been available. Red = 30+ days, Yellow = 7-29 days\">Days Overdue</th>");
        sb.AppendLine("  </tr></thead>");
        sb.AppendLine("  <tbody>");

        foreach (var item in sorted)
        {
            var urgencyClass = item.DaysSince >= 30 ? "critical" : item.DaysSince >= 7 ? "warning" : "ok";
            sb.AppendLine("    <tr>");
            sb.AppendLine($"      <td><strong>{EscapeHtml(item.PackageId)}</strong></td>");
            sb.AppendLine($"      <td><a href=\"https://osv.dev/vulnerability/{EscapeHtml(item.VulnId)}\" target=\"_blank\" style=\"color:var(--accent);text-decoration:none;\"><code>{EscapeHtml(item.VulnId)}</code></a></td>");
            sb.AppendLine($"      <td><code>{EscapeHtml(item.PatchVersion)}</code></td>");
            sb.AppendLine($"      <td><span class=\"days-overdue {urgencyClass}\">{item.DaysSince} days</span></td>");
            sb.AppendLine("    </tr>");
        }

        sb.AppendLine("  </tbody>");
        sb.AppendLine("</table>");
    }

    private void GenerateAttackSurfaceSection(StringBuilder sb)
    {
        sb.AppendLine("<div class=\"section-header\">");
        sb.AppendLine("  <h2>Attack Surface Analysis</h2>");
        sb.AppendLine("</div>");

        sb.AppendLine("<div class=\"info-box\">");
        sb.AppendLine("  <div class=\"info-box-title\">What is this?</div>");
        sb.AppendLine("  <p>Every dependency you add also pulls in its own dependencies (called <strong>transitive</strong> dependencies). These are packages you didn't choose, but any vulnerability in them affects your project. This section measures how wide and deep your dependency tree is.</p>");
        sb.AppendLine("  <p style=\"margin-top:8px;\"><strong>Why it matters:</strong> A high ratio means each package you add brings many hidden dependencies. A deep tree means vulnerabilities can hide several layers down, making them hard to track and update.</p>");
        sb.AppendLine("</div>");

        var surface = _attackSurface!;

        // Metric cards
        var ratioClass = surface.TransitiveToDirectRatio < 5.0 ? "ok" : surface.TransitiveToDirectRatio >= 10.0 ? "critical" : "warning";
        var depthClass = surface.MaxDepth < 8 ? "ok" : surface.MaxDepth >= 12 ? "critical" : "warning";

        sb.AppendLine("<div class=\"surface-metrics\">");
        sb.AppendLine("  <div class=\"surface-metric\" title=\"Packages you explicitly added to your project (in .csproj or package.json).\">");
        sb.AppendLine($"    <div class=\"metric-big\">{surface.DirectCount}</div>");
        sb.AppendLine("    <div class=\"metric-label\">Direct Dependencies</div>");
        sb.AppendLine("    <div class=\"metric-hint\">Packages you chose</div>");
        sb.AppendLine("  </div>");
        sb.AppendLine("  <div class=\"surface-metric\" title=\"Packages pulled in automatically by your direct dependencies. You didn't choose these, but they run in your project.\">");
        sb.AppendLine($"    <div class=\"metric-big\">{surface.TransitiveCount}</div>");
        sb.AppendLine("    <div class=\"metric-label\">Transitive Dependencies</div>");
        sb.AppendLine("    <div class=\"metric-hint\">Pulled in automatically</div>");
        sb.AppendLine("  </div>");
        sb.AppendLine("  <div class=\"surface-metric\" title=\"For every 1 package you add, this many come along as transitive dependencies. Lower is better. Under 5:1 is healthy, over 10:1 means your tree is very wide.\">");
        sb.AppendLine($"    <div class=\"metric-big days-overdue {ratioClass}\">{surface.TransitiveToDirectRatio}:1</div>");
        sb.AppendLine("    <div class=\"metric-label\">Hidden Dependency Ratio</div>");
        sb.AppendLine($"    <div class=\"metric-hint\">{(surface.TransitiveToDirectRatio < 5.0 ? "Healthy" : surface.TransitiveToDirectRatio >= 10.0 ? "Very wide &mdash; consider alternatives" : "Wider than ideal")}</div>");
        sb.AppendLine("  </div>");
        sb.AppendLine("  <div class=\"surface-metric\" title=\"The deepest chain of dependencies. A depth of 8+ means updates to a deep package need to propagate through many layers before reaching you.\">");
        sb.AppendLine($"    <div class=\"metric-big days-overdue {depthClass}\">{surface.MaxDepth}</div>");
        sb.AppendLine("    <div class=\"metric-label\">Deepest Chain</div>");
        sb.AppendLine($"    <div class=\"metric-hint\">{(surface.MaxDepth < 8 ? "Manageable depth" : surface.MaxDepth >= 12 ? "Very deep &mdash; slow to patch" : "Deeper than ideal")}</div>");
        sb.AppendLine("  </div>");
        sb.AppendLine("</div>");

        // Thresholds reference - make it a table for clarity
        sb.AppendLine("<div class=\"card\" style=\"margin-top:12px; padding:14px;\">");
        sb.AppendLine("  <strong>How to read these numbers</strong>");
        sb.AppendLine("  <table style=\"margin-top:8px;width:100%;font-size:0.9rem;\">");
        sb.AppendLine("    <tr><td style=\"color:var(--healthy);padding:4px 8px;\">&#9679; Good</td><td>Ratio under 5:1, depth under 8 &mdash; manageable supply chain</td></tr>");
        sb.AppendLine("    <tr><td style=\"color:var(--warning);padding:4px 8px;\">&#9679; Review</td><td>Ratio 5:1&ndash;10:1 or depth 8&ndash;11 &mdash; consider if all dependencies are needed</td></tr>");
        sb.AppendLine("    <tr><td style=\"color:var(--critical);padding:4px 8px;\">&#9679; Action</td><td>Ratio over 10:1 or depth 12+ &mdash; evaluate lighter alternatives for heavy packages</td></tr>");
        sb.AppendLine("  </table>");
        sb.AppendLine("</div>");

        // Heavy packages table
        if (surface.HeavyPackages.Count > 0)
        {
            sb.AppendLine("<h3 style=\"margin-top:20px;\">Heavy Packages</h3>");
            sb.AppendLine("<p style=\"color:var(--text-secondary);margin-bottom:12px;\">These packages each bring in over 20 transitive dependencies. They are the biggest contributors to your attack surface. Consider whether lighter alternatives exist.</p>");
            sb.AppendLine("<table class=\"detail-table\">");
            sb.AppendLine("  <thead><tr>");
            sb.AppendLine("    <th title=\"The direct dependency that pulls in many transitive packages\">Package</th>");
            sb.AppendLine("    <th title=\"How many additional packages this one brings into your project\">Hidden Packages Brought In</th>");
            sb.AppendLine("  </tr></thead>");
            sb.AppendLine("  <tbody>");

            foreach (var (packageId, count) in surface.HeavyPackages)
            {
                var weight = count >= 100 ? "critical" : count >= 50 ? "warning" : "";
                sb.AppendLine("    <tr>");
                sb.AppendLine($"      <td><strong>{EscapeHtml(packageId)}</strong></td>");
                sb.AppendLine($"      <td><span class=\"{weight}\">{count} packages</span></td>");
                sb.AppendLine("    </tr>");
            }

            sb.AppendLine("  </tbody>");
            sb.AppendLine("</table>");
        }
    }

    private void GenerateSbomQualitySection(StringBuilder sb)
    {
        sb.AppendLine("<div class=\"section-header\">");
        sb.AppendLine("  <h2>SBOM Quality</h2>");
        sb.AppendLine("</div>");

        sb.AppendLine("<div class=\"info-box\">");
        sb.AppendLine("  <div class=\"info-box-title\">What is this?</div>");
        sb.AppendLine("  <p>A <strong>Software Bill of Materials (SBOM)</strong> is a list of every component in your project &mdash; like a nutrition label for software. The EU Cyber Resilience Act requires SBOMs to include specific fields for each package so that vulnerabilities can be traced and managed.</p>");
        sb.AppendLine("  <p style=\"margin-top:8px;\">This section checks how complete your SBOM data is. A score of <strong>90% or higher</strong> means your SBOM meets the quality bar for CRA compliance. Missing fields don't block your build, but they weaken your ability to respond to security incidents.</p>");
        sb.AppendLine("</div>");

        var v = _sbomValidation!;
        var completeness = v.CompletenessPercent;
        var barClass = completeness >= 90 ? "high" : completeness >= 70 ? "medium" : "low";

        // Overall completeness bar
        sb.AppendLine("<div style=\"margin: 20px 0;\">");
        sb.AppendLine("  <div style=\"display: flex; justify-content: space-between; margin-bottom: 6px;\">");
        sb.AppendLine("    <strong>Overall Data Completeness</strong>");
        sb.AppendLine($"    <strong class=\"{barClass}\">{completeness}%</strong>");
        sb.AppendLine("  </div>");
        sb.AppendLine("  <div class=\"progress-bar-container\">");
        sb.AppendLine($"    <div class=\"progress-bar-fill {barClass}\" style=\"width: {completeness}%\">{completeness}%</div>");
        sb.AppendLine("  </div>");
        sb.AppendLine($"  <div style=\"color:var(--text-secondary);font-size:0.85rem;margin-top:6px;\">{(completeness >= 90 ? "Meets CRA quality requirements." : completeness >= 70 ? "Close to target &mdash; address the gaps below to reach 90%." : "Significant gaps &mdash; review which fields are missing below.")}</div>");
        sb.AppendLine("</div>");

        // Per-field breakdown
        sb.AppendLine("<h3>Field-by-Field Breakdown</h3>");
        sb.AppendLine("<p style=\"color:var(--text-secondary);margin-bottom:16px;\">Each card shows how many of your packages have that field populated. Hover for details on what each field means.</p>");
        sb.AppendLine("<div class=\"field-grid\">");

        // Document-level fields
        AppendFieldCard(sb, "Timestamp", v.HasTimestamp ? "Present" : "Missing", v.HasTimestamp,
            "When the SBOM was generated. Needed to know if your inventory is current.");
        AppendFieldCard(sb, "Creator Tool", v.HasCreator ? "Present" : "Missing", v.HasCreator,
            "Which tool generated the SBOM. Helps verify the data source is trustworthy.");

        // Package-level fields
        if (v.TotalPackages > 0)
        {
            AppendFieldCardWithBar(sb, "Supplier", v.WithSupplier, v.TotalPackages,
                "Who published the package. Needed to contact maintainers about vulnerabilities.");
            AppendFieldCardWithBar(sb, "License", v.WithLicense, v.TotalPackages,
                "The license under which the package is distributed. Required for legal compliance.");
            AppendFieldCardWithBar(sb, "Package URL (PURL)", v.WithPurl, v.TotalPackages,
                "A universal identifier (like pkg:nuget/Newtonsoft.Json@13.0.1) that uniquely identifies the exact package version across all registries.");
            AppendFieldCardWithBar(sb, "Checksum", v.WithChecksum, v.TotalPackages,
                "A cryptographic hash verifying the package hasn't been tampered with since download.");
        }

        sb.AppendLine("</div>");
    }

    private static void AppendFieldCard(StringBuilder sb, string label, string value, bool ok, string tooltip)
    {
        sb.AppendLine($"  <div class=\"field-card\" title=\"{EscapeHtml(tooltip)}\">");
        sb.AppendLine($"    <div class=\"field-label\">{EscapeHtml(label)}</div>");
        sb.AppendLine($"    <div class=\"field-value\"><span class=\"status-pill {(ok ? "signed" : "unsigned")}\">{EscapeHtml(value)}</span></div>");
        sb.AppendLine("  </div>");
    }

    private static void AppendFieldCardWithBar(StringBuilder sb, string label, int count, int total, string tooltip)
    {
        var pct = total > 0 ? (int)Math.Round(100.0 * count / total) : 0;
        var barClass = pct >= 90 ? "high" : pct >= 70 ? "medium" : "low";
        sb.AppendLine($"  <div class=\"field-card\" title=\"{EscapeHtml(tooltip)}\">");
        sb.AppendLine($"    <div class=\"field-label\">{EscapeHtml(label)}</div>");
        sb.AppendLine($"    <div style=\"display:flex;justify-content:space-between;margin-bottom:4px;\"><span>{count}/{total} packages</span><span>{pct}%</span></div>");
        sb.AppendLine($"    <div class=\"progress-bar-container\"><div class=\"progress-bar-fill {barClass}\" style=\"width:{pct}%\"></div></div>");
        sb.AppendLine("  </div>");
    }

    private void GenerateProvenanceSection(StringBuilder sb)
    {
        sb.AppendLine("<div class=\"section-header\">");
        sb.AppendLine("  <h2>Package Provenance</h2>");
        sb.AppendLine("</div>");

        sb.AppendLine("<div class=\"info-box\">");
        sb.AppendLine("  <div class=\"info-box-title\">What is this?</div>");
        sb.AppendLine("  <p><strong>Provenance</strong> means verifying that a package actually came from its claimed source. When NuGet signs a package, it creates a cryptographic proof that the package was published through the official registry and hasn't been tampered with.</p>");
        sb.AppendLine("  <p style=\"margin-top:8px;\"><strong>Why it matters:</strong> Supply chain attacks work by injecting malicious code into packages. Signed packages are harder to tamper with. Unsigned packages aren't necessarily dangerous, but they lack this verification layer.</p>");
        sb.AppendLine("</div>");

        var verified = _provenanceResults.Count(r => r.IsVerified);
        var total = _provenanceResults.Count;
        var pct = total > 0 ? (int)Math.Round(100.0 * verified / total) : 0;

        // Summary bar
        var barClass = pct >= 90 ? "high" : pct >= 50 ? "medium" : "low";
        sb.AppendLine("<div style=\"margin: 15px 0;\">");
        sb.AppendLine("  <div style=\"display: flex; justify-content: space-between; margin-bottom: 6px;\">");
        sb.AppendLine($"    <strong>{verified} of {total} packages verified</strong>");
        sb.AppendLine($"    <strong class=\"{barClass}\">{pct}%</strong>");
        sb.AppendLine("  </div>");
        sb.AppendLine("  <div class=\"progress-bar-container\">");
        sb.AppendLine($"    <div class=\"progress-bar-fill {barClass}\" style=\"width: {pct}%\">{pct}% signed</div>");
        sb.AppendLine("  </div>");
        sb.AppendLine("</div>");

        // Show unsigned packages first (they need attention)
        var unsigned = _provenanceResults.Where(r => !r.IsVerified).OrderBy(r => r.PackageId).ToList();
        var signed = _provenanceResults.Where(r => r.IsVerified).OrderBy(r => r.PackageId).ToList();

        if (unsigned.Count > 0)
        {
            sb.AppendLine("<h3>Unsigned Packages</h3>");
            sb.AppendLine("<p style=\"color:var(--text-secondary);margin-bottom:12px;\">These packages could not be verified through NuGet repository signatures. This is common for npm packages (signing support is newer) and some smaller NuGet packages. It doesn't mean they're malicious &mdash; but extra review may be warranted.</p>");
            sb.AppendLine("<table class=\"detail-table\">");
            sb.AppendLine("  <thead><tr>");
            sb.AppendLine("    <th title=\"The package that couldn't be verified\">Package</th>");
            sb.AppendLine("    <th>Version</th>");
            sb.AppendLine("    <th title=\"NuGet or npm\">Ecosystem</th>");
            sb.AppendLine("    <th>Status</th>");
            sb.AppendLine("  </tr></thead>");
            sb.AppendLine("  <tbody>");
            foreach (var p in unsigned)
            {
                sb.AppendLine("    <tr>");
                sb.AppendLine($"      <td><strong>{EscapeHtml(p.PackageId)}</strong></td>");
                sb.AppendLine($"      <td>{EscapeHtml(p.Version)}</td>");
                sb.AppendLine($"      <td>{p.Ecosystem}</td>");
                sb.AppendLine("      <td><span class=\"status-pill unsigned\">Unsigned</span></td>");
                sb.AppendLine("    </tr>");
            }
            sb.AppendLine("  </tbody></table>");
        }

        if (signed.Count > 0)
        {
            sb.AppendLine($"<details style=\"margin-top:16px;\"><summary><strong>Signed Packages ({signed.Count})</strong> &mdash; click to expand</summary>");
            sb.AppendLine("<p style=\"color:var(--text-secondary);margin:8px 0;\">These packages have verified signatures, meaning they were published through official channels and haven't been modified in transit.</p>");
            sb.AppendLine("<table class=\"detail-table\">");
            sb.AppendLine("  <thead><tr><th>Package</th><th>Version</th><th>Ecosystem</th><th>Signature Type</th></tr></thead>");
            sb.AppendLine("  <tbody>");
            foreach (var p in signed)
            {
                var signType = p.HasAuthorSignature ? "Author + Repository" : "Repository";
                var signHint = p.HasAuthorSignature ? "Signed by both the author and the registry" : "Signed by the package registry";
                sb.AppendLine("    <tr>");
                sb.AppendLine($"      <td><strong>{EscapeHtml(p.PackageId)}</strong></td>");
                sb.AppendLine($"      <td>{EscapeHtml(p.Version)}</td>");
                sb.AppendLine($"      <td>{p.Ecosystem}</td>");
                sb.AppendLine($"      <td><span class=\"status-pill signed\" title=\"{signHint}\">{signType}</span></td>");
                sb.AppendLine("    </tr>");
            }
            sb.AppendLine("  </tbody></table>");
            sb.AppendLine("</details>");
        }
    }

    private void GenerateMaintenanceSection(StringBuilder sb)
    {
        sb.AppendLine("<div class=\"section-header\">");
        sb.AppendLine("  <h2>Maintenance Status</h2>");
        sb.AppendLine("</div>");

        sb.AppendLine("<div class=\"info-box\">");
        sb.AppendLine("  <div class=\"info-box-title\">What is this?</div>");
        sb.AppendLine("  <p>This checks whether the open-source projects behind your dependencies are still being actively developed. If a project's GitHub repository is <strong>archived</strong> (read-only) or has had <strong>no commits for a long time</strong>, security patches won't be available when vulnerabilities are discovered.</p>");
        sb.AppendLine("  <p style=\"margin-top:8px;\"><strong>What to do:</strong> Archived and unmaintained packages should be replaced with actively maintained alternatives. Stale packages may still be fine (some libraries are \"done\"), but keep an eye on them.</p>");
        sb.AppendLine("</div>");

        // Summary metrics
        var activeCount = _totalWithRepoData - _archivedPackageNames.Count - _stalePackageNames.Count;
        sb.AppendLine("<div class=\"surface-metrics\">");
        sb.AppendLine($"  <div class=\"surface-metric\" title=\"How many of your packages we could find GitHub repository data for. Packages without repo data are not shown here.\">");
        sb.AppendLine($"    <div class=\"metric-big\">{_totalWithRepoData}</div>");
        sb.AppendLine("    <div class=\"metric-label\">Packages Checked</div>");
        sb.AppendLine("    <div class=\"metric-hint\">With GitHub repo data</div>");
        sb.AppendLine("  </div>");
        sb.AppendLine($"  <div class=\"surface-metric\" title=\"Repositories marked as archived (read-only) by their owner. No further updates, bug fixes, or security patches will be released.\">");
        sb.AppendLine($"    <div class=\"metric-big days-overdue {(_archivedPackageNames.Count > 0 ? "critical" : "ok")}\">{_archivedPackageNames.Count}</div>");
        sb.AppendLine("    <div class=\"metric-label\">Archived</div>");
        sb.AppendLine("    <div class=\"metric-hint\">No future updates possible</div>");
        sb.AppendLine("  </div>");
        sb.AppendLine($"  <div class=\"surface-metric\" title=\"Packages whose GitHub repository has had no commits in over 1 year. May still be fine for stable libraries, but monitor closely.\">");
        sb.AppendLine($"    <div class=\"metric-big days-overdue {(_stalePackageNames.Count > 0 ? "warning" : "ok")}\">{_stalePackageNames.Count}</div>");
        sb.AppendLine("    <div class=\"metric-label\">Stale</div>");
        sb.AppendLine("    <div class=\"metric-hint\">No commits in 1+ year</div>");
        sb.AppendLine("  </div>");
        sb.AppendLine($"  <div class=\"surface-metric\" title=\"Packages with no commits in over 2 years. High risk of not receiving security patches. Strongly consider replacing.\">");
        sb.AppendLine($"    <div class=\"metric-big days-overdue {(_unmaintainedPackageNames.Count > 0 ? "critical" : "ok")}\">{_unmaintainedPackageNames.Count}</div>");
        sb.AppendLine("    <div class=\"metric-label\">Unmaintained</div>");
        sb.AppendLine("    <div class=\"metric-hint\">No commits in 2+ years</div>");
        sb.AppendLine("  </div>");
        sb.AppendLine("</div>");

        if (_archivedPackageNames.Count > 0)
        {
            sb.AppendLine("<div class=\"maintenance-group\">");
            sb.AppendLine("  <h4>Archived Repositories</h4>");
            sb.AppendLine("  <p style=\"margin:0 0 8px;color:var(--text-secondary);font-size:0.9rem;\">The owner has made these repositories read-only. No bug fixes or security patches will be released. You should find replacement packages.</p>");
            sb.AppendLine("  <div class=\"maintenance-list\">");
            foreach (var pkg in _archivedPackageNames)
            {
                sb.AppendLine($"    <span class=\"maintenance-pkg\"><span class=\"status-pill archived\">Archived</span> {EscapeHtml(pkg)}</span>");
            }
            sb.AppendLine("  </div>");
            sb.AppendLine("</div>");
        }

        if (_stalePackageNames.Count > 0)
        {
            sb.AppendLine("<div class=\"maintenance-group\">");
            sb.AppendLine("  <h4>Stale Packages</h4>");
            sb.AppendLine("  <p style=\"margin:0 0 8px;color:var(--text-secondary);font-size:0.9rem;\">No commits in over a year. Some libraries are stable and \"done\" (e.g., math utilities), but others may simply be abandoned. Check if alternatives exist.</p>");
            sb.AppendLine("  <div class=\"maintenance-list\">");
            foreach (var pkg in _stalePackageNames)
            {
                var alsoUnmaintained = _unmaintainedPackageNames.Contains(pkg);
                var pillClass = alsoUnmaintained ? "unmaintained" : "stale";
                var pillLabel = alsoUnmaintained ? "2+ years" : "1+ year";
                sb.AppendLine($"    <span class=\"maintenance-pkg\"><span class=\"status-pill {pillClass}\">{pillLabel}</span> {EscapeHtml(pkg)}</span>");
            }
            sb.AppendLine("  </div>");
            sb.AppendLine("</div>");
        }

        // Show healthy count
        if (activeCount > 0)
        {
            sb.AppendLine("<div class=\"maintenance-group\">");
            sb.AppendLine($"  <h4>Actively Maintained ({activeCount} packages)</h4>");
            sb.AppendLine("  <p style=\"margin:0;color:var(--text-secondary);font-size:0.9rem;\">These packages have commits within the last year &mdash; they're likely to receive security patches when needed.</p>");
            sb.AppendLine("</div>");
        }
    }

    private void GenerateComplianceSection(StringBuilder sb, CraReport report)
    {
        sb.AppendLine("<div class=\"section-header\">");
        sb.AppendLine("  <h2>CRA Compliance Checklist</h2>");
        sb.AppendLine("</div>");

        sb.AppendLine("<div class=\"compliance-list\">");

        foreach (var item in report.ComplianceItems)
        {
            var statusClass = item.Status switch
            {
                CraComplianceStatus.Compliant => "compliant",
                CraComplianceStatus.ActionRequired => "action-required",
                _ => "non-compliant"
            };

            sb.AppendLine($"  <div class=\"compliance-item {statusClass}\">");
            sb.AppendLine("    <div class=\"compliance-header\">");
            sb.AppendLine($"      <div class=\"compliance-icon\">{(item.Status == CraComplianceStatus.Compliant ? "&#10003;" : item.Status == CraComplianceStatus.ActionRequired ? "!" : "&#10007;")}</div>");
            sb.AppendLine("      <div class=\"compliance-info\">");
            sb.AppendLine($"        <h3>{EscapeHtml(item.Requirement)}</h3>");
            sb.AppendLine($"        <p>{EscapeHtml(item.Description)}</p>");
            sb.AppendLine("      </div>");
            sb.AppendLine($"      <span class=\"compliance-status {statusClass}\">{item.Status}</span>");
            sb.AppendLine("    </div>");
            sb.AppendLine("    <div class=\"compliance-evidence\">");
            sb.AppendLine($"      <strong>Evidence:</strong> {EscapeHtml(item.Evidence ?? "N/A")}");
            sb.AppendLine("    </div>");
            if (!string.IsNullOrEmpty(item.Recommendation))
            {
                sb.AppendLine($"    <div class=\"compliance-recommendation\">");
                sb.AppendLine($"      <strong>Recommendation:</strong> {EscapeHtml(item.Recommendation)}");
                sb.AppendLine("    </div>");
            }
            sb.AppendLine("  </div>");
        }

        sb.AppendLine("</div>");
    }

    private void GenerateSupplyChainSection(StringBuilder sb)
    {
        sb.AppendLine("<div class=\"section-header\">");
        sb.AppendLine("  <h2>Supply Chain Analysis</h2>");
        sb.AppendLine("</div>");

        if (_typosquatResults.Count == 0)
        {
            sb.AppendLine("<div class=\"card typosquat-success\">");
            sb.AppendLine("  <div class=\"empty-icon\">&#9989;</div>");
            sb.AppendLine("  <h3>No Typosquatting Issues Detected</h3>");
            sb.AppendLine("  <p>All dependency names were verified against known popular packages. No suspicious name similarities were found.</p>");
            sb.AppendLine("</div>");
            return;
        }

        // Summary stats
        var criticalCount = _typosquatResults.Count(r => r.RiskLevel == TyposquatRiskLevel.Critical);
        var highCount = _typosquatResults.Count(r => r.RiskLevel == TyposquatRiskLevel.High);
        var mediumCount = _typosquatResults.Count(r => r.RiskLevel == TyposquatRiskLevel.Medium);
        var lowCount = _typosquatResults.Count(r => r.RiskLevel == TyposquatRiskLevel.Low);

        sb.AppendLine("<div class=\"typosquat-summary\">");
        sb.AppendLine($"  <div class=\"typosquat-stat-card\"><span class=\"typosquat-stat-count\">{_typosquatResults.Count}</span><span class=\"typosquat-stat-label\">Total Warnings</span></div>");
        if (criticalCount > 0)
            sb.AppendLine($"  <div class=\"typosquat-stat-card critical\"><span class=\"typosquat-stat-count\">{criticalCount}</span><span class=\"typosquat-stat-label\">Critical</span></div>");
        if (highCount > 0)
            sb.AppendLine($"  <div class=\"typosquat-stat-card high\"><span class=\"typosquat-stat-count\">{highCount}</span><span class=\"typosquat-stat-label\">High</span></div>");
        if (mediumCount > 0)
            sb.AppendLine($"  <div class=\"typosquat-stat-card medium\"><span class=\"typosquat-stat-count\">{mediumCount}</span><span class=\"typosquat-stat-label\">Medium</span></div>");
        if (lowCount > 0)
            sb.AppendLine($"  <div class=\"typosquat-stat-card low\"><span class=\"typosquat-stat-count\">{lowCount}</span><span class=\"typosquat-stat-label\">Low</span></div>");
        sb.AppendLine("</div>");

        // Results table
        sb.AppendLine("<div class=\"card\">");
        sb.AppendLine("<table class=\"data-table typosquat-table\">");
        sb.AppendLine("  <thead>");
        sb.AppendLine("    <tr>");
        sb.AppendLine("      <th>Risk</th>");
        sb.AppendLine("      <th>Package</th>");
        sb.AppendLine("      <th>Similar To</th>");
        sb.AppendLine("      <th>Detection Method</th>");
        sb.AppendLine("      <th>Confidence</th>");
        sb.AppendLine("      <th>Detail</th>");
        sb.AppendLine("    </tr>");
        sb.AppendLine("  </thead>");
        sb.AppendLine("  <tbody>");

        foreach (var result in _typosquatResults.OrderByDescending(r => r.RiskLevel).ThenByDescending(r => r.Confidence))
        {
            var riskClass = result.RiskLevel switch
            {
                TyposquatRiskLevel.Critical => "typosquat-critical",
                TyposquatRiskLevel.High => "typosquat-high",
                TyposquatRiskLevel.Medium => "typosquat-medium",
                _ => "typosquat-low"
            };

            var methodLabel = result.Method switch
            {
                TyposquatDetectionMethod.EditDistance => "Edit Distance",
                TyposquatDetectionMethod.Homoglyph => "Homoglyph",
                TyposquatDetectionMethod.SeparatorSwap => "Separator Swap",
                TyposquatDetectionMethod.PrefixSuffix => "Prefix/Suffix",
                TyposquatDetectionMethod.ScopeConfusion => "Scope Confusion",
                _ => result.Method.ToString()
            };

            sb.AppendLine("    <tr>");
            sb.AppendLine($"      <td><span class=\"typosquat-risk {riskClass}\">{result.RiskLevel}</span></td>");
            sb.AppendLine($"      <td><code>{EscapeHtml(result.PackageName)}</code></td>");
            sb.AppendLine($"      <td><code>{EscapeHtml(result.SimilarTo)}</code></td>");
            sb.AppendLine($"      <td>{EscapeHtml(methodLabel)}</td>");
            sb.AppendLine($"      <td><span class=\"confidence-bar\"><span class=\"confidence-fill\" style=\"width:{result.Confidence}%\"></span><span class=\"confidence-text\">{result.Confidence}%</span></span></td>");
            sb.AppendLine($"      <td>{EscapeHtml(result.Detail)}</td>");
            sb.AppendLine("    </tr>");
        }

        sb.AppendLine("  </tbody>");
        sb.AppendLine("</table>");
        sb.AppendLine("</div>");
    }

    private void GenerateDependencyTreeSection(StringBuilder sb)
    {
        sb.AppendLine("<div class=\"section-header\">");
        sb.AppendLine("  <h2>Dependency Tree</h2>");
        sb.AppendLine("</div>");

        if (_dependencyTrees.Count == 0 || _dependencyTrees.All(t => t.Roots.Count == 0))
        {
            sb.AppendLine("<div class=\"card empty-state\">");
            sb.AppendLine("  <div class=\"empty-icon\">&#128230;</div>");
            sb.AppendLine("  <h3>No Dependency Tree Available</h3>");
            sb.AppendLine("  <p>Dependency tree data was not generated for this report.</p>");
            sb.AppendLine("</div>");
            return;
        }

        // Overall stats
        var totalPackages = _dependencyTrees.Sum(t => t.TotalPackages);
        var maxDepth = _dependencyTrees.Max(t => t.MaxDepth);
        var vulnerableCount = _dependencyTrees.Sum(t => t.VulnerableCount);

        sb.AppendLine("<div class=\"tree-stats\">");
        sb.AppendLine($"  <span class=\"tree-stat\"><strong>Total Packages:</strong> {totalPackages}</span>");
        sb.AppendLine($"  <span class=\"tree-stat\"><strong>Max Depth:</strong> {maxDepth}</span>");
        if (vulnerableCount > 0)
        {
            sb.AppendLine($"  <span class=\"tree-stat vulnerable\" title=\"Packages with vulnerable sub-dependencies\"><strong>Has Vuln Deps:</strong> {vulnerableCount}</span>");
        }
        if (_dependencyTrees.Count > 1)
        {
            sb.AppendLine($"  <span class=\"tree-stat\"><strong>Ecosystems:</strong> {string.Join(", ", _dependencyTrees.Select(t => t.ProjectType))}</span>");
        }
        else
        {
            sb.AppendLine($"  <span class=\"tree-stat\"><strong>Type:</strong> {_dependencyTrees[0].ProjectType}</span>");
        }
        sb.AppendLine("</div>");

        // Tree controls
        sb.AppendLine("<div class=\"tree-controls\">");
        sb.AppendLine("  <button class=\"tree-btn\" onclick=\"expandAllTree()\">Expand All</button>");
        sb.AppendLine("  <button class=\"tree-btn\" onclick=\"collapseAllTree()\">Collapse All</button>");
        sb.AppendLine("  <input type=\"text\" id=\"tree-search\" class=\"search-input\" placeholder=\"Search packages...\" onkeyup=\"filterTree()\">");
        if (_dependencyTrees.Count > 1)
        {
            sb.AppendLine("  <span class=\"filter-group tree-ecosystem-filter\">");
            sb.AppendLine("    <span class=\"filter-label\">Ecosystem:</span>");
            sb.AppendLine("    <button class=\"filter-btn ecosystem-btn active\" onclick=\"filterTreeByEcosystem('all')\">All</button>");
            sb.AppendLine("    <button class=\"filter-btn ecosystem-btn nuget\" onclick=\"filterTreeByEcosystem('nuget')\">NuGet</button>");
            sb.AppendLine("    <button class=\"filter-btn ecosystem-btn npm\" onclick=\"filterTreeByEcosystem('npm')\">npm</button>");
            sb.AppendLine("  </span>");
        }
        sb.AppendLine("</div>");

        // Generate tree for each ecosystem
        foreach (var tree in _dependencyTrees)
        {
            if (tree.Roots.Count == 0) continue;

            var ecosystemValue = tree.ProjectType == ProjectType.Npm ? "npm" : "nuget";

            // Ecosystem header (only if multiple ecosystems)
            if (_dependencyTrees.Count > 1)
            {
                var ecosystemIcon = tree.ProjectType == ProjectType.Npm ? "📦" : "🔷";
                var ecosystemLabel = tree.ProjectType == ProjectType.Npm ? "npm" : "NuGet";
                sb.AppendLine($"<div class=\"ecosystem-header\" data-ecosystem=\"{ecosystemValue}\">");
                sb.AppendLine($"  <span class=\"ecosystem-icon\">{ecosystemIcon}</span>");
                sb.AppendLine($"  <span class=\"ecosystem-label\">{ecosystemLabel}</span>");
                sb.AppendLine($"  <span class=\"ecosystem-count\">{tree.TotalPackages} packages</span>");
                sb.AppendLine($"</div>");
            }

            // Tree container
            sb.AppendLine($"<div class=\"dependency-tree\" data-ecosystem=\"{ecosystemValue}\">");
            sb.AppendLine("  <ul class=\"tree-root\">");

            foreach (var root in tree.Roots)
            {
                GenerateTreeNode(sb, root, 1);
            }

            sb.AppendLine("  </ul>");
            sb.AppendLine("</div>");
        }
    }

    private void GenerateTreeNode(StringBuilder sb, DependencyTreeNode node, int indent)
    {
        var hasChildren = node.Children.Count > 0;
        var indentStr = new string(' ', indent * 2);

        var nodeClasses = new List<string> { "tree-node" };
        if (node.IsDuplicate) nodeClasses.Add("duplicate");
        if (node.HasVulnerabilities) nodeClasses.Add("has-vuln");
        if (node.HasVulnerableDescendant) nodeClasses.Add("has-vuln-descendant");
        var hasKev = _kevPackageIds.Contains(node.PackageId);
        if (hasKev) nodeClasses.Add("has-kev");

        var scoreClass = node.HealthScore.HasValue ? GetScoreClass(node.HealthScore.Value) : "";

        sb.AppendLine($"{indentStr}<li class=\"{string.Join(" ", nodeClasses)}\" data-name=\"{EscapeHtml(node.PackageId.ToLowerInvariant())}\">");

        if (hasChildren && !node.IsDuplicate)
        {
            // Trees are collapsed by default, so show [+]
            sb.AppendLine($"{indentStr}  <span class=\"tree-toggle\" onclick=\"toggleTreeNode(this)\">[+]</span>");
        }
        else
        {
            sb.AppendLine($"{indentStr}  <span class=\"tree-toggle leaf\">&nbsp;&bull;&nbsp;</span>");
        }

        // Package name as link to registry
        var packageUrl = node.Ecosystem == PackageEcosystem.Npm
            ? $"https://www.npmjs.com/package/{Uri.EscapeDataString(node.PackageId)}"
            : $"https://www.nuget.org/packages/{node.PackageId}";
        sb.AppendLine($"{indentStr}  <a href=\"{EscapeHtml(packageUrl)}\" target=\"_blank\" class=\"node-name\">{EscapeHtml(node.PackageId)}</a>");
        sb.AppendLine($"{indentStr}  <span class=\"node-version\">{EscapeHtml(node.Version)}</span>");

        // Look up package health data for CRA score
        var healthData = _healthDataCache?.FirstOrDefault(p => p.PackageId.Equals(node.PackageId, StringComparison.OrdinalIgnoreCase))
                      ?? _transitiveDataCache?.FirstOrDefault(p => p.PackageId.Equals(node.PackageId, StringComparison.OrdinalIgnoreCase));

        if (healthData is not null)
        {
            // Show Health score
            var healthScoreClass = GetScoreClass(healthData.Score);
            sb.AppendLine($"{indentStr}  <span class=\"node-score health {healthScoreClass}\" title=\"Health Score\">{healthData.Score}</span>");
        }
        else if (node.HealthScore.HasValue)
        {
            // Fallback to tree node score if no health data found
            sb.AppendLine($"{indentStr}  <span class=\"node-score {scoreClass}\">{node.HealthScore.Value}</span>");
        }

        if (node.IsDuplicate)
        {
            var dupTooltip = "Appears elsewhere in the tree";
            if (_parentLookup.TryGetValue(node.PackageId, out var parents) && parents.Count > 0)
            {
                dupTooltip = $"Required by: {string.Join(", ", parents.Distinct().Take(5))}";
                if (parents.Distinct().Count() > 5)
                    dupTooltip += $" (+{parents.Distinct().Count() - 5} more)";
            }
            sb.AppendLine($"{indentStr}  <span class=\"node-badge duplicate\" title=\"{EscapeHtml(dupTooltip)}\">dup</span>");
        }

        if (node.HasVulnerabilities)
        {
            var vulnUrl = node.VulnerabilityUrl ?? $"https://osv.dev/list?ecosystem={(node.Ecosystem == PackageEcosystem.Npm ? "npm" : "NuGet")}&q={Uri.EscapeDataString(node.PackageId)}";
            var vulnTooltip = EscapeHtml(node.VulnerabilitySummary ?? "Click for vulnerability details");
            if (hasKev && healthData?.KevCves.Count > 0)
            {
                var kevCve = healthData.KevCves[0];
                var kevUrl = $"https://osv.dev/vulnerability/{Uri.EscapeDataString(kevCve)}";
                sb.AppendLine($"{indentStr}  <a href=\"{EscapeHtml(kevUrl)}\" target=\"_blank\" class=\"node-badge kev\" title=\"{EscapeHtml(kevCve)} - CISA KEV (click for details)\">{EscapeHtml(kevCve)}</a>");
            }
            else if (hasKev)
            {
                sb.AppendLine($"{indentStr}  <a href=\"{EscapeHtml(vulnUrl)}\" target=\"_blank\" class=\"node-badge kev\" title=\"CISA KEV: {vulnTooltip}\">KEV</a>");
            }
            else
            {
                sb.AppendLine($"{indentStr}  <a href=\"{EscapeHtml(vulnUrl)}\" target=\"_blank\" class=\"node-badge vuln\" title=\"{vulnTooltip}\">VULN</a>");
            }
        }
        else if (node.HasVulnerableDescendant)
        {
            sb.AppendLine($"{indentStr}  <span class=\"node-badge transitive-vuln\" title=\"Has vulnerable sub-dependencies\">&#9888;</span>");
        }

        if (node.HasVersionConflict && node.ConflictingVersions.Count > 0)
        {
            var conflictTooltip = $"Also found: {string.Join(", ", node.ConflictingVersions)}";
            sb.AppendLine($"{indentStr}  <span class=\"node-badge version-conflict\" title=\"{EscapeHtml(conflictTooltip)}\">CONFLICT</span>");
        }

        if (!string.IsNullOrEmpty(node.License))
        {
            sb.AppendLine($"{indentStr}  <span class=\"node-license\">{FormatLicenseWithLinks(node.License)}</span>");
        }

        if (hasChildren && !node.IsDuplicate)
        {
            // Trees are collapsed by default
            sb.AppendLine($"{indentStr}  <ul class=\"tree-children collapsed\">");
            foreach (var child in node.Children)
            {
                GenerateTreeNode(sb, child, indent + 2);
            }
            sb.AppendLine($"{indentStr}  </ul>");
        }

        sb.AppendLine($"{indentStr}</li>");
    }

    private static void GenerateDependencyIssuesSection(StringBuilder sb, CraReport report)
    {
        sb.AppendLine("<div class=\"section-header\">");
        sb.AppendLine("  <h2>Dependency Issues</h2>");
        sb.AppendLine("</div>");

        if (report.DependencyIssues.Count == 0)
        {
            sb.AppendLine("<div class=\"card empty-state\">");
            sb.AppendLine("  <div class=\"empty-icon\">&#10004;</div>");
            sb.AppendLine("  <h3>No Dependency Issues</h3>");
            sb.AppendLine("  <p>No version conflicts or dependency issues detected.</p>");
            sb.AppendLine("</div>");
            return;
        }

        // Summary stats
        sb.AppendLine("<div class=\"issues-summary\">");
        var versionConflicts = report.DependencyIssues.Count(i => i.Type == DependencyIssueType.VersionConflict);
        var peerMismatches = report.DependencyIssues.Count(i => i.Type == DependencyIssueType.PeerDependencyMismatch);
        sb.AppendLine($"  <span class=\"issue-stat\"><strong>{versionConflicts}</strong> version conflicts</span>");
        if (peerMismatches > 0)
        {
            sb.AppendLine($"  <span class=\"issue-stat\"><strong>{peerMismatches}</strong> peer dependency mismatches</span>");
        }
        sb.AppendLine("</div>");

        // Issues list
        sb.AppendLine("<div class=\"issues-list\">");
        foreach (var issue in report.DependencyIssues.OrderByDescending(i => i.Versions.Count))
        {
            var severityClass = issue.Severity.ToLowerInvariant();
            sb.AppendLine($"<div class=\"card issue-card {severityClass}\">");
            sb.AppendLine($"  <div class=\"issue-header\">");
            sb.AppendLine($"    <span class=\"issue-package\">{EscapeHtml(issue.PackageId)}</span>");
            sb.AppendLine($"    <span class=\"issue-badge {severityClass}\">{issue.Versions.Count} versions</span>");
            sb.AppendLine($"  </div>");
            sb.AppendLine($"  <div class=\"issue-versions\">");
            sb.AppendLine($"    <span class=\"versions-label\">Found in tree:</span>");
            foreach (var version in issue.Versions.OrderByDescending(v => v))
            {
                sb.AppendLine($"    <span class=\"version-tag\">{EscapeHtml(version)}</span>");
            }
            sb.AppendLine($"  </div>");
            if (!string.IsNullOrEmpty(issue.Recommendation))
            {
                sb.AppendLine($"  <div class=\"issue-recommendation\">");
                sb.AppendLine($"    <strong>Recommendation:</strong> {EscapeHtml(issue.Recommendation)}");
                sb.AppendLine($"  </div>");
            }
            sb.AppendLine("</div>");
        }
        sb.AppendLine("</div>");
    }

    private static string GetHtmlStyles()
    {
        return @"
  <style>
    :root {
      --bg-primary: #ffffff;
      --bg-secondary: #f8f9fa;
      --bg-tertiary: #e9ecef;
      --bg-card: #ffffff;
      --border: #dee2e6;
      --border-light: #e9ecef;
      --text-primary: #212529;
      --text-secondary: #495057;
      --text-muted: #6c757d;
      --text-light: #adb5bd;
      --accent: #0d6efd;
      --accent-light: #e7f1ff;
      --success: #198754;
      --success-light: #d1e7dd;
      --warning: #fd7e14;
      --warning-light: #fff3cd;
      --danger: #dc3545;
      --danger-light: #f8d7da;
      --watch: #17a2b8;
      --watch-light: #d1ecf1;
      --shadow-sm: 0 1px 2px rgba(0,0,0,0.05);
      --shadow: 0 4px 6px rgba(0,0,0,0.07);
      --shadow-lg: 0 10px 15px rgba(0,0,0,0.1);
      --sidebar-width: 260px;
      /* Legacy compatibility */
      --primary: var(--accent);
      --primary-dark: #0b5ed7;
      --bg: var(--bg-secondary);
      --card-bg: var(--bg-card);
      --text: var(--text-primary);
    }

    [data-theme=""dark""] {
      --bg-primary: #1a1d21;
      --bg-secondary: #212529;
      --bg-tertiary: #2b3035;
      --bg-card: #212529;
      --border: #373b3e;
      --border-light: #2b3035;
      --text-primary: #f8f9fa;
      --text-secondary: #ced4da;
      --text-muted: #adb5bd;
      --text-light: #6c757d;
      --accent: #0d6efd;
      --accent-light: #1a2942;
      --success: #198754;
      --success-light: #0f3d25;
      --warning: #fd7e14;
      --warning-light: #3d2a0f;
      --danger: #dc3545;
      --danger-light: #3d1519;
      --watch: #17a2b8;
      --watch-light: #0c343d;
      --shadow-sm: 0 1px 2px rgba(0,0,0,0.2);
      --shadow: 0 4px 6px rgba(0,0,0,0.25);
      --shadow-lg: 0 10px 15px rgba(0,0,0,0.3);
      /* Legacy compatibility */
      --bg: var(--bg-secondary);
      --card-bg: var(--bg-card);
      --text: var(--text-primary);
    }

    * { box-sizing: border-box; margin: 0; padding: 0; }

    html, body {
      height: auto;
      min-height: 100%;
    }

    body {
      font-family: 'IBM Plex Sans', -apple-system, BlinkMacSystemFont, sans-serif;
      background: var(--bg-secondary);
      color: var(--text-primary);
      line-height: 1.5;
      transition: background 0.3s ease, color 0.3s ease;
      overflow-y: auto;
    }

    .app-container {
      display: flex;
      min-height: 100vh;
    }

    /* Sidebar */
    .sidebar {
      width: var(--sidebar-width);
      background: var(--bg-primary);
      border-right: 1px solid var(--border);
      display: flex;
      flex-direction: column;
      position: fixed;
      height: 100vh;
      z-index: 100;
    }

    .sidebar-header {
      padding: 24px;
      border-bottom: 1px solid var(--border);
    }

    .logo {
      display: flex;
      align-items: center;
      gap: 12px;
    }

    .logo-icon {
      width: 36px;
      height: 36px;
      flex-shrink: 0;
    }

    .logo-text {
      font-size: 1.25rem;
      font-weight: 600;
      color: var(--text-primary);
    }

    .logo-badge {
      font-size: 0.65rem;
      background: var(--bg-tertiary);
      color: var(--text-muted);
      padding: 2px 6px;
      border-radius: 4px;
      margin-left: auto;
      font-family: 'IBM Plex Mono', monospace;
    }

    .sidebar-content {
      flex: 1;
      padding: 20px 16px;
      overflow-y: auto;
    }

    .nav-section {
      margin-bottom: 24px;
    }

    .nav-label {
      font-size: 0.7rem;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      color: var(--text-muted);
      padding: 0 12px;
      margin-bottom: 8px;
    }

    .nav-links {
      list-style: none;
    }

    .nav-links a {
      display: flex;
      align-items: center;
      gap: 10px;
      padding: 10px 12px;
      color: var(--text-secondary);
      text-decoration: none;
      font-size: 0.9rem;
      font-weight: 500;
      border-radius: 6px;
      transition: all 0.15s ease;
      margin-bottom: 2px;
    }

    .nav-links a:hover {
      background: var(--bg-secondary);
      color: var(--text-primary);
    }

    .nav-links a.active {
      background: var(--accent-light);
      color: var(--accent);
    }

    .nav-icon {
      width: 18px;
      height: 18px;
      opacity: 0.7;
      flex-shrink: 0;
    }

    .nav-links a.active .nav-icon {
      opacity: 1;
    }

    .nav-badge {
      margin-left: auto;
      font-size: 0.7rem;
      background: var(--bg-tertiary);
      color: var(--text-muted);
      padding: 2px 8px;
      border-radius: 10px;
      font-weight: 600;
    }

    .nav-links .external-link-item {
      margin-top: 12px;
      padding-top: 12px;
      border-top: 1px solid var(--border);
    }

    .nav-links .external-link-item a.external {
      color: var(--text-muted);
      font-size: 0.85em;
    }

    .nav-links .external-link-item a.external:hover {
      color: var(--text-primary);
      background: var(--bg-secondary);
    }

    /* Theme Toggle */
    .theme-section {
      padding: 16px;
      border-top: 1px solid var(--border);
    }

    .theme-toggle {
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 12px;
      background: var(--bg-secondary);
      border-radius: 8px;
    }

    .theme-info {
      display: flex;
      align-items: center;
      gap: 10px;
    }

    .theme-icon {
      width: 20px;
      height: 20px;
      color: var(--text-muted);
    }

    .theme-label {
      font-size: 0.85rem;
      color: var(--text-secondary);
    }

    .toggle-switch {
      position: relative;
      width: 44px;
      height: 24px;
      background: var(--bg-tertiary);
      border-radius: 12px;
      cursor: pointer;
      transition: all 0.2s ease;
    }

    .toggle-switch::after {
      content: '';
      position: absolute;
      width: 20px;
      height: 20px;
      background: var(--bg-card);
      border-radius: 50%;
      top: 2px;
      left: 2px;
      transition: all 0.2s ease;
      box-shadow: var(--shadow-sm);
    }

    .toggle-switch.active {
      background: var(--accent);
    }

    .toggle-switch.active::after {
      left: 22px;
    }

    .sidebar-footer {
      padding: 16px 24px;
      border-top: 1px solid var(--border);
    }

    .version-info {
      font-size: 0.75rem;
      color: var(--text-light);
      font-family: 'IBM Plex Mono', monospace;
    }

    /* Main Content */
    .main-content {
      flex: 1;
      margin-left: var(--sidebar-width);
      min-height: 100vh;
      padding-bottom: 100px;
    }

    .main-header {
      background: var(--bg-primary);
      border-bottom: 1px solid var(--border);
      padding: 20px 32px;
      display: flex;
      justify-content: space-between;
      align-items: center;
      position: sticky;
      top: 0;
      z-index: 50;
    }

    .header-left h1 {
      font-size: 1.5rem;
      font-weight: 600;
      color: var(--text-primary);
      margin-bottom: 4px;
    }

    .breadcrumb {
      display: flex;
      align-items: center;
      gap: 8px;
      font-size: 0.85rem;
      color: var(--text-muted);
    }

    .breadcrumb-sep {
      color: var(--text-light);
    }

    .header {
      margin-bottom: 30px;
    }

    .header h1 {
      font-size: 1.75rem;
      font-weight: 600;
      color: var(--text-primary);
    }

    .subtitle {
      color: var(--text-muted);
      font-size: 0.9rem;
    }

    .section {
      display: none;
    }

    .section.active {
      display: block;
    }

    .section {
      padding: 32px;
    }

    .section-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 20px;
      flex-wrap: wrap;
      gap: 15px;
    }

    .section-header h2 {
      font-size: 1.5rem;
      font-weight: 600;
      color: var(--text-primary);
    }

    .card {
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 24px;
      margin-bottom: 20px;
      box-shadow: var(--shadow-sm);
    }

    .overview-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 20px;
      margin-bottom: 30px;
    }

    .score-card {
      text-align: center;
    }

    .score-gauge {
      position: relative;
      width: 150px;
      height: 80px;
      margin: 20px auto;
    }

    .score-gauge svg {
      width: 100%;
      height: 100%;
    }

    .gauge-bg {
      fill: none;
      stroke: var(--bg-tertiary);
      stroke-width: 8;
      stroke-linecap: round;
    }

    .gauge-fill {
      fill: none;
      stroke: var(--accent);
      stroke-width: 8;
      stroke-linecap: round;
      transform-origin: center;
      transition: stroke-dasharray 0.5s;
    }

    .score-gauge.healthy .gauge-fill { stroke: var(--success); }
    .score-gauge.watch .gauge-fill { stroke: var(--watch); }
    .score-gauge.warning .gauge-fill { stroke: var(--warning); }
    .score-gauge.critical .gauge-fill { stroke: var(--danger); }

    .score-value {
      position: absolute;
      bottom: 0;
      left: 50%;
      transform: translateX(-50%);
      font-size: 2rem;
      font-weight: 700;
    }

    .score-label {
      font-weight: 600;
      text-transform: uppercase;
      font-size: 0.85rem;
    }

    .score-label.healthy, .healthy { color: var(--success); }
    .score-label.watch, .watch { color: var(--watch); }
    .score-label.warning, .warning { color: var(--warning); }
    .score-label.critical, .critical { color: var(--danger); }

    .status-card {
      text-align: center;
    }

    .status-card.healthy { border-left: 4px solid var(--success); }
    .status-card.warning { border-left: 4px solid var(--warning); }
    .status-card.critical { border-left: 4px solid var(--danger); }

    .big-status {
      font-size: 1.5rem;
      font-weight: 700;
      margin: 15px 0;
    }

    .status-detail {
      color: var(--text-muted);
      font-size: 0.9rem;
    }

    .metric-card {
      text-align: center;
    }

    .metric-value {
      font-size: 2.5rem;
      font-weight: 700;
      color: var(--accent);
    }

    .metric-label {
      color: var(--text-muted);
      font-size: 0.9rem;
    }

    .metric-detail {
      color: var(--text-muted);
      font-size: 0.75rem;
      margin-top: 0.25rem;
    }

    .search-input {
      padding: 10px 15px;
      border: 1px solid var(--border);
      border-radius: 6px;
      font-size: 0.9rem;
      width: 250px;
      background: var(--bg-card);
      color: var(--text-primary);
    }

    .search-input:focus {
      outline: none;
      border-color: var(--accent);
    }

    .filter-bar {
      display: flex;
      gap: 10px;
      margin-bottom: 20px;
      flex-wrap: wrap;
    }

    .filter-btn {
      padding: 8px 16px;
      border: 1px solid var(--border);
      background: var(--bg-card);
      color: var(--text-secondary);
      border-radius: 20px;
      cursor: pointer;
      font-size: 0.85rem;
      transition: all 0.15s ease;
    }

    .filter-btn:hover, .filter-btn.active {
      background: var(--accent);
      color: white;
      border-color: var(--accent);
    }

    .filter-btn.healthy.active { background: var(--success); border-color: var(--success); }
    .filter-btn.watch.active { background: var(--watch); border-color: var(--watch); }
    .filter-btn.warning.active { background: var(--warning); border-color: var(--warning); color: #000; }
    .filter-btn.critical.active { background: var(--danger); border-color: var(--danger); }

    .filter-group {
      display: flex;
      align-items: center;
      gap: 8px;
    }

    .filter-label {
      font-size: 0.85rem;
      color: var(--text-muted);
      font-weight: 500;
    }

    .filter-btn.nuget.active { background: #512bd4; border-color: #512bd4; }
    .filter-btn.npm.active { background: #cb3837; border-color: #cb3837; }

    .tree-ecosystem-filter {
      margin-left: auto;
    }

    .packages-list {
      display: flex;
      flex-direction: column;
      gap: 10px;
    }

    .package-card {
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: 8px;
      overflow: hidden;
      box-shadow: var(--shadow-sm);
    }

    .package-card[data-status='healthy'] { border-left: 4px solid var(--success); }
    .package-card[data-status='watch'] { border-left: 4px solid var(--watch); }
    .package-card[data-status='warning'] { border-left: 4px solid var(--warning); }
    .package-card[data-status='critical'] { border-left: 4px solid var(--danger); }

    .package-header {
      display: flex;
      align-items: center;
      padding: 15px 20px;
      cursor: pointer;
      transition: background 0.2s;
    }

    .package-header:hover {
      background: var(--bg-secondary);
    }

    .package-info {
      flex: 1;
    }

    .package-name {
      font-weight: 600;
      font-size: 1rem;
    }

    .package-version {
      color: var(--text-muted);
      font-size: 0.85rem;
      margin-left: 10px;
    }

    .package-score {
      width: 40px;
      height: 40px;
      border-radius: 50%;
      display: flex;
      align-items: center;
      justify-content: center;
      font-weight: 700;
      color: white;
      margin-right: 15px;
    }

    .package-score.healthy { background: var(--success); }
    .package-score.watch { background: var(--watch); }
    .package-score.warning { background: var(--warning); color: #000; }
    .package-score.critical { background: var(--danger); }

    .package-scores {
      display: flex;
      gap: 12px;
      margin-right: 15px;
    }

    .package-score-item {
      display: flex;
      flex-direction: column;
      align-items: center;
      gap: 2px;
    }

    .package-score-item .score-label {
      font-size: 0.65rem;
      color: var(--text-muted);
      text-transform: uppercase;
      font-weight: 600;
    }

    .package-score-item .score-value {
      position: static;
      bottom: auto;
      left: auto;
      transform: none;
      width: 36px;
      height: 36px;
      border-radius: 50%;
      display: flex;
      align-items: center;
      justify-content: center;
      font-weight: 700;
      font-size: 0.85rem;
      color: white;
      background-color: #6c757d;
    }

    .package-score-item .score-value.healthy { background-color: #28a745 !important; }
    .package-score-item .score-value.watch { background-color: #17a2b8 !important; }
    .package-score-item .score-value.warning { background-color: #ffc107 !important; color: #000; }
    .package-score-item .score-value.critical { background-color: #dc3545 !important; }
    .package-score-item .score-value.na { background-color: #6c757d !important; color: #aaa; }

    .expand-icon {
      font-size: 1.25rem;
      color: var(--text-muted);
      transition: transform 0.2s;
    }

    .package-card.expanded .expand-icon {
      transform: rotate(45deg);
    }

    .package-details {
      display: none;
      padding: 20px;
      border-top: 1px solid var(--border);
      background: var(--bg-secondary);
    }

    .package-card.expanded .package-details {
      display: block;
    }

    .detail-grid {
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(180px, 1fr));
      gap: 15px;
      margin-bottom: 20px;
    }

    .detail-item {
      min-width: 0;
      overflow: hidden;
    }

    .detail-item .label {
      display: block;
      color: var(--text-muted);
      font-size: 0.8rem;
      margin-bottom: 3px;
    }

    .detail-item .value {
      font-weight: 500;
      word-break: break-word;
      overflow-wrap: break-word;
      display: block;
      max-width: 100%;
    }

    .detail-item .value a {
      color: var(--primary);
      text-decoration: none;
    }

    .detail-item .value a:hover {
      text-decoration: underline;
    }

    .detail-item.full-width {
      grid-column: 1 / -1;
    }

    .unresolved-version {
      background: #fff3cd;
      color: #856404;
      padding: 2px 6px;
      border-radius: 4px;
      font-size: 0.85rem;
      cursor: help;
    }

    .version-hint {
      font-size: 0.75rem;
      opacity: 0.7;
      margin-left: 2px;
    }

    .unknown-date {
      color: #6c757d;
      font-style: italic;
      cursor: help;
    }

    .license-unknown {
      background: #f8d7da;
      color: #721c24;
      padding: 2px 8px;
      border-radius: 4px;
      font-size: 0.85rem;
      cursor: help;
    }

    .license-link {
      color: var(--accent);
      text-decoration: none;
    }

    .license-link:hover {
      text-decoration: underline;
      color: #4da3ff;
    }

    .msb-warning {
      background: #fff3cd;
      border: 1px solid #ffc107;
      border-left: 4px solid #ffc107;
      border-radius: 8px;
      padding: 15px 20px;
      margin-bottom: 20px;
    }

    .msb-warning h4 {
      color: #856404;
      margin-bottom: 8px;
      font-size: 1rem;
    }

    .msb-warning p {
      color: #856404;
      font-size: 0.9rem;
      margin: 0;
    }

    .msb-warning code {
      background: rgba(0,0,0,0.1);
      padding: 2px 6px;
      border-radius: 3px;
      font-size: 0.85rem;
    }

    .sbom-warning {
      background: var(--warning-light);
      border: 1px solid var(--warning);
      border-left: 4px solid var(--warning);
      border-radius: 8px;
      padding: 20px;
      margin-bottom: 24px;
    }

    .sbom-warning h4 {
      color: var(--warning);
      margin: 0 0 12px 0;
      font-size: 1.1rem;
    }

    .sbom-warning p {
      color: var(--text-secondary);
      font-size: 0.9rem;
      margin: 8px 0;
    }

    .sbom-warning ul {
      margin: 12px 0;
      padding-left: 24px;
      color: var(--text-secondary);
    }

    .sbom-warning li {
      margin: 6px 0;
      font-size: 0.9rem;
    }

    .sbom-warning code {
      background: var(--bg-tertiary);
      padding: 2px 8px;
      border-radius: 4px;
      font-size: 0.9rem;
      font-family: 'IBM Plex Mono', monospace;
    }

    /* License Section Styles */
    .license-status {
      display: flex;
      align-items: center;
      gap: 12px;
      padding: 16px 20px;
      border-radius: 8px;
      margin-bottom: 24px;
    }

    .license-status.healthy {
      background: var(--success-light);
      border: 1px solid var(--success);
    }

    .license-status.warning {
      background: var(--warning-light);
      border: 1px solid var(--warning);
    }

    .license-status.critical {
      background: var(--danger-light);
      border: 1px solid var(--danger);
    }

    .license-status .status-icon {
      font-size: 1.5rem;
    }

    .license-status .status-text {
      font-weight: 600;
      font-size: 1.1rem;
    }

    .license-status .status-detail {
      color: #666;
      font-size: 0.9rem;
    }

    .license-distribution {
      background: var(--bg-card);
      border-radius: 8px;
      padding: 20px;
      margin-bottom: 24px;
      box-shadow: var(--shadow);
    }

    .license-distribution h3 {
      margin: 0 0 16px 0;
      color: var(--text-primary);
    }

    .distribution-stacked-bar {
      display: flex;
      height: 40px;
      border-radius: 8px;
      overflow: hidden;
      box-shadow: inset 0 1px 2px rgba(0,0,0,0.1);
    }

    .bar-segment {
      display: flex;
      align-items: center;
      justify-content: center;
      color: white;
      font-weight: 500;
      font-size: 0.85rem;
      transition: filter 0.2s;
      min-width: 0;
    }

    .bar-segment:hover {
      filter: brightness(1.1);
    }

    .bar-segment .segment-label {
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
      padding: 0 8px;
      text-shadow: 0 1px 2px rgba(0,0,0,0.2);
    }

    .bar-segment.permissive { background: linear-gradient(180deg, #34ce57, #28a745); }
    .bar-segment.weak-copyleft { background: linear-gradient(180deg, #20c9e0, #17a2b8); }
    .bar-segment.strong-copyleft { background: linear-gradient(180deg, #e4606d, #dc3545); }
    .bar-segment.public-domain { background: linear-gradient(180deg, #8b5cf6, #6f42c1); }
    .bar-segment.unknown { background: linear-gradient(180deg, #868e96, #6c757d); }

    .distribution-legend {
      display: flex;
      flex-wrap: wrap;
      gap: 16px;
      margin-top: 16px;
    }

    .legend-item {
      display: flex;
      align-items: center;
      gap: 8px;
      font-size: 0.9rem;
    }

    .legend-color {
      width: 16px;
      height: 16px;
      border-radius: 4px;
    }

    .legend-color.permissive { background: #28a745; }
    .legend-color.weak-copyleft { background: #17a2b8; }
    .legend-color.strong-copyleft { background: #dc3545; }
    .legend-color.public-domain { background: #6f42c1; }
    .legend-color.unknown { background: #6c757d; }

    .legend-label {
      font-weight: 500;
      color: var(--text-primary);
    }

    .legend-count {
      font-weight: 600;
      color: var(--text-primary);
    }

    .legend-percent {
      color: var(--text-muted);
    }

    .license-table-container {
      background: var(--bg-card);
      border-radius: 8px;
      padding: 20px;
      margin-bottom: 24px;
      box-shadow: var(--shadow);
    }

    .license-table {
      width: 100%;
      border-collapse: collapse;
    }

    .license-table th, .license-table td {
      padding: 12px;
      text-align: left;
      border-bottom: 1px solid var(--border);
    }

    .license-table th {
      background: var(--bg-tertiary);
      font-weight: 600;
    }

    .category-badge {
      display: inline-block;
      padding: 4px 12px;
      border-radius: 12px;
      font-size: 0.8rem;
      font-weight: 500;
      color: white;
    }

    .category-badge.permissive { background: #28a745; }
    .category-badge.weak-copyleft { background: #17a2b8; }
    .category-badge.strong-copyleft { background: #dc3545; }
    .category-badge.public-domain { background: #6f42c1; }
    .category-badge.unknown { background: #6c757d; }

    .license-issues {
      background: var(--bg-card);
      border-radius: 8px;
      padding: 20px;
      margin-bottom: 24px;
      box-shadow: var(--shadow);
    }

    .issue-item {
      display: flex;
      flex-direction: column;
      gap: 4px;
      padding: 12px;
      border-radius: 6px;
      margin-bottom: 8px;
    }

    .issue-item.error {
      background: var(--danger-light);
      border-left: 4px solid var(--danger);
    }

    .issue-item.warning {
      background: var(--warning-light);
      border-left: 4px solid var(--warning);
    }

    .issue-severity {
      font-weight: 600;
      font-size: 0.85rem;
      text-transform: uppercase;
    }

    .issue-message {
      color: var(--text-primary);
    }

    .issue-recommendation {
      color: var(--text-muted);
      font-size: 0.9rem;
      font-style: italic;
    }

    .unknown-licenses {
      background: var(--bg-tertiary);
      border-radius: 8px;
      padding: 20px;
      margin-bottom: 24px;
    }

    .unknown-licenses ul {
      margin: 12px 0;
      padding-left: 24px;
    }

    .unknown-licenses li {
      margin: 4px 0;
    }

    .package-dependencies {
      margin-top: 15px;
      padding: 15px;
      background: var(--bg-tertiary);
      border-radius: 8px;
      border: 1px solid var(--border);
    }

    .package-dependencies h4 {
      margin-bottom: 10px;
      font-size: 0.9rem;
      color: var(--text-muted);
    }

    .dep-list {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
    }

    .dep-item {
      display: inline-block;
      padding: 4px 10px;
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: 15px;
      font-size: 0.8rem;
      color: var(--primary);
      text-decoration: none;
      transition: all 0.2s;
    }

    .dep-item:hover {
      background: var(--primary);
      color: white;
      border-color: var(--primary);
    }

    .dep-more {
      display: inline-block;
      padding: 4px 10px;
      font-size: 0.8rem;
      color: var(--text-muted);
    }

    .dep-internal {
      background: #e8f4f8;
      border-color: var(--primary);
      cursor: pointer;
    }

    .dep-internal::after {
      content: ' ↗';
      font-size: 0.7rem;
      opacity: 0.6;
    }

    .dep-internal:hover {
      background: var(--primary);
      color: white;
    }

    .dep-external {
      background: #f8f8f8;
      border-color: #ddd;
    }

    .dep-external::after {
      content: ' ↗';
      font-size: 0.7rem;
      opacity: 0.4;
    }

    .dep-peer {
      background: #fff3e0;
      border-color: #ff9800;
      color: #e65100;
    }

    [data-theme=""dark""] .dep-peer {
      background: #3d2a0f;
      border-color: #ff9800;
      color: #ffb74d;
    }

    .dep-peer:hover {
      background: #ff9800;
      color: white;
      border-color: #ff9800;
    }

    .peer-range {
      font-size: 0.7rem;
      opacity: 0.8;
      margin-left: 4px;
    }

    .peer-deps h4 {
      color: var(--warning);
    }

    /* Version status indicators */
    .version-current {
      color: var(--success);
      font-weight: 600;
    }

    .version-upgrade {
      font-weight: 600;
      padding: 2px 8px;
      border-radius: 4px;
    }

    .version-upgrade.upgrade-patch {
      background: var(--success-light);
      color: var(--success);
    }

    .version-upgrade.upgrade-minor {
      background: var(--warning-light);
      color: var(--warning);
    }

    .version-upgrade.upgrade-major {
      background: var(--danger-light);
      color: var(--danger);
    }

    .package-card.highlight {
      animation: highlightPulse 2s ease-out;
    }

    @keyframes highlightPulse {
      0% { box-shadow: 0 0 0 4px rgba(37, 99, 235, 0.6); }
      100% { box-shadow: none; }
    }

    .highlight-flash {
      animation: flashHighlight 2s ease-out;
    }

    @keyframes flashHighlight {
      0%, 20% { background-color: rgba(37, 99, 235, 0.3); box-shadow: 0 0 0 3px rgba(37, 99, 235, 0.5); }
      100% { background-color: transparent; box-shadow: none; }
    }

    .tree-node.highlight-flash {
      background-color: rgba(37, 99, 235, 0.2);
    }

    .recommendations {
      background: var(--warning-light);
      border: 1px solid var(--warning);
      padding: 15px;
      border-radius: 8px;
      margin-bottom: 15px;
    }

    .recommendations h4 {
      margin-bottom: 10px;
      color: var(--warning);
    }

    .recommendations ul {
      margin-left: 20px;
      color: var(--text-secondary);
    }

    .vulnerabilities-badge {
      background: var(--danger);
      color: white;
      padding: 8px 15px;
      border-radius: 8px;
      display: inline-block;
    }

    .kev-badge {
      background: #dc3545;
      color: white;
      padding: 2px 6px;
      border-radius: 4px;
      font-size: 0.7rem;
      font-weight: 700;
      margin-left: 8px;
      animation: kev-pulse 2s infinite;
      text-decoration: none;
      cursor: pointer;
    }

    @keyframes kev-pulse {
      0%, 100% { opacity: 1; }
      50% { opacity: 0.7; }
    }

    .package-card.has-kev {
      border-left: 4px solid #dc3545;
    }

    .epss-badge {
      padding: 2px 6px;
      border-radius: 4px;
      font-size: 0.7rem;
      font-weight: 600;
      margin-left: 8px;
    }

    .epss-badge.epss-critical {
      background: #dc3545;
      color: white;
    }

    .epss-badge.epss-high {
      background: #fd7e14;
      color: white;
    }

    .epss-badge.epss-medium {
      background: #ffc107;
      color: #212529;
    }

    .epss-badge.epss-low {
      background: var(--bg-secondary);
      color: var(--text-secondary);
    }

    /* Supply Chain / Typosquatting */
    .typosquat-success {
      text-align: center;
      padding: 3rem;
    }

    .typosquat-summary {
      display: flex;
      gap: 1rem;
      margin-bottom: 1.5rem;
      flex-wrap: wrap;
    }

    .typosquat-stat-card {
      background: var(--bg-secondary);
      border-radius: 8px;
      padding: 1rem 1.5rem;
      display: flex;
      flex-direction: column;
      align-items: center;
      min-width: 100px;
      border: 1px solid var(--border);
    }

    .typosquat-stat-card.critical { border-color: var(--danger); background: var(--danger-light); }
    .typosquat-stat-card.high { border-color: #e67e22; background: #fdf2e9; }
    .typosquat-stat-card.medium { border-color: var(--warning); background: var(--warning-light); }
    .typosquat-stat-card.low { border-color: var(--text-secondary); }

    .typosquat-stat-count {
      font-size: 1.5rem;
      font-weight: 700;
      line-height: 1.2;
    }

    .typosquat-stat-card.critical .typosquat-stat-count { color: var(--danger); }
    .typosquat-stat-card.high .typosquat-stat-count { color: #e67e22; }
    .typosquat-stat-card.medium .typosquat-stat-count { color: #856404; }

    .typosquat-stat-label {
      font-size: 0.75rem;
      color: var(--text-secondary);
      text-transform: uppercase;
      letter-spacing: 0.05em;
    }

    .typosquat-risk {
      display: inline-block;
      padding: 2px 8px;
      border-radius: 4px;
      font-size: 0.75rem;
      font-weight: 600;
      text-transform: uppercase;
    }

    .typosquat-risk.typosquat-critical { background: var(--danger-light); color: var(--danger); }
    .typosquat-risk.typosquat-high { background: #fdf2e9; color: #e67e22; }
    .typosquat-risk.typosquat-medium { background: var(--warning-light); color: #856404; }
    .typosquat-risk.typosquat-low { background: var(--bg-secondary); color: var(--text-secondary); }

    .confidence-bar {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      width: 100%;
    }

    .confidence-fill {
      display: inline-block;
      height: 6px;
      border-radius: 3px;
      background: var(--accent);
    }

    .confidence-text {
      font-size: 0.8rem;
      color: var(--text-secondary);
      white-space: nowrap;
    }

    .typosquat-table code {
      font-size: 0.85em;
    }

    .nav-badge.warning {
      background: var(--warning);
      color: #000;
    }

    .required-by {
      margin-top: 12px;
      padding: 10px 12px;
      background: var(--bg-secondary);
      border-radius: 8px;
      border: 1px solid var(--border);
    }

    .required-by-label {
      font-size: 0.85rem;
      color: var(--text-muted);
      margin-right: 8px;
    }

    .parent-packages {
      display: inline-flex;
      flex-wrap: wrap;
      gap: 6px;
      margin-top: 4px;
    }

    .parent-badge {
      display: inline-block;
      padding: 3px 10px;
      background: var(--primary);
      color: white;
      border-radius: 12px;
      font-size: 0.8rem;
      text-decoration: none;
      cursor: pointer;
      transition: background 0.2s;
    }

    .parent-badge:hover {
      background: var(--primary-dark);
      text-decoration: none;
    }

    .parent-badge.direct {
      background: var(--success);
    }

    .parent-badge.direct:hover {
      background: #1e7e34;
    }

    .more-parents {
      font-size: 0.8rem;
      color: var(--text-muted);
      padding: 3px 6px;
    }

    .package-links {
      margin-top: 15px;
    }

    .package-links a {
      color: var(--primary);
      margin-right: 15px;
      text-decoration: none;
    }

    .package-links a:hover {
      text-decoration: underline;
    }

    .sbom-table {
      width: 100%;
      border-collapse: collapse;
      margin-top: 15px;
    }

    .sbom-table th, .sbom-table td {
      padding: 12px;
      text-align: left;
      border-bottom: 1px solid var(--border);
    }

    .sbom-table th {
      background: var(--bg-secondary);
      font-weight: 600;
    }

    .component-name strong {
      display: block;
    }

    .external-link {
      font-size: 0.8rem;
      color: var(--primary);
    }

    .license-badge {
      background: var(--bg-secondary);
      padding: 4px 8px;
      border-radius: 4px;
      font-size: 0.85rem;
    }

    .purl code {
      background: var(--bg-secondary);
      padding: 4px 8px;
      border-radius: 4px;
      font-size: 0.75rem;
      word-break: break-all;
    }

    .export-section {
      margin-top: 20px;
      display: flex;
      gap: 10px;
    }

    .export-btn {
      padding: 10px 20px;
      background: var(--primary);
      color: white;
      border: none;
      border-radius: 8px;
      cursor: pointer;
      font-size: 0.9rem;
    }

    .export-btn:hover {
      background: var(--primary-dark);
    }

    .empty-state.success {
      border: 2px solid var(--success);
      background: rgba(34, 197, 94, 0.05);
    }

    .empty-state.success .empty-icon {
      color: var(--success);
    }

    .vuln-alert {
      display: flex;
      align-items: center;
      gap: 12px;
      padding: 16px 20px;
      background: rgba(239, 68, 68, 0.1);
      border: 1px solid var(--danger);
      border-radius: 8px;
      margin-bottom: 20px;
    }

    .vuln-alert-icon {
      font-size: 1.5rem;
      color: var(--danger);
    }

    .vuln-alert-text {
      font-size: 1.1rem;
      color: var(--danger);
    }

    .vuln-safe-note {
      color: var(--text-muted);
      font-size: 0.9rem;
    }

    .reviewed-vulns-section {
      margin-top: 30px;
      border-top: 1px solid var(--border);
      padding-top: 20px;
    }

    .reviewed-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 12px 16px;
      background: var(--bg-card);
      border-radius: 8px;
      cursor: pointer;
      color: var(--text-muted);
      font-size: 0.9rem;
    }

    .reviewed-header:hover {
      background: var(--border);
    }

    .vuln-summary {
      display: flex;
      gap: 20px;
      margin-bottom: 30px;
    }

    .vuln-stat {
      flex: 1;
      text-align: center;
      padding: 20px;
      border-radius: 12px;
      background: var(--bg-card);
    }

    .vuln-stat .count {
      display: block;
      font-size: 2rem;
      font-weight: 700;
    }

    .vuln-stat.affected .count { color: var(--danger); }
    .vuln-stat.fixed .count { color: var(--success); }
    .vuln-stat.not-affected .count { color: var(--text-muted); }

    .vuln-stat .label {
      display: block;
      font-weight: 600;
      margin-top: 5px;
    }

    .vuln-stat .sublabel {
      display: block;
      font-size: 0.8rem;
      color: var(--text-muted);
      margin-top: 4px;
    }

    .vuln-package-info {
      margin: 8px 0;
    }

    .vuln-patched-note {
      display: block;
      color: var(--success);
      font-size: 0.9rem;
      margin-top: 4px;
    }

    .vuln-affected-note {
      display: block;
      color: var(--danger);
      font-size: 0.9rem;
      margin-top: 4px;
    }

    .vuln-fixed-in {
      display: block;
      color: var(--primary);
      font-size: 0.9rem;
      font-weight: 600;
      margin-top: 4px;
    }

    .vulnerabilities-list {
      display: flex;
      flex-direction: column;
      gap: 15px;
    }

    .vuln-card {
      background: var(--bg-card);
      border-radius: 12px;
      padding: 20px;
      border-left: 4px solid var(--border);
    }

    .vuln-card.affected { border-left-color: var(--danger); }
    .vuln-card.fixed { border-left-color: var(--success); }

    .vuln-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 10px;
    }

    .vuln-id {
      font-weight: 700;
      font-size: 1.1rem;
      color: var(--primary);
      text-decoration: none;
    }
    .vuln-id:hover {
      text-decoration: underline;
    }

    .vuln-status {
      padding: 4px 12px;
      border-radius: 20px;
      font-size: 0.8rem;
      font-weight: 600;
      text-transform: uppercase;
    }

    .vuln-status.affected { background: #f8d7da; color: #721c24; }
    .vuln-status.fixed { background: #d4edda; color: #155724; }
    .vuln-status.not-affected { background: #e9ecef; color: #6c757d; }

    .vuln-description {
      color: var(--text-muted);
      margin-bottom: 15px;
    }

    .vuln-products, .vuln-action, .vuln-aliases {
      margin-top: 10px;
      font-size: 0.9rem;
    }

    .vuln-products code {
      background: var(--bg-secondary);
      padding: 2px 6px;
      border-radius: 4px;
    }

    .vuln-action {
      background: #fff3cd;
      padding: 10px;
      border-radius: 8px;
    }

    .compliance-list {
      display: flex;
      flex-direction: column;
      gap: 15px;
    }

    .compliance-item {
      background: var(--bg-card);
      border-radius: 12px;
      padding: 20px;
      border-left: 4px solid var(--border);
    }

    .compliance-item.compliant { border-left-color: var(--success); }
    .compliance-item.action-required { border-left-color: var(--warning); }
    .compliance-item.non-compliant { border-left-color: var(--danger); }

    .compliance-header {
      display: flex;
      align-items: flex-start;
      gap: 15px;
    }

    .compliance-icon {
      width: 40px;
      height: 40px;
      border-radius: 50%;
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 1.25rem;
      flex-shrink: 0;
    }

    .compliance-item.compliant .compliance-icon { background: #d4edda; color: var(--success); }
    .compliance-item.action-required .compliance-icon { background: #fff3cd; color: #856404; }
    .compliance-item.non-compliant .compliance-icon { background: #f8d7da; color: var(--danger); }

    .compliance-info {
      flex: 1;
    }

    .compliance-info h3 {
      font-size: 1rem;
      margin-bottom: 5px;
    }

    .compliance-info p {
      color: var(--text-muted);
      font-size: 0.9rem;
    }

    .compliance-item.non-compliant .compliance-info p { color: var(--danger); font-weight: 500; }
    .compliance-item.action-required .compliance-info p { color: #856404; }

    .compliance-status {
      padding: 4px 12px;
      border-radius: 20px;
      font-size: 0.8rem;
      font-weight: 600;
    }

    .compliance-status.compliant { background: #d4edda; color: #155724; }
    .compliance-status.action-required { background: #fff3cd; color: #856404; }
    .compliance-status.non-compliant { background: #f8d7da; color: #721c24; }

    .compliance-evidence, .compliance-recommendation {
      margin-top: 15px;
      padding-top: 15px;
      border-top: 1px solid var(--border);
      font-size: 0.9rem;
    }

    .compliance-item.non-compliant .compliance-evidence { color: var(--danger); }

    .compliance-recommendation {
      background: #fff3cd;
      color: #856404;
      padding: 15px;
      border-radius: 8px;
      border-top: none;
    }

    .empty-state {
      text-align: center;
      padding: 60px 20px;
    }

    .empty-icon {
      font-size: 4rem;
      color: var(--success);
      margin-bottom: 20px;
    }

    .disclaimer-footer {
      position: fixed;
      bottom: 0;
      left: var(--sidebar-width);
      right: 0;
      background: var(--bg-card);
      border-top: 1px solid var(--border);
      padding: 12px 30px;
      text-align: center;
      font-size: 0.8rem;
      color: var(--text-muted);
      z-index: 100;
    }

    .disclaimer-footer p {
      margin: 0;
      max-width: 800px;
      margin: 0 auto;
    }

    .action-list {
      margin-left: 20px;
    }

    .action-list li {
      margin-bottom: 10px;
    }

    .sbom-meta {
      display: flex;
      gap: 20px;
    }

    .meta-item {
      color: var(--text-muted);
      font-size: 0.9rem;
    }

    /* Transitive Dependencies */
    .transitive-section {
      margin-top: 30px;
      background: var(--bg-card);
      border-radius: 12px;
      overflow: hidden;
      box-shadow: 0 1px 3px rgba(0,0,0,0.1);
    }

    .transitive-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 15px 20px;
      background: var(--bg-tertiary);
      cursor: pointer;
      border-bottom: 1px solid var(--border);
    }

    .transitive-header:hover {
      background: var(--bg-secondary);
    }

    .transitive-header h3 {
      font-size: 1rem;
      color: var(--text-primary);
      margin: 0;
    }

    .transitive-toggle {
      padding: 4px 12px;
      background: var(--accent);
      color: white;
      border-radius: 20px;
      font-size: 0.8rem;
      font-weight: 500;
    }

    .transitive-list {
      padding: 15px;
      background: #fafafa;
    }

    .dep-type-badge {
      padding: 2px 8px;
      border-radius: 10px;
      font-size: 0.7rem;
      margin-left: 10px;
      font-weight: 500;
      text-transform: lowercase;
    }

    .dep-type-badge.direct {
      background: #0d6efd;
      color: white;
    }

    .dep-type-badge.transitive {
      background: #6c757d;
      color: white;
    }

    .dep-type-badge.sub-dep {
      background: #6f42c1;
      color: white;
    }

    .package-card.transitive {
      opacity: 0.9;
      border-left-width: 3px;
    }

    /* Dependency Issues */
    .issues-summary {
      display: flex;
      gap: 20px;
      margin-bottom: 20px;
      flex-wrap: wrap;
    }

    .issue-stat {
      background: var(--bg-secondary);
      padding: 8px 16px;
      border-radius: 6px;
      font-size: 0.9rem;
    }

    .issues-list {
      display: flex;
      flex-direction: column;
      gap: 12px;
    }

    .issue-card {
      border-left: 4px solid var(--warning);
    }

    .issue-card.critical {
      border-left-color: var(--danger);
    }

    .issue-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 12px;
    }

    .issue-package {
      font-weight: 600;
      font-size: 1.1rem;
    }

    .issue-badge {
      padding: 4px 10px;
      border-radius: 12px;
      font-size: 0.8rem;
      font-weight: 500;
      background: var(--warning);
      color: #000;
    }

    .issue-badge.critical {
      background: var(--danger);
      color: white;
    }

    .issue-versions {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      margin-bottom: 12px;
      align-items: center;
    }

    .versions-label {
      color: var(--text-muted);
      font-size: 0.85rem;
      margin-right: 4px;
    }

    .version-tag {
      background: var(--bg-secondary);
      padding: 4px 10px;
      border-radius: 4px;
      font-family: monospace;
      font-size: 0.85rem;
    }

    .issue-recommendation {
      background: rgba(255, 193, 7, 0.1);
      padding: 10px 12px;
      border-radius: 4px;
      font-size: 0.9rem;
    }

    /* Dependency Tree */
    .tree-stats {
      display: flex;
      gap: 20px;
      margin-bottom: 15px;
      flex-wrap: wrap;
    }

    .tree-stat {
      padding: 8px 16px;
      background: var(--bg-card);
      border-radius: 8px;
      font-size: 0.9rem;
      box-shadow: 0 1px 3px rgba(0,0,0,0.1);
    }

    .tree-stat.vulnerable {
      background: var(--danger-light);
      color: var(--danger);
      border: 1px solid var(--danger);
    }

    .tree-controls {
      display: flex;
      gap: 10px;
      margin-bottom: 20px;
      flex-wrap: wrap;
      align-items: center;
    }

    .tree-btn {
      padding: 8px 16px;
      border: 1px solid var(--border);
      background: var(--bg-card);
      color: var(--text-secondary);
      border-radius: 8px;
      cursor: pointer;
      font-size: 0.85rem;
      transition: all 0.2s;
    }

    .tree-btn:hover {
      background: var(--accent);
      color: white;
      border-color: var(--accent);
    }

    .dependency-tree {
      background: var(--bg-card);
      border-radius: 12px;
      padding: 20px;
      box-shadow: 0 1px 3px rgba(0,0,0,0.1);
      font-family: 'SF Mono', Monaco, 'Cascadia Code', Consolas, monospace;
      font-size: 0.9rem;
      overflow-x: auto;
    }

    .tree-root, .tree-children {
      list-style: none;
      padding-left: 0;
      margin: 0;
    }

    .tree-children {
      margin-left: 16px;
      margin-top: 4px;
      padding: 8px 8px 8px 16px;
      border-left: 3px solid var(--primary);
      background: rgba(0, 102, 204, 0.03);
      border-radius: 0 8px 8px 0;
    }

    .tree-children .tree-children {
      border-left-color: var(--success);
      background: rgba(40, 167, 69, 0.03);
    }

    .tree-children .tree-children .tree-children {
      border-left-color: var(--watch);
      background: rgba(23, 162, 184, 0.03);
    }

    .tree-children .tree-children .tree-children .tree-children {
      border-left-color: var(--warning);
      background: rgba(255, 193, 7, 0.03);
    }

    .tree-node {
      padding: 8px 12px;
      margin: 4px 0;
      display: flex;
      align-items: center;
      flex-wrap: wrap;
      gap: 8px;
      background: var(--bg-card);
      border-radius: 6px;
      border: 1px solid var(--border);
      transition: box-shadow 0.2s;
    }

    .tree-node:hover {
      box-shadow: 0 2px 8px rgba(0,0,0,0.1);
    }

    .tree-node.duplicate {
      opacity: 0.6;
    }

    .tree-node.duplicate .node-name {
      font-style: italic;
    }

    .tree-node.has-vuln {
      background: rgba(220, 53, 69, 0.15);
      margin: 0 -10px;
      padding: 6px 10px;
      border-radius: 4px;
    }

    .tree-node.has-kev {
      background: rgba(220, 53, 69, 0.25);
      border-left: 3px solid #dc3545;
    }

    .node-badge.kev {
      background: #dc3545;
      color: white;
      font-weight: 700;
      animation: kev-pulse 2s infinite;
    }

    .tree-node.has-vuln-descendant:not(.has-vuln) {
      /* Subtle indicator - the warning badge is enough */
    }

    .tree-node.has-vuln-descendant:not(.has-vuln) > .tree-toggle {
      color: var(--warning);
    }

    .tree-toggle {
      cursor: pointer;
      color: var(--text-muted);
      width: 24px;
      text-align: center;
      user-select: none;
      flex-shrink: 0;
    }

    .tree-toggle:not(.leaf):hover {
      color: var(--primary);
    }

    .tree-toggle.leaf {
      cursor: default;
      color: var(--border);
    }

    .node-name {
      font-weight: 600;
      color: var(--text-primary);
    }

    .node-version {
      color: var(--text-muted);
      font-size: 0.85em;
    }

    .node-score {
      padding: 2px 6px;
      border-radius: 4px;
      font-size: 0.7em;
      font-weight: 600;
      color: white;
    }

    .node-score::before {
      font-weight: 400;
      margin-right: 3px;
      opacity: 0.9;
    }

    .node-score.health::before { content: ""H""; }

    .node-score.healthy { background: var(--success); }
    .node-score.watch { background: var(--watch); }
    .node-score.warning { background: var(--warning); color: #000; }
    .node-score.critical { background: var(--danger); }

    .node-badge {
      padding: 1px 6px;
      border-radius: 4px;
      font-size: 0.7em;
      font-weight: 600;
      text-transform: uppercase;
    }

    .node-badge.duplicate {
      background: var(--text-muted);
      color: white;
    }

    a.node-badge.vuln {
      background: var(--danger);
      color: white;
      text-decoration: none;
      cursor: pointer;
      font-size: 0.75em;
      padding: 3px 8px;
      font-weight: 700;
      animation: pulse-danger 2s infinite;
    }

    @keyframes pulse-danger {
      0%, 100% { box-shadow: 0 0 0 0 rgba(220, 53, 69, 0.4); }
      50% { box-shadow: 0 0 0 4px rgba(220, 53, 69, 0); }
    }

    a.node-badge.vuln:hover {
      background: #c82333;
      text-decoration: underline;
      animation: none;
    }

    .node-badge.transitive-vuln {
      color: var(--warning);
      font-size: 1.1em;
      padding: 0 4px;
    }

    .node-badge.version-conflict {
      background: var(--warning);
      color: #000;
    }

    .node-license {
      font-size: 0.75em;
      padding: 1px 6px;
      background: var(--bg-tertiary);
      border-radius: 4px;
    }

    .node-license,
    .node-license a {
      color: var(--accent);
    }

    .node-license a:hover {
      color: #4da3ff;
      text-decoration: underline;
    }

    .tree-children.collapsed {
      display: none;
    }

    .tree-node.hidden {
      display: none;
    }

    .ecosystem-header {
      display: flex;
      align-items: center;
      gap: 10px;
      padding: 12px 16px;
      background: var(--bg-tertiary);
      border-radius: 8px;
      margin: 20px 0 10px 0;
      border-left: 4px solid var(--accent);
    }

    .ecosystem-header:first-of-type {
      margin-top: 0;
    }

    .ecosystem-icon {
      font-size: 1.25rem;
    }

    .ecosystem-label {
      font-weight: 600;
      font-size: 1.1rem;
    }

    .ecosystem-count {
      color: var(--text-muted);
      font-size: 0.9rem;
      margin-left: auto;
    }

    @media (max-width: 768px) {
      .sidebar {
        width: 100%;
        position: relative;
        height: auto;
      }
      .main-content {
        margin-left: 0;
      }
      .overview-grid {
        grid-template-columns: 1fr;
      }
    }

    /* ===== v1.2 Detail Sections ===== */

    .detail-table {
      width: 100%;
      border-collapse: collapse;
      margin-top: 15px;
    }
    .detail-table th, .detail-table td {
      padding: 10px 12px;
      text-align: left;
      border-bottom: 1px solid var(--border);
    }
    .detail-table th {
      background: var(--bg-secondary);
      font-weight: 600;
      font-size: 0.85rem;
      text-transform: uppercase;
      letter-spacing: 0.03em;
      color: var(--text-secondary);
    }
    .detail-table tr:hover {
      background: var(--bg-secondary);
    }

    .days-overdue {
      font-weight: 600;
    }
    .days-overdue.critical { color: var(--danger); }
    .days-overdue.warning { color: var(--warning-text, #856404); }
    .days-overdue.ok { color: var(--success); }

    .status-pill {
      display: inline-block;
      padding: 3px 10px;
      border-radius: 12px;
      font-size: 0.8rem;
      font-weight: 600;
    }
    .status-pill.signed { background: var(--success-light, #d4edda); color: var(--success); }
    .status-pill.unsigned { background: var(--bg-secondary); color: var(--text-secondary); }
    .status-pill.archived { background: var(--danger-light); color: var(--danger); }
    .status-pill.stale { background: var(--warning-light); color: var(--warning-text, #856404); }
    .status-pill.unmaintained { background: #fce4ec; color: #c0392b; }
    .status-pill.active { background: var(--success-light, #d4edda); color: var(--success); }

    .progress-bar-container {
      background: var(--bg-secondary);
      border-radius: 6px;
      height: 22px;
      overflow: hidden;
      position: relative;
    }
    .progress-bar-fill {
      height: 100%;
      border-radius: 6px;
      transition: width 0.3s;
      display: flex;
      align-items: center;
      padding-left: 8px;
      font-size: 0.75rem;
      font-weight: 600;
      color: #fff;
      min-width: fit-content;
    }
    .progress-bar-fill.high { background: var(--success); }
    .progress-bar-fill.medium { background: var(--warning); }
    .progress-bar-fill.low { background: var(--danger); }

    .field-grid {
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
      gap: 12px;
      margin-top: 15px;
    }
    .field-card {
      background: var(--bg-primary);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 14px;
    }
    .field-card .field-label {
      font-size: 0.85rem;
      color: var(--text-secondary);
      margin-bottom: 6px;
    }
    .field-card .field-value {
      font-size: 1.1rem;
      font-weight: 600;
    }

    .surface-metrics {
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(180px, 1fr));
      gap: 12px;
      margin: 15px 0;
    }
    .surface-metric {
      background: var(--bg-primary);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 16px;
      text-align: center;
    }
    .surface-metric .metric-big {
      font-size: 2rem;
      font-weight: 700;
      line-height: 1;
    }
    .surface-metric .metric-label {
      font-size: 0.85rem;
      color: var(--text-secondary);
      margin-top: 4px;
    }
    .surface-metric .metric-hint {
      font-size: 0.78rem;
      color: var(--text-secondary);
      margin-top: 4px;
      opacity: 0.8;
      font-style: italic;
    }

    .info-box {
      background: rgba(76, 175, 255, 0.06);
      border: 1px solid rgba(76, 175, 255, 0.2);
      border-left: 3px solid var(--accent);
      border-radius: 6px;
      padding: 16px 18px;
      margin: 16px 0;
      font-size: 0.92rem;
      line-height: 1.5;
    }
    .info-box .info-box-title {
      font-weight: 600;
      color: var(--accent);
      margin-bottom: 6px;
      font-size: 0.88rem;
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }
    .info-box p {
      margin: 0;
      color: var(--text-secondary);
    }

    .empty-state {
      text-align: center;
      padding: 40px 20px;
      color: var(--text-secondary);
    }
    .empty-state .empty-icon {
      font-size: 2rem;
      margin-bottom: 10px;
    }

    .maintenance-group {
      margin-bottom: 20px;
    }
    .maintenance-group h4 {
      margin: 0 0 8px 0;
      font-size: 0.95rem;
    }
    .maintenance-list {
      display: flex;
      flex-wrap: wrap;
      gap: 6px;
    }
    .maintenance-pkg {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      padding: 4px 10px;
      border-radius: 6px;
      font-size: 0.85rem;
      border: 1px solid var(--border);
      background: var(--bg-primary);
    }
  </style>";
    }

    private string GetHtmlScripts(CraReport report, bool darkMode)
    {
        // Serialize without indentation to minimize HTML report size (saves 1-3MB for large projects)
        var sbomJson = JsonSerializer.Serialize(report.Sbom);
        var vexJson = JsonSerializer.Serialize(report.Vex, CamelCaseOptions);

        // Generate centralized package data for lazy loading (reduces DOM size by 80%+)
        var packageDataJson = GeneratePackageDataJson();

        return $@"
<script>
const sbomData = {sbomJson};
const vexData = {vexJson};
const packageData = {packageDataJson};

function toggleTheme() {{
  const toggle = document.getElementById('themeToggle');
  toggle.classList.toggle('active');
  if (toggle.classList.contains('active')) {{
    document.documentElement.setAttribute('data-theme', 'dark');
  }} else {{
    document.documentElement.removeAttribute('data-theme');
  }}
}}

function showSection(sectionId) {{
  document.querySelectorAll('.section').forEach(s => s.classList.remove('active'));
  document.querySelectorAll('.nav-links a').forEach(a => a.classList.remove('active'));
  document.getElementById(sectionId).classList.add('active');
  document.querySelector(`[data-section='${{sectionId}}']`).classList.add('active');
}}

function togglePackage(header) {{
  const card = header.parentElement;
  const details = card.querySelector('.package-details');

  // Lazy load details on first expand
  if (details && !details.dataset.loaded) {{
    const pkgId = card.id.replace('pkg-', '');
    const pkg = packageData[pkgId] || packageData[pkgId.toLowerCase()];
    if (pkg) {{
      details.innerHTML = renderPackageDetails(pkg);
      details.dataset.loaded = 'true';
    }}
  }}

  card.classList.toggle('expanded');
}}

function renderPackageDetails(pkg) {{
  var html = '';

  // Detail grid
  if (pkg.hasData) {{
    html += '<div class=""detail-grid"">';
    html += '<div class=""detail-item""><span class=""label"">License</span><span class=""value"">' + formatLicense(pkg.license) + '</span></div>';
    if (pkg.daysSinceLastRelease !== null) {{
      html += '<div class=""detail-item""><span class=""label"">Last Release</span><span class=""value"">' + formatDaysSince(pkg.daysSinceLastRelease) + '</span></div>';
    }}
    // Version status - show if newer version available
    if (pkg.latestVersion) {{
      var versionStatus = compareVersions(pkg.version, pkg.latestVersion);
      if (versionStatus.isLatest) {{
        html += '<div class=""detail-item""><span class=""label"">Version Status</span><span class=""value""><span class=""version-current"">&#10003; Latest</span></span></div>';
      }} else {{
        var urgencyClass = versionStatus.urgency;
        html += '<div class=""detail-item""><span class=""label"">Latest Available</span><span class=""value""><span class=""version-upgrade ' + urgencyClass + '"">&#8593; ' + escapeHtml(pkg.latestVersion) + '</span></span></div>';
      }}
    }}
    if (pkg.releasesPerYear > 0) {{
      html += '<div class=""detail-item""><span class=""label"">Releases/Year</span><span class=""value"">' + pkg.releasesPerYear.toFixed(1) + '</span></div>';
    }}
    if (pkg.downloads > 0) {{
      html += '<div class=""detail-item""><span class=""label"">Downloads</span><span class=""value"">' + formatNumber(pkg.downloads) + '</span></div>';
    }}
    if (pkg.stars) {{
      html += '<div class=""detail-item""><span class=""label"">GitHub Stars</span><span class=""value"">' + formatNumber(pkg.stars) + '</span></div>';
    }}
    if (pkg.daysSinceLastCommit !== null) {{
      html += '<div class=""detail-item""><span class=""label"">Last Commit</span><span class=""value"">' + pkg.daysSinceLastCommit + ' days ago</span></div>';
    }}
    html += '</div>';
  }}

  // Recommendations
  if (pkg.recommendations && pkg.recommendations.length > 0) {{
    html += '<div class=""recommendations""><h4>Recommendations</h4><ul>';
    pkg.recommendations.forEach(function(r) {{ html += '<li>' + escapeHtml(r) + '</li>'; }});
    html += '</ul></div>';
  }}

  // Vulnerabilities
  if (pkg.vulnCount > 0) {{
    html += '<div class=""vulnerabilities-badge""><span class=""vuln-count"">' + pkg.vulnCount + ' vulnerabilities</span></div>';
  }}

  // Peer dependencies (npm only)
  if (pkg.peerDependencies && pkg.peerDependencies.length > 0) {{
    html += '<div class=""package-dependencies peer-deps""><h4>Peer Dependencies (' + pkg.peerDependencies.length + ')</h4><div class=""dep-list"">';
    pkg.peerDependencies.forEach(function(dep) {{
      var url = 'https://www.npmjs.com/package/' + encodeURIComponent(dep.id);
      html += '<a href=""' + url + '"" target=""_blank"" class=""dep-item dep-peer"" title=""Required: ' + escapeHtml(dep.range || 'any') + '"">' + escapeHtml(dep.id) + ' <span class=""peer-range"">' + escapeHtml(dep.range || '') + '</span></a>';
    }});
    html += '</div></div>';
  }}

  // Dependencies
  if (pkg.dependencies && pkg.dependencies.length > 0) {{
    html += '<div class=""package-dependencies""><h4>Dependencies (' + pkg.dependencies.length + ')</h4><div class=""dep-list"">';
    var deps = pkg.dependencies.slice(0, 10);
    deps.forEach(function(dep) {{
      if (packageData[dep.id] || packageData[dep.id.toLowerCase()]) {{
        html += '<a href=""#pkg-' + escapeHtml(dep.id) + '"" class=""dep-item dep-internal"" title=""' + escapeHtml(dep.range || 'any') + ' - Click to jump to package"" onclick=""navigateToPackage(\'' + escapeJs(dep.id) + '\'); return false;"">' + escapeHtml(dep.id) + '</a>';
      }} else {{
        var url = pkg.ecosystem === 'npm' ? 'https://www.npmjs.com/package/' + encodeURIComponent(dep.id) : 'https://www.nuget.org/packages/' + encodeURIComponent(dep.id);
        html += '<a href=""' + url + '"" target=""_blank"" class=""dep-item dep-external"" title=""' + escapeHtml(dep.range || 'any') + ' - External dependency"">' + escapeHtml(dep.id) + '</a>';
      }}
    }});
    if (pkg.dependencies.length > 10) {{
      html += '<span class=""dep-more"">+' + (pkg.dependencies.length - 10) + ' more</span>';
    }}
    html += '</div></div>';
  }}

  // Parent packages (required by)
  if (pkg.parents && pkg.parents.length > 0) {{
    html += '<div class=""required-by""><h4>Required By</h4><div class=""parent-packages"">';
    var parents = pkg.parents.slice(0, 5);
    parents.forEach(function(parentId) {{
      var isDirect = packageData[parentId] && packageData[parentId].isDirect;
      var cls = isDirect ? 'parent-badge direct' : 'parent-badge';
      html += '<a href=""#"" class=""' + cls + '"" onclick=""navigateToPackage(\'' + escapeHtml(parentId.toLowerCase()) + '\'); return false;"" title=""' + (isDirect ? 'Direct dependency' : 'Transitive dependency') + '"">' + escapeHtml(parentId) + '</a>';
    }});
    if (pkg.parents.length > 5) {{
      html += '<span class=""more-parents"">+' + (pkg.parents.length - 5) + ' more</span>';
    }}
    html += '</div></div>';
  }}

  // Links
  html += '<div class=""package-links"">';
  html += '<a href=""' + pkg.registryUrl + '"" target=""_blank"">' + (pkg.ecosystem === 'npm' ? 'npm' : 'NuGet') + '</a>';
  if (pkg.repoUrl) {{
    html += '<a href=""' + escapeHtml(pkg.repoUrl) + '"" target=""_blank"">Repository</a>';
  }}
  html += '</div>';

  return html;
}}

function formatLicense(license) {{
  if (!license) return '<span class=""unknown"">Unknown</span>';
  return '<span class=""license-badge"">' + escapeHtml(license) + '</span>';
}}

function formatDaysSince(days) {{
  if (days === null || days === undefined) return 'Unknown';
  if (days === 0) return 'Today';
  if (days === 1) return 'Yesterday';
  if (days < 30) return days + ' days ago';
  if (days < 365) return Math.floor(days / 30) + ' months ago';
  return (days / 365).toFixed(1) + ' years ago';
}}

function formatNumber(n) {{
  if (n >= 1000000000) return (n / 1000000000).toFixed(1) + 'B';
  if (n >= 1000000) return (n / 1000000).toFixed(1) + 'M';
  if (n >= 1000) return (n / 1000).toFixed(1) + 'K';
  return n.toString();
}}

function escapeHtml(str) {{
  if (!str) return '';
  var div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}}

function escapeJs(str) {{
  if (!str) return '';
  return str.replace(/\\/g, '\\\\').replace(/'/g, ""\\'"");
}}

function compareVersions(current, latest) {{
  if (!current || !latest) return {{ isLatest: true, urgency: """" }};

  // Normalize versions - remove leading v, handle pre-release
  var normCurrent = current.replace(/^v/, """").split(""-"")[0];
  var normLatest = latest.replace(/^v/, """").split(""-"")[0];

  if (normCurrent === normLatest) return {{ isLatest: true, urgency: """" }};

  // Parse semver parts
  var currParts = normCurrent.split(""."").map(function(p) {{ return parseInt(p, 10) || 0; }});
  var lateParts = normLatest.split(""."").map(function(p) {{ return parseInt(p, 10) || 0; }});

  // Pad arrays to same length
  while (currParts.length < 3) currParts.push(0);
  while (lateParts.length < 3) lateParts.push(0);

  // Compare major.minor.patch
  var majorDiff = lateParts[0] - currParts[0];
  var minorDiff = lateParts[1] - currParts[1];
  var patchDiff = lateParts[2] - currParts[2];

  // Determine urgency based on version difference
  var urgency = ""upgrade-patch"";
  if (majorDiff > 0) {{
    urgency = ""upgrade-major"";
  }} else if (majorDiff === 0 && minorDiff > 0) {{
    urgency = ""upgrade-minor"";
  }} else if (majorDiff < 0 || (majorDiff === 0 && minorDiff < 0)) {{
    // Current is actually newer than latest
    return {{ isLatest: true, urgency: """" }};
  }}

  return {{ isLatest: false, urgency: urgency }};
}}

function navigateToPackage(packageIdOrName) {{
  // Normalize to lowercase for data-name lookup
  var nameLower = packageIdOrName.toLowerCase();

  // Try to find by ID first (case-preserved), then by data-name (lowercase)
  var target = document.getElementById('pkg-' + packageIdOrName) ||
               document.querySelector("".package-card[data-name='"" + nameLower + ""']"");

  if (target) {{
    showSection('packages');

    // If it's transitive, expand the transitive section
    if (target.classList.contains('transitive')) {{
      const list = document.getElementById('transitive-list');
      const toggle = document.getElementById('transitive-toggle');
      if (list && list.style.display === 'none') {{
        list.style.display = '';
        if (toggle) toggle.textContent = 'Hide';
      }}
    }}

    // Clear search/filter that might be hiding the package
    const searchInput = document.getElementById('package-search');
    if (searchInput && searchInput.value) {{
      searchInput.value = '';
      filterPackages();
    }}

    // Reset filters to show all packages
    currentStatusFilter = 'all';
    currentEcosystemFilter = 'all';
    document.querySelectorAll('.filter-btn').forEach(btn => {{
      btn.classList.remove('active');
      if (btn.textContent.toLowerCase() === 'all') btn.classList.add('active');
    }});
    document.querySelectorAll('.package-card').forEach(card => card.style.display = '');

    // Expand and highlight the package
    target.classList.add('expanded');
    setTimeout(() => {{
      target.scrollIntoView({{ behavior: 'smooth', block: 'center' }});
      target.classList.add('highlight-flash');
      setTimeout(() => target.classList.remove('highlight-flash'), 2000);
    }}, 100);
    return;
  }}

  // Try dependency tree
  const treeNode = document.querySelector(`.tree-node[data-name='${{nameLower}}']`);
  if (treeNode) {{
    showSection('tree');
    // Expand parent nodes to make this node visible
    let parent = treeNode.parentElement;
    while (parent) {{
      if (parent.classList && parent.classList.contains('tree-children')) {{
        parent.style.display = 'block';
        const toggle = parent.previousElementSibling?.querySelector('.tree-toggle');
        if (toggle && toggle.textContent === '[+]') {{
          toggle.textContent = '[-]';
        }}
      }}
      parent = parent.parentElement;
    }}
    treeNode.scrollIntoView({{ behavior: 'smooth', block: 'center' }});
    treeNode.classList.add('highlight-flash');
    setTimeout(() => treeNode.classList.remove('highlight-flash'), 2000);
    return;
  }}

  // Package not found - open external link (NuGet for .NET, npm for JS)
  const ecosystem = document.querySelector('.package-card')?.dataset.ecosystem || 'nuget';
  if (ecosystem === 'npm') {{
    window.open('https://www.npmjs.com/package/' + encodeURIComponent(packageIdOrName), '_blank');
  }} else {{
    window.open('https://www.nuget.org/packages/' + encodeURIComponent(packageIdOrName), '_blank');
  }}
}}

function filterPackages() {{
  const search = document.getElementById('package-search').value.toLowerCase();
  document.querySelectorAll('.package-card').forEach(card => {{
    const name = card.dataset.name;
    card.style.display = name.includes(search) ? '' : 'none';
  }});
}}

let currentStatusFilter = 'all';
let currentEcosystemFilter = 'all';

function filterByStatus(status) {{
  currentStatusFilter = status;
  document.querySelectorAll('.filter-btn:not(.ecosystem-btn)').forEach(btn => btn.classList.remove('active'));
  event.target.classList.add('active');
  applyPackageFilters();
}}

function filterByEcosystem(ecosystem) {{
  currentEcosystemFilter = ecosystem;
  document.querySelectorAll('.filter-btn.ecosystem-btn').forEach(btn => btn.classList.remove('active'));
  event.target.classList.add('active');
  applyPackageFilters();
}}

function sortPackages(sortBy, isInitial) {{
  if (!isInitial) {{
    document.querySelectorAll('.filter-btn.sort-btn').forEach(btn => btn.classList.remove('active'));
    event.target.classList.add('active');
  }}

  // Sort comparator with name as tiebreaker
  const compare = (a, b) => {{
    let result = 0;
    if (sortBy === 'name') {{
      result = a.dataset.name.localeCompare(b.dataset.name);
    }} else if (sortBy === 'health') {{
      result = parseInt(a.dataset.health || 50) - parseInt(b.dataset.health || 50);
      if (result === 0) result = a.dataset.name.localeCompare(b.dataset.name);
    }}
    return result;
  }};

  // Sort direct packages
  const directList = document.getElementById('packages-list');
  const directCards = Array.from(directList.querySelectorAll('.package-card:not(.transitive)'));
  directCards.sort(compare);
  directCards.forEach(card => directList.appendChild(card));

  // Sort transitive packages
  const transitiveList = document.getElementById('transitive-list');
  if (transitiveList) {{
    const transitiveCards = Array.from(transitiveList.querySelectorAll('.package-card.transitive'));
    transitiveCards.sort(compare);
    transitiveCards.forEach(card => transitiveList.appendChild(card));
  }}
}}

// Apply default sort on page load
document.addEventListener('DOMContentLoaded', () => sortPackages('health', true));

function applyPackageFilters() {{
  document.querySelectorAll('.package-card').forEach(card => {{
    const statusMatch = currentStatusFilter === 'all' || card.dataset.status === currentStatusFilter;
    const ecosystemMatch = currentEcosystemFilter === 'all' || card.dataset.ecosystem === currentEcosystemFilter;
    card.style.display = (statusMatch && ecosystemMatch) ? '' : 'none';
  }});
}}

function filterSbom() {{
  const search = document.getElementById('sbom-search').value.toLowerCase();
  document.querySelectorAll('#sbom-table tbody tr').forEach(row => {{
    const name = row.dataset.name;
    row.style.display = name.includes(search) ? '' : 'none';
  }});
}}

function toggleTransitive() {{
  const list = document.getElementById('transitive-list');
  const toggle = document.getElementById('transitive-toggle');
  if (list.style.display === 'none') {{
    list.style.display = '';
    toggle.textContent = 'Hide';
  }} else {{
    list.style.display = 'none';
    toggle.textContent = 'Show';
  }}
}}

function toggleReviewedVulns() {{
  const list = document.getElementById('reviewed-vulns-list');
  const toggle = document.getElementById('reviewed-toggle');
  if (list.style.display === 'none') {{
    list.style.display = '';
    toggle.textContent = '-';
  }} else {{
    list.style.display = 'none';
    toggle.textContent = '+';
  }}
}}

function exportSbom(format) {{
  let data, filename, type;
  if (format === 'spdx') {{
    data = JSON.stringify(sbomData, null, 2);
    filename = 'sbom.spdx.json';
    type = 'application/json';
  }} else {{
    // Convert to CycloneDX format
    data = JSON.stringify(sbomData, null, 2);
    filename = 'sbom.cyclonedx.json';
    type = 'application/json';
  }}

  const blob = new Blob([data], {{ type }});
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}}

// Dependency Tree functions
function toggleTreeNode(toggle) {{
  const li = toggle.closest('.tree-node');
  const children = li.querySelector('.tree-children');
  if (children) {{
    const isCollapsed = children.classList.contains('collapsed');
    children.classList.toggle('collapsed');
    toggle.textContent = isCollapsed ? '[-]' : '[+]';
  }}
}}

function expandAllTree() {{
  document.querySelectorAll('.tree-children').forEach(el => {{
    el.classList.remove('collapsed');
  }});
  document.querySelectorAll('.tree-toggle:not(.leaf)').forEach(el => {{
    el.textContent = '[-]';
  }});
}}

function collapseAllTree() {{
  document.querySelectorAll('.tree-children').forEach(el => {{
    el.classList.add('collapsed');
  }});
  document.querySelectorAll('.tree-toggle:not(.leaf)').forEach(el => {{
    el.textContent = '[+]';
  }});
}}

function filterTree() {{
  const search = document.getElementById('tree-search').value.toLowerCase();

  if (!search) {{
    // Show all nodes
    document.querySelectorAll('.tree-node').forEach(node => {{
      node.classList.remove('hidden');
    }});
    return;
  }}

  // First, hide all nodes
  document.querySelectorAll('.tree-node').forEach(node => {{
    node.classList.add('hidden');
  }});

  // Find matching nodes and show them with their ancestors
  document.querySelectorAll('.tree-node').forEach(node => {{
    const name = node.dataset.name || '';
    if (name.includes(search)) {{
      // Show this node
      node.classList.remove('hidden');

      // Show all ancestors
      let parent = node.parentElement;
      while (parent) {{
        if (parent.classList && parent.classList.contains('tree-node')) {{
          parent.classList.remove('hidden');
        }}
        parent = parent.parentElement;
      }}

      // Expand ancestor tree-children
      let ancestor = node.parentElement;
      while (ancestor) {{
        if (ancestor.classList && ancestor.classList.contains('tree-children')) {{
          ancestor.classList.remove('collapsed');
          const toggle = ancestor.previousElementSibling?.querySelector('.tree-toggle');
          if (toggle && !toggle.classList.contains('leaf')) {{
            toggle.textContent = '[-]';
          }}
        }}
        ancestor = ancestor.parentElement;
      }}
    }}
  }});
}}

function filterTreeByEcosystem(ecosystem) {{
  document.querySelectorAll('.tree-ecosystem-filter .filter-btn').forEach(btn => btn.classList.remove('active'));
  event.target.classList.add('active');

  document.querySelectorAll('.dependency-tree').forEach(tree => {{
    const header = tree.previousElementSibling;
    if (ecosystem === 'all') {{
      tree.style.display = '';
      if (header && header.classList.contains('ecosystem-header')) {{
        header.style.display = '';
      }}
    }} else {{
      const match = tree.dataset.ecosystem === ecosystem;
      tree.style.display = match ? '' : 'none';
      if (header && header.classList.contains('ecosystem-header')) {{
        header.style.display = match ? '' : 'none';
      }}
    }}
  }});
}}
</script>";
    }

    private List<PackageHealth>? _healthDataCache;
    private List<PackageHealth>? _transitiveDataCache;
    private List<DependencyTree> _dependencyTrees = [];
    private Dictionary<string, List<string>> _parentLookup = new(StringComparer.OrdinalIgnoreCase);
    private bool _hasIncompleteTransitive;
    private bool _hasUnresolvedVersions;

    // Cached license data (computed once on first access)
    private List<(string PackageId, string? License)>? _packageLicensesCache;

    // Additional CRA compliance data
    private int _deprecatedPackageCount;
    private List<string> _deprecatedPackages = [];
    private int _packagesWithSecurityPolicy;
    private int _totalPackagesWithRepo;
    private List<(string Cve, string PackageId)> _kevCvePackages = [];
    private HashSet<string> _kevPackageIds = new(StringComparer.OrdinalIgnoreCase);
    private Dictionary<string, EpssScore> _epssScores = new(StringComparer.OrdinalIgnoreCase);
    private List<TyposquatResult> _typosquatResults = [];
    private bool _typosquatChecked;
    private CryptoComplianceResult? _cryptoCompliance;

    // Phase 1: Maintenance data (F1/F2)
    private List<string> _archivedPackageNames = [];
    private List<string> _stalePackageNames = [];
    private List<string> _unmaintainedPackageNames = [];
    private int _totalWithRepoData;

    // Phase 1: Documentation (F3)
    private bool _hasReadme;
    private bool _hasSecurityContact;
    private bool _hasSupportPeriod;
    private bool _hasChangelog;

    // Phase 2: Remediation (F5)
    private List<(string PackageId, string VulnId, int DaysSince, string PatchVersion)> _remediationData = [];

    // Phase 3: Attack surface (F7) and SBOM validation (F8)
    private AttackSurfaceResult? _attackSurface;
    private SbomValidationResult? _sbomValidation;

    // Phase 4: Provenance (F9)
    private List<ProvenanceResult> _provenanceResults = [];

    /// <summary>
    /// Get cached list of package licenses (computed once from health and transitive data).
    /// </summary>
    private List<(string PackageId, string? License)> GetPackageLicenses()
    {
        if (_packageLicensesCache is not null)
            return _packageLicensesCache;

        _packageLicensesCache = new List<(string PackageId, string? License)>();
        if (_healthDataCache is not null)
        {
            foreach (var pkg in _healthDataCache)
                _packageLicensesCache.Add((pkg.PackageId, pkg.License));
        }
        if (_transitiveDataCache is not null)
        {
            foreach (var pkg in _transitiveDataCache)
                _packageLicensesCache.Add((pkg.PackageId, pkg.License));
        }
        return _packageLicensesCache;
    }

    /// <summary>
    /// Set package health data for detailed report generation.
    /// </summary>
    public void SetHealthData(IEnumerable<PackageHealth> packages)
    {
        _healthDataCache = packages.ToList();
    }

    /// <summary>
    /// Set transitive dependency health data for detailed report generation.
    /// </summary>
    public void SetTransitiveData(IEnumerable<PackageHealth> packages)
    {
        _transitiveDataCache = packages.ToList();
    }

    /// <summary>
    /// Set SBOM completeness warnings.
    /// </summary>
    public void SetCompletenessWarnings(bool incompleteTransitive, bool unresolvedVersions)
    {
        _hasIncompleteTransitive = incompleteTransitive;
        _hasUnresolvedVersions = unresolvedVersions;
    }

    /// <summary>
    /// Set deprecated packages data (CRA Article 10 - deprecated components).
    /// </summary>
    public void SetDeprecatedPackages(IEnumerable<string> deprecatedPackages)
    {
        _deprecatedPackages = deprecatedPackages.ToList();
        _deprecatedPackageCount = _deprecatedPackages.Count;
    }

    /// <summary>
    /// Set security policy statistics from GitHub repos (CRA Article 11(5)).
    /// </summary>
    public void SetSecurityPolicyStats(int packagesWithPolicy, int totalPackagesWithRepo)
    {
        _packagesWithSecurityPolicy = packagesWithPolicy;
        _totalPackagesWithRepo = totalPackagesWithRepo;
    }

    /// <summary>
    /// Set CISA KEV (Known Exploited Vulnerabilities) data (CRA Article 10(4)).
    /// </summary>
    public void SetKnownExploitedVulnerabilities(IEnumerable<(string Cve, string PackageId)> kevCvePackages)
    {
        _kevCvePackages = kevCvePackages.ToList();
        _kevPackageIds = new HashSet<string>(_kevCvePackages.Select(k => k.PackageId), StringComparer.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Set EPSS (Exploit Prediction Scoring System) scores for vulnerability prioritization.
    /// </summary>
    public void SetEpssScores(Dictionary<string, EpssScore> scores)
    {
        _epssScores = scores;
    }

    /// <summary>
    /// Set typosquatting detection results for supply chain analysis section.
    /// </summary>
    public void SetTyposquatResults(List<TyposquatResult> results)
    {
        _typosquatResults = results;
        _typosquatChecked = true;
    }

    /// <summary>
    /// Set cryptographic compliance check results (CRA Article 10).
    /// </summary>
    public void SetCryptoCompliance(CryptoComplianceResult result)
    {
        _cryptoCompliance = result;
    }

    /// <summary>
    /// Set maintenance data for CRA Art. 10(6) and Art. 13(8).
    /// </summary>
    public void SetMaintenanceData(List<string> archived, List<string> stale, List<string> unmaintained, int totalWithRepoData)
    {
        _archivedPackageNames = archived;
        _stalePackageNames = stale;
        _unmaintainedPackageNames = unmaintained;
        _totalWithRepoData = totalWithRepoData;
    }

    /// <summary>
    /// Set project documentation status for CRA Annex II.
    /// </summary>
    public void SetProjectDocumentation(bool hasReadme, bool hasSecurityContact, bool hasSupportPeriod, bool hasChangelog)
    {
        _hasReadme = hasReadme;
        _hasSecurityContact = hasSecurityContact;
        _hasSupportPeriod = hasSupportPeriod;
        _hasChangelog = hasChangelog;
    }

    /// <summary>
    /// Set vulnerability remediation data for CRA Art. 11(4).
    /// </summary>
    public void SetRemediationData(List<(string PackageId, string VulnId, int DaysSince, string PatchVersion)> data)
    {
        _remediationData = data;
    }

    /// <summary>
    /// Set attack surface analysis data for CRA Annex I Part I(10).
    /// </summary>
    public void SetAttackSurfaceData(AttackSurfaceResult result)
    {
        _attackSurface = result;
    }

    /// <summary>
    /// Set SBOM validation data for CRA Annex I Part II(1).
    /// </summary>
    public void SetSbomValidation(SbomValidationResult result)
    {
        _sbomValidation = result;
    }

    /// <summary>
    /// Set package provenance results for CRA Art. 13(5).
    /// </summary>
    public void SetProvenanceResults(List<ProvenanceResult> results)
    {
        _provenanceResults = results;
    }

    /// <summary>
    /// Set dependency tree for tree visualization.
    /// </summary>
    public void SetDependencyTree(DependencyTree? tree)
    {
        if (tree is not null)
        {
            _dependencyTrees = [tree];
        }
    }

    /// <summary>
    /// Add a dependency tree for tree visualization (supports multiple ecosystems).
    /// </summary>
    public void AddDependencyTree(DependencyTree? tree)
    {
        if (tree is not null)
        {
            _dependencyTrees.Add(tree);
        }
    }

    /// <summary>
    /// Build reverse dependency lookup (package -> list of packages that depend on it).
    /// Must be called after setting dependency trees.
    /// </summary>
    private void BuildParentLookup()
    {
        _parentLookup.Clear();

        foreach (var tree in _dependencyTrees)
        {
            foreach (var root in tree.Roots)
            {
                BuildParentLookupRecursive(root, null);
            }
        }
    }

    private void BuildParentLookupRecursive(DependencyTreeNode node, string? parentId)
    {
        // Record this node's parent
        if (parentId is not null)
        {
            if (!_parentLookup.TryGetValue(node.PackageId, out var parents))
            {
                parents = [];
                _parentLookup[node.PackageId] = parents;
            }
            if (!parents.Contains(parentId, StringComparer.OrdinalIgnoreCase))
            {
                parents.Add(parentId);
            }
        }

        // Process children
        foreach (var child in node.Children)
        {
            BuildParentLookupRecursive(child, node.PackageId);
        }
    }

    /// <summary>
    /// Generate centralized package data JSON for lazy loading in client.
    /// </summary>
    private string GeneratePackageDataJson()
    {
        var packages = new Dictionary<string, object>(StringComparer.OrdinalIgnoreCase);

        // Add direct packages
        if (_healthDataCache is not null)
        {
            foreach (var pkg in _healthDataCache)
            {
                packages[pkg.PackageId] = CreatePackageDataObject(pkg, isDirect: true);
            }
        }

        // Add transitive packages (excluding sub-dependencies)
        if (_transitiveDataCache is not null)
        {
            foreach (var pkg in _transitiveDataCache.Where(p => p.DependencyType != DependencyType.SubDependency))
            {
                if (!packages.ContainsKey(pkg.PackageId))
                {
                    packages[pkg.PackageId] = CreatePackageDataObject(pkg, isDirect: false);
                }
            }
        }

        return JsonSerializer.Serialize(packages);
    }

    private object CreatePackageDataObject(PackageHealth pkg, bool isDirect)
    {
        var ecosystem = pkg.Ecosystem == PackageEcosystem.Npm ? "npm" : "nuget";
        var registryUrl = ecosystem == "npm"
            ? $"https://www.npmjs.com/package/{Uri.EscapeDataString(pkg.PackageId)}/v/{Uri.EscapeDataString(pkg.Version)}"
            : $"https://www.nuget.org/packages/{pkg.PackageId}/{pkg.Version}";

        var hasData = pkg.Metrics.TotalDownloads > 0 ||
                      pkg.Metrics.DaysSinceLastRelease.HasValue ||
                      pkg.Metrics.ReleasesPerYear > 0;

        _parentLookup.TryGetValue(pkg.PackageId, out var parents);

        return new
        {
            name = pkg.PackageId,
            version = pkg.Version,
            score = pkg.Score,
            status = pkg.Status.ToString().ToLowerInvariant(),
            ecosystem,
            isDirect,
            hasData,
            license = pkg.License,
            daysSinceLastRelease = pkg.Metrics.DaysSinceLastRelease,
            releasesPerYear = pkg.Metrics.ReleasesPerYear,
            downloads = pkg.Metrics.TotalDownloads,
            stars = pkg.Metrics.Stars,
            daysSinceLastCommit = pkg.Metrics.DaysSinceLastCommit,
            repoUrl = pkg.RepositoryUrl,
            registryUrl,
            recommendations = pkg.Recommendations,
            vulnCount = pkg.Vulnerabilities.Count,
            dependencies = pkg.Dependencies.Select(d => new { id = d.PackageId, range = d.VersionRange }).ToList(),
            parents = parents ?? [],
            latestVersion = pkg.LatestVersion,
            peerDependencies = pkg.PeerDependencies.Select(p => new { id = p.Key, range = p.Value }).ToList()
        };
    }

    private static string GetScoreClass(int score) => score switch
    {
        >= 80 => "healthy",
        >= 60 => "watch",
        >= 40 => "warning",
        _ => "critical"
    };

    private static string GetEpssBadgeClass(double probability) => probability switch
    {
        >= 0.5 => "epss-critical",
        >= 0.1 => "epss-high",
        >= 0.01 => "epss-medium",
        _ => "epss-low"
    };

    private static bool IsKnownSpdxLicense(string license)
    {
        var normalized = license.Trim().TrimStart('(').TrimEnd(')').Trim();
        var separators = new[] { " OR ", " AND ", " WITH " };
        var parts = normalized.Split(separators, StringSplitOptions.RemoveEmptyEntries);

        if (parts.Length > 1)
        {
            return parts.All(p => IsKnownSingleLicense(p.Trim().TrimStart('(').TrimEnd(')').Trim().ToUpperInvariant()));
        }

        return IsKnownSingleLicense(normalized.ToUpperInvariant());
    }

    private static bool IsKnownSingleLicense(string license) => license switch
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
        "CLASSPATH-EXCEPTION-2.0" or "LLVM-EXCEPTION" => true,
        _ => false
    };

    private static string FormatNumber(long number) => number switch
    {
        >= 1_000_000_000 => $"{number / 1_000_000_000.0:F1}B",
        >= 1_000_000 => $"{number / 1_000_000.0:F1}M",
        >= 1_000 => $"{number / 1_000.0:F1}K",
        _ => number.ToString()
    };

    private static string FormatDownloads(long downloads) =>
        downloads == 0 ? "N/A" : FormatNumber(downloads);

    private static string FormatDuration(TimeSpan duration) => duration.TotalSeconds switch
    {
        < 1 => $"{duration.TotalMilliseconds:F0}ms",
        < 60 => $"{duration.TotalSeconds:F1}s",
        < 3600 => $"{duration.Minutes}m {duration.Seconds}s",
        _ => $"{duration.Hours}h {duration.Minutes}m"
    };

    // Known SPDX license URLs
    private static readonly Dictionary<string, string> LicenseUrls = new(StringComparer.OrdinalIgnoreCase)
    {
        ["MIT"] = "https://opensource.org/licenses/MIT",
        ["Apache-2.0"] = "https://opensource.org/licenses/Apache-2.0",
        ["BSD-2-Clause"] = "https://opensource.org/licenses/BSD-2-Clause",
        ["BSD-3-Clause"] = "https://opensource.org/licenses/BSD-3-Clause",
        ["GPL-2.0"] = "https://opensource.org/licenses/GPL-2.0",
        ["GPL-3.0"] = "https://opensource.org/licenses/GPL-3.0",
        ["LGPL-2.1"] = "https://opensource.org/licenses/LGPL-2.1",
        ["LGPL-3.0"] = "https://opensource.org/licenses/LGPL-3.0",
        ["MPL-2.0"] = "https://opensource.org/licenses/MPL-2.0",
        ["ISC"] = "https://opensource.org/licenses/ISC",
        ["Unlicense"] = "https://unlicense.org/",
        ["CC0-1.0"] = "https://creativecommons.org/publicdomain/zero/1.0/",
        ["MS-PL"] = "https://opensource.org/licenses/MS-PL",
    };

    private static string FormatLicense(string? license)
    {
        if (string.IsNullOrEmpty(license))
            return "<span class=\"license-unknown\">Unknown</span>";

        // Handle NOASSERTION - SPDX term for unknown/unspecified license
        if (license.Equals("NOASSERTION", StringComparison.OrdinalIgnoreCase))
        {
            return "<span class=\"license-unknown\" title=\"License not specified in package metadata\">Not Specified</span>";
        }

        // Check for known SPDX licenses and add links
        if (LicenseUrls.TryGetValue(license, out var url))
        {
            return $"<a href=\"{url}\" target=\"_blank\" class=\"license-link\">{EscapeHtml(license)}</a>";
        }

        // If it's a URL, make it a clickable link with truncated display
        if (license.StartsWith("http://", StringComparison.OrdinalIgnoreCase) ||
            license.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
        {
            // Extract license name from URL if possible
            var displayName = "View License";
            try
            {
                var uri = new Uri(license);
                var segments = uri.Segments;
                if (segments.Length > 0)
                {
                    var lastSegment = segments[^1].TrimEnd('/');
                    if (!string.IsNullOrEmpty(lastSegment) &&
                        !lastSegment.Equals("license", StringComparison.OrdinalIgnoreCase) &&
                        !lastSegment.Equals("licenses", StringComparison.OrdinalIgnoreCase))
                    {
                        displayName = lastSegment;
                    }
                }
            }
            catch { /* Use default display name */ }

            return $"<a href=\"{EscapeHtml(license)}\" target=\"_blank\" title=\"{EscapeHtml(license)}\" class=\"license-link\">{EscapeHtml(displayName)}</a>";
        }

        // For other license identifiers, try to link to SPDX
        return $"<a href=\"https://spdx.org/licenses/{EscapeHtml(license)}.html\" target=\"_blank\" class=\"license-link\">{EscapeHtml(license)}</a>";
    }

    private static string FormatVersionForSbom(string? version)
    {
        if (string.IsNullOrEmpty(version))
            return "<span class=\"unresolved-version\">Unknown</span>";

        if (version.Contains("$("))
        {
            return $"<span class=\"unresolved-version\" title=\"MSBuild variable not resolved: {EscapeHtml(version)}\">Not resolved ⓘ</span>";
        }

        return EscapeHtml(version);
    }

    private static string FormatPurlForSbom(string? purl)
    {
        if (string.IsNullOrEmpty(purl))
            return "<span class=\"text-muted\">-</span>";

        if (purl.Contains("$("))
        {
            // Extract the package name from the purl using compiled regex
            var match = PurlRegex().Match(purl);
            if (match.Success)
            {
                return $"<span class=\"unresolved-version\" title=\"Full PURL: {EscapeHtml(purl)}\">pkg:nuget/{EscapeHtml(match.Groups[1].Value)}@? ⓘ</span>";
            }
            return $"<span class=\"unresolved-version\" title=\"{EscapeHtml(purl)}\">Not resolved ⓘ</span>";
        }

        return EscapeHtml(purl);
    }

    private static string FormatDaysSinceRelease(int? days)
    {
        if (!days.HasValue)
            return "<span class=\"unknown-date\" title=\"Release date not available from NuGet API\">Unknown</span>";

        return $"{days.Value} days ago";
    }

    private static string FormatVersion(string? version, string packageId)
    {
        if (string.IsNullOrEmpty(version))
            return "<span class=\"unresolved-version\">Unknown</span>";

        // Check for unresolved MSBuild variable
        if (version.StartsWith("$(") || version.Contains("$("))
        {
            // Extract variable name for the tooltip
            var varName = version;
            var tooltip = $"Version uses MSBuild variable '{varName}' which wasn't resolved. Run 'dotnet restore' first, or ensure Directory.Build.props defines this variable.";
            return $"<span class=\"unresolved-version\" title=\"{EscapeHtml(tooltip)}\">Version not resolved <span class=\"version-hint\">ⓘ</span></span>";
        }

        return EscapeHtml(version);
    }

    /// <summary>
    /// Generate JSON report.
    /// </summary>
    public string GenerateJson(CraReport report)
    {
        return JsonSerializer.Serialize(report, new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase
        });
    }

    private static string? GetLicenseUrl(string license)
    {
        // Normalize license identifier
        var normalized = license.Trim();

        // Map common license identifiers to SPDX URLs
        return normalized.ToUpperInvariant() switch
        {
            "MIT" => "https://spdx.org/licenses/MIT.html",
            "APACHE-2.0" or "APACHE 2.0" or "APACHE2" => "https://spdx.org/licenses/Apache-2.0.html",
            "BSD-2-CLAUSE" or "BSD 2-CLAUSE" => "https://spdx.org/licenses/BSD-2-Clause.html",
            "BSD-3-CLAUSE" or "BSD 3-CLAUSE" => "https://spdx.org/licenses/BSD-3-Clause.html",
            "GPL-2.0" or "GPL-2.0-ONLY" or "GPL2" => "https://spdx.org/licenses/GPL-2.0-only.html",
            "GPL-3.0" or "GPL-3.0-ONLY" or "GPL3" => "https://spdx.org/licenses/GPL-3.0-only.html",
            "GPL-3.0-OR-LATER" => "https://spdx.org/licenses/GPL-3.0-or-later.html",
            "LGPL-2.1" or "LGPL-2.1-ONLY" => "https://spdx.org/licenses/LGPL-2.1-only.html",
            "LGPL-3.0" or "LGPL-3.0-ONLY" => "https://spdx.org/licenses/LGPL-3.0-only.html",
            "ISC" => "https://spdx.org/licenses/ISC.html",
            "MPL-2.0" => "https://spdx.org/licenses/MPL-2.0.html",
            "UNLICENSE" or "UNLICENSED" => "https://spdx.org/licenses/Unlicense.html",
            "CC0-1.0" or "CC0" => "https://spdx.org/licenses/CC0-1.0.html",
            "WTFPL" => "https://spdx.org/licenses/WTFPL.html",
            "0BSD" => "https://spdx.org/licenses/0BSD.html",
            "MS-PL" => "https://spdx.org/licenses/MS-PL.html",
            "MS-RL" => "https://spdx.org/licenses/MS-RL.html",
            "ZLIB" => "https://spdx.org/licenses/Zlib.html",
            _ => normalized.StartsWith("HTTP", StringComparison.OrdinalIgnoreCase)
                ? normalized  // Already a URL
                : $"https://spdx.org/licenses/{Uri.EscapeDataString(normalized)}.html"  // Try SPDX lookup
        };
    }

    /// <summary>
    /// Format a license expression with individual links for each license.
    /// Handles SPDX expressions like "(MIT OR GPL-3.0-or-later)".
    /// </summary>
    private static string FormatLicenseWithLinks(string license)
    {
        if (string.IsNullOrWhiteSpace(license))
            return EscapeHtml(license);

        // Remove outer parentheses for display
        var text = license.Trim();
        if (text.StartsWith('(') && text.EndsWith(')'))
        {
            text = text[1..^1].Trim();
        }

        // Check for compound expressions
        if (text.Contains(" OR ", StringComparison.OrdinalIgnoreCase))
        {
            var parts = text.Split(new[] { " OR " }, StringSplitOptions.RemoveEmptyEntries);
            var linkedParts = parts.Select(p => FormatSingleLicenseLink(p.Trim()));
            return "(" + string.Join(" OR ", linkedParts) + ")";
        }

        if (text.Contains(" AND ", StringComparison.OrdinalIgnoreCase))
        {
            var parts = text.Split(new[] { " AND " }, StringSplitOptions.RemoveEmptyEntries);
            var linkedParts = parts.Select(p => FormatSingleLicenseLink(p.Trim()));
            return "(" + string.Join(" AND ", linkedParts) + ")";
        }

        if (text.Contains(" WITH ", StringComparison.OrdinalIgnoreCase))
        {
            var parts = text.Split(new[] { " WITH " }, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length >= 2)
            {
                return FormatSingleLicenseLink(parts[0].Trim()) + " WITH " + EscapeHtml(parts[1].Trim());
            }
        }

        // Simple single license
        return FormatSingleLicenseLink(text);
    }

    /// <summary>
    /// Format a single license identifier as a link.
    /// </summary>
    private static string FormatSingleLicenseLink(string license)
    {
        var url = GetLicenseUrl(license);
        if (url is not null)
        {
            return $"<a href=\"{EscapeHtml(url)}\" target=\"_blank\" title=\"View license\">{EscapeHtml(license)}</a>";
        }
        return EscapeHtml(license);
    }

    private static string EscapeHtml(string input)
    {
        if (string.IsNullOrEmpty(input)) return input;

        // Single pass with StringBuilder to avoid 5 intermediate string allocations
        var sb = new StringBuilder(input.Length + 16);
        foreach (var c in input)
        {
            sb.Append(c switch
            {
                '&' => "&amp;",
                '<' => "&lt;",
                '>' => "&gt;",
                '"' => "&quot;",
                '\'' => "&#39;",
                _ => c.ToString()
            });
        }
        return sb.ToString();
    }

    private static string EscapeJs(string input)
    {
        if (string.IsNullOrEmpty(input)) return input;

        // Single pass with StringBuilder to avoid 5 intermediate string allocations
        var sb = new StringBuilder(input.Length + 16);
        foreach (var c in input)
        {
            sb.Append(c switch
            {
                '\\' => "\\\\",
                '\'' => "\\'",
                '"' => "\\\"",
                '\n' => "\\n",
                '\r' => "\\r",
                _ => c.ToString()
            });
        }
        return sb.ToString();
    }
}

public sealed class CraReport
{
    public required DateTime GeneratedAt { get; init; }
    public TimeSpan? GenerationDuration { get; init; }
    public required string ProjectPath { get; init; }
    public required int HealthScore { get; init; }
    public required HealthStatus HealthStatus { get; init; }
    public required List<CraComplianceItem> ComplianceItems { get; init; }
    public required CraComplianceStatus OverallComplianceStatus { get; init; }
    public required SbomDocument Sbom { get; init; }
    public required VexDocument Vex { get; init; }
    public required int PackageCount { get; init; }
    public required int TransitivePackageCount { get; init; }
    public required int VulnerabilityCount { get; init; }
    public required int CriticalPackageCount { get; init; }
    public int VersionConflictCount { get; init; }
    public List<DependencyIssue> DependencyIssues { get; init; } = [];
    public int CraReadinessScore { get; init; }
}

public sealed class CraComplianceItem
{
    public required string Requirement { get; init; }
    public required string Description { get; init; }
    public required CraComplianceStatus Status { get; init; }
    public string? Evidence { get; init; }
    public string? Recommendation { get; init; }
}

// CraComplianceStatus enum is defined in Models/PackageHealth.cs
