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

    // CSS styles loaded once from embedded resource and minified
    private static readonly Lazy<string> _htmlStyles = new(() =>
    {
        using var stream = typeof(CraReportGenerator).Assembly
            .GetManifestResourceStream("DepSafe.Resources.report-styles.css")!;
        using var reader = new StreamReader(stream);
        return "<style>" + MinifyCss(reader.ReadToEnd()) + "</style>";
    });

    // Compiled regex for parsing PURLs (used repeatedly in FormatPurlForSbom)
    [GeneratedRegex(@"pkg:nuget/([^@]+)", RegexOptions.Compiled)]
    private static partial Regex PurlRegex();

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
    /// <summary>
    /// Generate SBOM and VEX artifacts without building compliance items.
    /// Use this to get the SBOM for validation before calling Generate(sbom, vex).
    /// </summary>
    public (SbomDocument Sbom, VexDocument Vex) GenerateArtifacts(
        ProjectReport healthReport,
        IReadOnlyDictionary<string, List<VulnerabilityInfo>> vulnerabilities)
    {
        var allPackagesForSbom = healthReport.Packages.AsEnumerable();
        if (_transitiveDataCache is not null)
        {
            allPackagesForSbom = allPackagesForSbom.Concat(_transitiveDataCache);
        }

        var sbom = _sbomGenerator.Generate(healthReport.ProjectPath, allPackagesForSbom);

        // Apply package checksums from provenance data
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

        var vex = _vexGenerator.Generate(allPackagesForSbom, vulnerabilities);
        return (sbom, vex);
    }

    /// <summary>
    /// Generate a full CRA report using pre-built SBOM and VEX artifacts.
    /// </summary>
    public CraReport Generate(
        ProjectReport healthReport,
        IReadOnlyDictionary<string, List<VulnerabilityInfo>> vulnerabilities,
        SbomDocument sbom, VexDocument vex,
        DateTime? startTime = null)
    {
        BuildParentLookup();

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
    /// Generate a full CRA report, building SBOM and VEX internally.
    /// Prefer the overload accepting pre-built artifacts when SBOM validation is needed.
    /// </summary>
    public CraReport Generate(
        ProjectReport healthReport,
        IReadOnlyDictionary<string, List<VulnerabilityInfo>> vulnerabilities,
        DateTime? startTime = null)
    {
        var (sbom, vex) = GenerateArtifacts(healthReport, vulnerabilities);
        return Generate(healthReport, vulnerabilities, sbom, vex, startTime);
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

        // Build lookup dictionaries for O(1) health data access (used by sub-methods)
        _healthLookup.Clear();
        if (_healthDataCache is not null)
            foreach (var h in _healthDataCache)
                _healthLookup.TryAdd(h.PackageId, h);
        if (_transitiveDataCache is not null)
            foreach (var h in _transitiveDataCache)
                _healthLookup.TryAdd(h.PackageId, h);

        // Cache filtered transitive list (excluding sub-dependencies used only for tree navigation)
        _actualTransitives = _transitiveDataCache?.Where(h => h.DependencyType != DependencyType.SubDependency).ToList() ?? [];

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
            sb.AppendLine("  <h4>\u26A0\uFE0F SBOM Completeness Warning</h4>");
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
        sb.AppendLine($"    <div class=\"metric-value {licenseStatusClass}\">{(licenseReport.ErrorCount == 0 ? "\u2713" : licenseReport.ErrorCount.ToString())}</div>");
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
        sb.AppendLine("    <button class=\"filter-btn sort-btn\" onclick=\"sortPackages('cra')\">CRA</button>");
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
            var healthData = _healthDataCache is not null ? _healthLookup.GetValueOrDefault(pkgName) : null;
            var ecosystemAttr = "nuget"; // Default for data attribute
            if (healthData != null)
            {
                score = healthData.Score;
                status = healthData.Status.ToString().ToLowerInvariant();
                ecosystemAttr = healthData.Ecosystem == PackageEcosystem.Npm ? "npm" : "nuget";
            }

            var hasKev = _kevPackageIds.Contains(pkgName);
            var kevClass = hasKev ? " has-kev" : "";
            var craScore = healthData?.CraScore ?? 0;
            var craTooltip = GetCraBadgeTooltip(healthData);
            sb.AppendLine($"  <div class=\"package-card{kevClass}\" id=\"pkg-{EscapeHtml(pkgName)}\" data-status=\"{status}\" data-name=\"{EscapeHtml(pkgName.ToLowerInvariant())}\" data-ecosystem=\"{ecosystemAttr}\" data-health=\"{score}\" data-cra=\"{craScore}\">");
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
            sb.AppendLine($"        <div class=\"package-score-item score-clickable\" onclick=\"showScorePopover(event, '{EscapeHtml(pkgName)}', 'health')\" title=\"Health Score - freshness, activity, and maintenance \u2014 click for breakdown\">");
            sb.AppendLine($"          <span class=\"score-label\">HEALTH</span>");
            sb.AppendLine($"          <span class=\"score-value {GetScoreClass(score)}\">{score}</span>");
            sb.AppendLine($"        </div>");
            sb.AppendLine($"        <div class=\"package-score-item score-clickable\" onclick=\"showScorePopover(event, '{EscapeHtml(pkgName)}', 'cra')\" title=\"{EscapeHtml(craTooltip)} \u2014 click for breakdown\">");
            sb.AppendLine($"          <span class=\"score-label\">CRA</span>");
            sb.AppendLine($"          <span class=\"score-value {GetCraScoreClass(craScore)}\">{craScore}</span>");
            sb.AppendLine($"        </div>");
            sb.AppendLine($"      </div>");
            sb.AppendLine($"      <span class=\"expand-icon\">+</span>");
            sb.AppendLine("    </div>");
            // Empty details container - content loaded lazily via JavaScript from packageData
            sb.AppendLine("    <div class=\"package-details\"></div>");
            sb.AppendLine("  </div>");
        }

        sb.AppendLine("</div>");

        // Transitive Dependencies Section (uses cached _actualTransitives, excluding sub-dependencies)
        if (_actualTransitives.Count > 0)
        {
            sb.AppendLine("<div class=\"transitive-section\">");
            sb.AppendLine("  <div class=\"transitive-header\" onclick=\"toggleTransitive()\">");
            sb.AppendLine($"    <h3>Transitive Dependencies ({_actualTransitives.Count})</h3>");
            sb.AppendLine("    <span class=\"transitive-toggle\" id=\"transitive-toggle\">Show</span>");
            sb.AppendLine("  </div>");
            sb.AppendLine("  <div id=\"transitive-list\" class=\"packages-list transitive-list\" style=\"display: none;\">");

            foreach (var healthData in _actualTransitives.OrderBy(h => h.PackageId, StringComparer.OrdinalIgnoreCase))
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
                var craScoreTrans = healthData.CraScore;
                var craTooltipTrans = GetCraBadgeTooltip(healthData);
                sb.AppendLine($"  <div class=\"package-card transitive{kevClassTrans}\" id=\"pkg-{EscapeHtml(pkgName)}\" data-status=\"{status}\" data-name=\"{EscapeHtml(pkgName.ToLowerInvariant())}\" data-ecosystem=\"{ecosystemAttr}\" data-health=\"{score}\" data-cra=\"{craScoreTrans}\">");
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
                    sb.AppendLine($"        <div class=\"package-score-item score-clickable\" onclick=\"showScorePopover(event, '{EscapeHtml(pkgName)}', 'health')\" title=\"Health Score - freshness &amp; activity \u2014 click for breakdown\">");
                    sb.AppendLine($"          <span class=\"score-label\">HEALTH</span>");
                    sb.AppendLine($"          <span class=\"score-value {GetScoreClass(score)}\">{score}</span>");
                    sb.AppendLine($"        </div>");
                }
                else
                {
                    sb.AppendLine($"        <div class=\"package-score-item\" title=\"Health Score not available - use --deep for full analysis\">");
                    sb.AppendLine($"          <span class=\"score-label\">HEALTH</span>");
                    sb.AppendLine($"          <span class=\"score-value na\">\u2014</span>");
                    sb.AppendLine($"        </div>");
                }
                sb.AppendLine($"        <div class=\"package-score-item score-clickable\" onclick=\"showScorePopover(event, '{EscapeHtml(pkgName)}', 'cra')\" title=\"{EscapeHtml(craTooltipTrans)} \u2014 click for breakdown\">");
                sb.AppendLine($"          <span class=\"score-label\">CRA</span>");
                sb.AppendLine($"          <span class=\"score-value {GetCraScoreClass(craScoreTrans)}\">{craScoreTrans}</span>");
                sb.AppendLine($"        </div>");
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
        sb.AppendLine($"  <span class=\"status-icon\">{(licenseReport.ErrorCount == 0 ? "\u2713" : "\u26A0")}</span>");
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
                "Who published the package. Needed to contact maintainers about vulnerabilities.",
                v.MissingSupplier, "supplier");
            AppendFieldCardWithBar(sb, "License", v.WithLicense, v.TotalPackages,
                "The license under which the package is distributed. Required for legal compliance.",
                v.MissingLicense, "license");
            AppendFieldCardWithBar(sb, "Package URL (PURL)", v.WithPurl, v.TotalPackages,
                "A universal identifier (like pkg:nuget/Newtonsoft.Json@13.0.1) that uniquely identifies the exact package version across all registries.",
                v.MissingPurl, "purl");
            AppendFieldCardWithBar(sb, "Checksum", v.WithChecksum, v.TotalPackages,
                "A cryptographic hash verifying the package hasn't been tampered with since download.",
                v.MissingChecksum, "checksum");
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

    private static void AppendFieldCardWithBar(StringBuilder sb, string label, int count, int total, string tooltip, List<string> missing, string fieldKey)
    {
        var pct = total > 0 ? (int)Math.Round(100.0 * count / total) : 0;
        var barClass = pct >= 90 ? "high" : pct >= 70 ? "medium" : "low";
        var hasMissing = missing.Count > 0;
        var cardClass = hasMissing ? "field-card field-card-clickable" : "field-card";
        sb.AppendLine($"  <div class=\"{cardClass}\" title=\"{EscapeHtml(tooltip)}{(hasMissing ? " \u2014 click to see missing packages" : "")}\">");
        sb.AppendLine($"    <div class=\"field-label\">{EscapeHtml(label)}{(hasMissing ? "<span class=\"field-toggle\">&#9660;</span>" : "")}</div>");
        sb.AppendLine($"    <div style=\"display:flex;justify-content:space-between;margin-bottom:4px;\"><span>{count}/{total} packages</span><span>{pct}%</span></div>");
        sb.AppendLine($"    <div class=\"progress-bar-container\"><div class=\"progress-bar-fill {barClass}\" style=\"width:{pct}%\"></div></div>");
        if (hasMissing)
        {
            sb.AppendLine($"    <div class=\"field-missing-list\" data-field=\"{fieldKey}\" style=\"display:none;\">");
            sb.AppendLine($"      <div class=\"field-missing-header\">Missing ({missing.Count})</div>");
            sb.AppendLine("    </div>");
        }
        sb.AppendLine("  </div>");
    }

    private void GenerateProvenanceSection(StringBuilder sb)
    {
        sb.AppendLine("<div class=\"section-header\">");
        sb.AppendLine("  <h2>Package Provenance</h2>");
        sb.AppendLine("</div>");

        sb.AppendLine("<div class=\"info-box\">");
        sb.AppendLine("  <div class=\"info-box-title\">What is this?</div>");
        sb.AppendLine("  <p><strong>Provenance</strong> means verifying that a package actually came from its claimed source. Package registries sign packages with cryptographic proofs &mdash; NuGet uses repository signatures, while npm uses ECDSA registry signatures and Sigstore attestations.</p>");
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
            sb.AppendLine("<p style=\"color:var(--text-secondary);margin-bottom:12px;\">These packages could not be verified through registry signatures. This can happen with older npm packages published before registry signing, or smaller NuGet packages. It doesn't mean they're malicious &mdash; but extra review may be warranted.</p>");
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
                var ecosystemIcon = tree.ProjectType == ProjectType.Npm ? "\U0001F4E6" : "\U0001F537";
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
        var healthData = _healthLookup.GetValueOrDefault(node.PackageId);

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

    private static string GetHtmlStyles() => _htmlStyles.Value;

    private string GetHtmlScripts(CraReport report, bool darkMode)
    {
        // Serialize without indentation to minimize HTML report size (saves 1-3MB for large projects)
        var sbomJson = JsonSerializer.Serialize(report.Sbom);

        // Generate centralized package data for lazy loading (reduces DOM size by 80%+)
        var packageDataJson = GeneratePackageDataJson();
        var sbomMissingJson = GenerateSbomMissingDataJson();

        return $@"
<script id=""sbom-json"" type=""application/json"">{sbomJson}</script>
<script>
var _hasSbomData = true;
const packageData = {packageDataJson};
const sbomMissingData = {sbomMissingJson};

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
    }} else if (sortBy === 'cra') {{
      result = parseInt(a.dataset.cra || 50) - parseInt(b.dataset.cra || 50);
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
  if (!_hasSbomData) return;
  var raw = document.getElementById('sbom-json').textContent;
  var data = JSON.stringify(JSON.parse(raw), null, 2);
  var filename = format === 'spdx' ? 'sbom.spdx.json' : 'sbom.cyclonedx.json';
  var type = 'application/json';

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

// CRA Score Breakdown Popover
var _activePopover = null;

function renderCraBreakdown(pkg) {{
  var wVuln=15, wKev=15, wPatch=8, wEpss=7, wMaint=11, wProv=4, wLic=2, wIdent=2;
  var total = wVuln+wKev+wPatch+wEpss+wMaint+wProv+wLic+wIdent;

  // 1. Vulnerabilities
  var vulnPts = pkg.vulnCount === 0 ? wVuln : pkg.vulnCount === 1 ? wVuln*0.3 : pkg.vulnCount === 2 ? wVuln*0.1 : 0;

  // 2. KEV
  var kevPts = pkg.hasKev ? 0 : wKev;

  // 3. Patch timeliness
  var patchPts = wPatch;
  if (pkg.patchPendingCount > 0) {{
    var d = pkg.oldestUnpatchedDays || 0;
    patchPts = d <= 7 ? wPatch*0.7 : d <= 30 ? wPatch*0.4 : d <= 90 ? wPatch*0.15 : 0;
  }}

  // 4. EPSS
  var epss = pkg.maxEpss || 0;
  var epssPts = epss === 0 ? wEpss : epss < 0.01 ? wEpss*0.8 : epss < 0.1 ? wEpss*0.4 : epss < 0.5 ? wEpss*0.15 : 0;

  // 5. Maintenance
  var actDays = pkg.daysSinceLastCommit != null ? pkg.daysSinceLastCommit : pkg.daysSinceLastRelease;
  var maintPts;
  if (actDays != null) {{
    maintPts = actDays <= 90 ? wMaint : actDays <= 180 ? wMaint*0.8 : actDays <= 365 ? wMaint*0.6 : actDays <= 730 ? wMaint*0.3 : 0;
  }} else {{
    maintPts = wMaint * 0.4;
  }}

  // 6. Provenance
  var provPts = 0;
  if (pkg.hasIntegrity) provPts += wProv * 0.6;
  if (pkg.authorCount > 0) provPts += wProv * 0.4;

  // 7. License
  var licPts = 0;
  if (pkg.license && pkg.license.trim()) {{
    licPts = wLic * 0.6;
    var upper = pkg.license.trim().toUpperCase();
    var spdx = ['MIT','APACHE-2.0','ISC','BSD-2-CLAUSE','BSD-3-CLAUSE','GPL-2.0','GPL-3.0','LGPL-2.1','LGPL-3.0','MPL-2.0','0BSD','UNLICENSE','CC0-1.0','WTFPL','ZLIB','ARTISTIC-2.0','CDDL-1.0','EPL-2.0','EUPL-1.2','AFL-3.0','BSL-1.0','POSTGRESQL','BLUEOAK-1.0.0','MIT-0'];
    for (var s = 0; s < spdx.length; s++) {{
      if (upper === spdx[s] || upper.indexOf(spdx[s]) >= 0) {{ licPts = wLic; break; }}
    }}
  }}

  // Provenance fix text based on what's actually missing
  var provFix = [];
  if (!pkg.hasIntegrity) provFix.push('No content checksum available');
  if (pkg.authorCount === 0) provFix.push('No supplier/author info');
  var provFixText = provFix.length > 0 ? provFix.join('; ') : 'Verify package source';

  var criteria = [
    {{ name: 'Vulnerabilities', pts: vulnPts, max: wVuln, ref: 'Art. 11', tip: 'Known security vulnerabilities in this package version. Update to patched versions to resolve.', fix: 'Update to patched versions' }},
    {{ name: 'Known Exploits (KEV)', pts: kevPts, max: wKev, ref: 'Art. 10(4)', tip: 'Whether this package has CVEs listed in CISA Known Exploited Vulnerabilities catalog. These are actively exploited in the wild.', fix: 'Replace or patch immediately' }},
    {{ name: 'Patch Timeliness', pts: patchPts, max: wPatch, ref: 'Art. 11(4)', tip: 'How quickly available security patches have been applied. Measures days since patch became available.', fix: 'Apply available patches' }},
    {{ name: 'Exploit Probability', pts: epssPts, max: wEpss, ref: 'Art. 10(4)', tip: 'EPSS score \u2014 the probability this package\u2019s vulnerabilities will be exploited within 30 days. Lower is better.', fix: 'Prioritize high-EPSS packages' }},
    {{ name: 'Maintenance', pts: maintPts, max: wMaint, ref: 'Art. 13(8)', tip: 'How recently the package was maintained, based on last commit or release. Stale packages may not receive security fixes.', fix: 'Consider alternatives if stale' }},
    {{ name: 'Provenance', pts: provPts, max: wProv, ref: 'Art. 13(5)', tip: 'Supply chain integrity \u2014 whether the package has a content checksum (integrity hash) and identified supplier/author.', fix: provFixText }},
    {{ name: 'License', pts: licPts, max: wLic, ref: 'Art. 10(9)', tip: 'Whether the package declares a recognized SPDX license. Needed for legal compliance and CRA documentation.', fix: 'Add license info' }}
  ];

  var html = '<div class=""score-popover-title"">CRA Readiness Breakdown &mdash; ' + pkg.craScore + '/100</div>';
  for (var i = 0; i < criteria.length; i++) {{
    var c = criteria[i];
    var pct = c.max > 0 ? Math.round(c.pts / c.max * 100) : 0;
    var full = pct >= 95;
    var icon = full ? '<span style=""color:#28a745"">&#10003;</span>' : '<span style=""color:#ffc107"">&#9888;</span>';
    var ptsStr = c.pts % 1 === 0 ? c.pts.toString() : c.pts.toFixed(1);
    html += '<div class=""score-popover-criterion"" title=""' + (c.tip || '') + '"">';
    html += '<div class=""score-popover-row"">';
    html += '<span class=""score-popover-row-icon"">' + icon + '</span>';
    html += '<span class=""score-popover-row-name"">' + c.name + '</span>';
    html += '<span class=""score-popover-row-pts"">' + ptsStr + '/' + c.max + '</span>';
    html += '<span class=""score-popover-row-ref"">' + c.ref + '</span>';
    html += '</div>';
    if (!full) {{
      html += '<div class=""score-popover-row-fix"">' + c.fix + '</div>';
    }}
    html += '</div>';
  }}
  return html;
}}

function renderHealthBreakdown(pkg) {{
  var wFresh=25, wCadence=15, wTrend=20, wActivity=25, wVuln=15;

  // 1. Freshness (daysSinceLastRelease)
  var freshRaw;
  if (pkg.daysSinceLastRelease == null) {{ freshRaw = 60; }}
  else if (pkg.daysSinceLastRelease <= 30) {{ freshRaw = 100; }}
  else if (pkg.daysSinceLastRelease <= 90) {{ freshRaw = 90; }}
  else if (pkg.daysSinceLastRelease <= 180) {{ freshRaw = 80; }}
  else if (pkg.daysSinceLastRelease <= 365) {{ freshRaw = 70; }}
  else if (pkg.daysSinceLastRelease <= 730) {{ freshRaw = 50; }}
  else if (pkg.daysSinceLastRelease <= 1095) {{ freshRaw = 30; }}
  else {{ freshRaw = 10; }}
  var freshPts = freshRaw / 100 * wFresh;

  // 2. Release Cadence (releasesPerYear)
  var cadRaw;
  var rpy = pkg.releasesPerYear || 0;
  if (rpy >= 2 && rpy <= 12) {{ cadRaw = 100; }}
  else if (rpy >= 1 && rpy < 2) {{ cadRaw = 70; }}
  else if (rpy > 12 && rpy <= 24) {{ cadRaw = 80; }}
  else if (rpy > 24) {{ cadRaw = 60; }}
  else {{ cadRaw = 40; }}
  var cadPts = cadRaw / 100 * wCadence;

  // 3. Download Trend
  var trend = pkg.downloadTrend || 0;
  var trendRaw = (trend + 1.0) * 50.0;
  var trendPts = Math.min(Math.max(trendRaw, 0), 100) / 100 * wTrend;

  // 4. Repository Activity (daysSinceLastCommit, stars, openIssues)
  var actRaw;
  if (pkg.daysSinceLastCommit == null) {{ actRaw = 50; }}
  else {{
    var dsc = pkg.daysSinceLastCommit;
    if (dsc <= 7) {{ actRaw = 100; }}
    else if (dsc <= 30) {{ actRaw = 90; }}
    else if (dsc <= 90) {{ actRaw = 80; }}
    else if (dsc <= 180) {{ actRaw = 60; }}
    else if (dsc <= 365) {{ actRaw = 40; }}
    else {{ actRaw = 20; }}
    var starBonus = (pkg.stars || 0) >= 10000 ? 10 : (pkg.stars || 0) >= 1000 ? 5 : (pkg.stars || 0) >= 100 ? 2 : 0;
    var issuePenalty = 0;
    if ((pkg.stars || 0) > 0 && (pkg.openIssues || 0) > 0) {{
      var ratio = pkg.openIssues / pkg.stars;
      issuePenalty = ratio > 0.5 ? 10 : ratio > 0.2 ? 5 : 0;
    }}
    actRaw = Math.min(Math.max(actRaw + starBonus - issuePenalty, 0), 100);
  }}
  var actPts = actRaw / 100 * wActivity;

  // 5. Vulnerabilities
  var vulnRaw = pkg.vulnCount === 0 ? 100 : pkg.vulnCount === 1 ? 50 : pkg.vulnCount === 2 ? 25 : 0;
  var vulnPts = vulnRaw / 100 * wVuln;

  var criteria = [
    {{ name: 'Freshness', pts: freshPts, max: wFresh, weight: '25%', tip: 'How recently the package was released. Packages not updated in years may lack security fixes.', fix: 'Update to latest version' }},
    {{ name: 'Release Cadence', pts: cadPts, max: wCadence, weight: '15%', tip: 'How often new versions are published. Ideal: 2\u201312 releases/year. Too few suggests abandonment, too many may indicate instability.', fix: 'Consider more active alternatives' }},
    {{ name: 'Download Trend', pts: trendPts, max: wTrend, weight: '20%', tip: 'Whether download volume is growing, stable, or declining. Declining adoption may signal the community is moving away.', fix: 'Check for declining adoption' }},
    {{ name: 'Repository Activity', pts: actPts, max: wActivity, weight: '25%', tip: 'Recent commits, star count, and issue-to-star ratio. Active repos are more likely to receive timely security patches.', fix: 'Check repository status' }},
    {{ name: 'Vulnerabilities', pts: vulnPts, max: wVuln, weight: '15%', tip: 'Known security vulnerabilities (CVEs) in this package version. Zero is ideal.', fix: 'Update to patched versions' }}
  ];

  var html = '<div class=""score-popover-title"">Health Score Breakdown &mdash; ' + pkg.score + '/100</div>';
  for (var i = 0; i < criteria.length; i++) {{
    var c = criteria[i];
    var pct = c.max > 0 ? Math.round(c.pts / c.max * 100) : 0;
    var full = pct >= 95;
    var icon = full ? '<span style=""color:#28a745"">&#10003;</span>' : '<span style=""color:#ffc107"">&#9888;</span>';
    var ptsStr = c.pts % 1 === 0 ? c.pts.toString() : c.pts.toFixed(1);
    html += '<div class=""score-popover-criterion"" title=""' + (c.tip || '') + '"">';
    html += '<div class=""score-popover-row"">';
    html += '<span class=""score-popover-row-icon"">' + icon + '</span>';
    html += '<span class=""score-popover-row-name"">' + c.name + '</span>';
    html += '<span class=""score-popover-row-pts"">' + ptsStr + '/' + c.max + '</span>';
    html += '<span class=""score-popover-row-ref"">' + c.weight + '</span>';
    html += '</div>';
    if (!full) {{
      html += '<div class=""score-popover-row-fix"">' + c.fix + '</div>';
    }}
    html += '</div>';
  }}
  return html;
}}

function showScorePopover(event, pkgId, type) {{
  event.stopPropagation();
  event.preventDefault();

  // Close existing popover
  if (_activePopover) {{
    _activePopover.remove();
    var wasSame = _activePopover.dataset.pkgId === pkgId && _activePopover.dataset.popType === type;
    _activePopover = null;
    if (wasSame) return;
  }}

  var pkg = packageData[pkgId] || packageData[pkgId.toLowerCase()];
  if (!pkg) return;

  var el = event.currentTarget;
  var rect = el.getBoundingClientRect();
  var popover = document.createElement('div');
  popover.className = 'score-popover';
  popover.dataset.pkgId = pkgId;
  popover.dataset.popType = type;
  popover.innerHTML = type === 'health' ? renderHealthBreakdown(pkg) : renderCraBreakdown(pkg);
  popover.addEventListener('click', function(e) {{ e.stopPropagation(); }});
  document.body.appendChild(popover);

  // Position below the badge, right-aligned
  var popW = 360;
  var left = rect.right - popW;
  if (left < 8) left = 8;
  var top = rect.bottom + 6;
  // If it would go off the bottom, show above instead
  if (top + popover.offsetHeight > window.innerHeight - 8) {{
    top = rect.top - popover.offsetHeight - 6;
  }}
  popover.style.left = left + 'px';
  popover.style.top = top + 'px';

  _activePopover = popover;
}}

document.addEventListener('click', function() {{
  if (_activePopover) {{
    _activePopover.remove();
    _activePopover = null;
  }}
}});

// SBOM field card click-to-expand (lazy-populated from sbomMissingData)
document.querySelectorAll('.field-card-clickable').forEach(function(card) {{
  card.addEventListener('click', function() {{
    var list = card.querySelector('.field-missing-list');
    if (!list) return;
    // Lazy populate on first click
    if (!list.dataset.loaded && sbomMissingData) {{
      var field = list.dataset.field;
      var items = sbomMissingData[field] || [];
      items.forEach(function(pkg) {{
        var div = document.createElement('div');
        div.className = 'field-missing-item';
        div.textContent = pkg;
        list.appendChild(div);
      }});
      list.dataset.loaded = 'true';
    }}
    var isOpen = list.style.display !== 'none';
    list.style.display = isOpen ? 'none' : 'block';
    card.classList.toggle('expanded', !isOpen);
  }});
}});
</script>";
    }

    private List<PackageHealth>? _healthDataCache;
    private List<PackageHealth>? _transitiveDataCache;
    private Dictionary<string, PackageHealth> _healthLookup = new(StringComparer.OrdinalIgnoreCase);
    private List<PackageHealth> _actualTransitives = [];
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

    private string GenerateSbomMissingDataJson()
    {
        if (_sbomValidation is null)
            return "null";

        var data = new Dictionary<string, List<string>>
        {
            ["supplier"] = _sbomValidation.MissingSupplier,
            ["license"] = _sbomValidation.MissingLicense,
            ["purl"] = _sbomValidation.MissingPurl,
            ["checksum"] = _sbomValidation.MissingChecksum
        };

        return JsonSerializer.Serialize(data);
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
            downloadTrend = pkg.Metrics.DownloadTrend,
            openIssues = pkg.Metrics.OpenIssues ?? 0,
            repoUrl = pkg.RepositoryUrl,
            registryUrl,
            recommendations = pkg.Recommendations,
            vulnCount = pkg.Vulnerabilities.Count,
            dependencies = pkg.Dependencies.Select(d => new { id = d.PackageId, range = d.VersionRange }).ToList(),
            parents = parents ?? [],
            latestVersion = pkg.LatestVersion,
            peerDependencies = pkg.PeerDependencies.Select(p => new { id = p.Key, range = p.Value }).ToList(),
            craScore = pkg.CraScore,
            craStatus = pkg.CraStatus.ToString(),
            hasKev = pkg.HasKevVulnerability,
            maxEpss = pkg.MaxEpssProbability,
            patchPendingCount = pkg.PatchAvailableNotAppliedCount,
            oldestUnpatchedDays = pkg.OldestUnpatchedVulnDays,
            hasIntegrity = !string.IsNullOrEmpty(pkg.ContentIntegrity),
            authorCount = pkg.Authors.Count
        };
    }

    private static string GetScoreClass(int score) => score switch
    {
        >= 80 => "healthy",
        >= 60 => "watch",
        >= 40 => "warning",
        _ => "critical"
    };

    private static string GetCraScoreClass(int score) => score switch
    {
        >= 90 => "healthy",
        >= 70 => "watch",
        >= 50 => "warning",
        _ => "critical"
    };

    private static string GetCraBadgeTooltip(PackageHealth? pkg)
    {
        if (pkg is null) return "CRA Readiness Score";
        var status = pkg.CraStatus switch
        {
            CraComplianceStatus.Compliant => "Compliant",
            CraComplianceStatus.Review => "Review needed",
            CraComplianceStatus.ActionRequired => "Action required",
            CraComplianceStatus.NonCompliant => "Non-compliant",
            _ => "Unknown"
        };
        return $"CRA Readiness: {pkg.CraScore}/100 - {status}";
    }

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
            return $"<span class=\"unresolved-version\" title=\"MSBuild variable not resolved: {EscapeHtml(version)}\">Not resolved \u2139</span>";
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
                return $"<span class=\"unresolved-version\" title=\"Full PURL: {EscapeHtml(purl)}\">pkg:nuget/{EscapeHtml(match.Groups[1].Value)}@? \u2139</span>";
            }
            return $"<span class=\"unresolved-version\" title=\"{EscapeHtml(purl)}\">Not resolved \u2139</span>";
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
            return $"<span class=\"unresolved-version\" title=\"{EscapeHtml(tooltip)}\">Version not resolved <span class=\"version-hint\">\u2139</span></span>";
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

        var sb = new StringBuilder(input.Length + 16);
        foreach (var c in input)
        {
            switch (c)
            {
                case '&': sb.Append("&amp;"); break;
                case '<': sb.Append("&lt;"); break;
                case '>': sb.Append("&gt;"); break;
                case '"': sb.Append("&quot;"); break;
                case '\'': sb.Append("&#39;"); break;
                default: sb.Append(c); break;
            }
        }
        return sb.ToString();
    }

    private static string EscapeJs(string input)
    {
        if (string.IsNullOrEmpty(input)) return input;

        var sb = new StringBuilder(input.Length + 16);
        foreach (var c in input)
        {
            switch (c)
            {
                case '\\': sb.Append("\\\\"); break;
                case '\'': sb.Append("\\'"); break;
                case '"': sb.Append("\\\""); break;
                case '\n': sb.Append("\\n"); break;
                case '\r': sb.Append("\\r"); break;
                default: sb.Append(c); break;
            }
        }
        return sb.ToString();
    }

    private static string MinifyCss(string css)
    {
        var sb = new StringBuilder(css.Length);
        var inComment = false;
        var i = 0;

        while (i < css.Length)
        {
            // Strip CSS comments
            if (!inComment && i + 1 < css.Length && css[i] == '/' && css[i + 1] == '*')
            {
                inComment = true;
                i += 2;
                continue;
            }
            if (inComment)
            {
                if (i + 1 < css.Length && css[i] == '*' && css[i + 1] == '/')
                {
                    inComment = false;
                    i += 2;
                }
                else
                {
                    i++;
                }
                continue;
            }

            var c = css[i];

            // Collapse newlines and carriage returns
            if (c == '\n' || c == '\r')
            {
                i++;
                continue;
            }

            // Collapse runs of whitespace to a single space
            if (c == ' ' || c == '\t')
            {
                // Skip whitespace after structural characters
                if (sb.Length > 0)
                {
                    var prev = sb[sb.Length - 1];
                    if (prev == '{' || prev == '}' || prev == ';' || prev == ':' || prev == ',')
                    {
                        i++;
                        continue;
                    }
                }

                // Collapse to single space, skip trailing whitespace
                sb.Append(' ');
                i++;
                while (i < css.Length && (css[i] == ' ' || css[i] == '\t' || css[i] == '\n' || css[i] == '\r'))
                    i++;
                continue;
            }

            // Skip whitespace before structural characters
            if ((c == '{' || c == '}' || c == ';' || c == ':' || c == ',') && sb.Length > 0 && sb[sb.Length - 1] == ' ')
            {
                sb[sb.Length - 1] = c;
                i++;
                continue;
            }

            sb.Append(c);
            i++;
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
