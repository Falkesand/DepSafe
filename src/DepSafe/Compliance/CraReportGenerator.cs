using System.Collections.Frozen;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using DepSafe.DataSources;
using DepSafe.Models;
using DepSafe.Scoring;

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

    // Source-generated regex for parsing PURLs (used repeatedly in FormatPurlForSbom)
    [GeneratedRegex(@"pkg:nuget/([^@]+)")]
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
        int activeVulnCount = 0, fixedVulnCount = 0;
        foreach (var s in vex.Statements)
        {
            if (s.Status == VexStatus.Affected) activeVulnCount++;
            else if (s.Status == VexStatus.Fixed) fixedVulnCount++;
        }
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

        // Art. 14 - Incident Reporting Obligations
        {
            var reportableCount = _reportingObligations.Count;
            var art14Status = reportableCount == 0 ? CraComplianceStatus.Compliant : CraComplianceStatus.NonCompliant;
            var art14KevCount = _reportingObligations.Count(r => r.IsKevVulnerability);
            var highEpssCount = _reportingObligations.Count(r => r.Trigger is ReportingTrigger.HighEpss or ReportingTrigger.Both);

            var evidence = reportableCount == 0
                ? "No vulnerabilities requiring CSIRT notification detected"
                : $"{reportableCount} reportable vulnerability(ies) found: {art14KevCount} CISA KEV, {highEpssCount} high EPSS (\u2265 0.5). " +
                  string.Join("; ", _reportingObligations.Take(3)
                      .Select(r => $"{r.PackageId} ({string.Join(", ", r.CveIds.Take(2))})"));

            complianceItems.Add(new CraComplianceItem
            {
                Requirement = "CRA Art. 14 - Incident Reporting",
                Description = "Report actively exploited vulnerabilities to CSIRT within 24 hours (Art. 14(2))",
                Status = art14Status,
                Evidence = evidence,
                Recommendation = reportableCount > 0
                    ? "Notify your designated CSIRT immediately. Early warning within 24h, full notification within 72h, final report within 14 days."
                    : null
            });
        }

        // CRA Art. 13(5) - Maintainer Trust (supply chain due diligence on maintainer reliability)
        {
            var packages = healthReport.Packages;
            var packagesWithTrust = packages
                .Where(p => p.MaintainerTrust is not null)
                .ToList();

            if (packagesWithTrust.Count == 0)
            {
                complianceItems.Add(new CraComplianceItem
                {
                    Requirement = "CRA Art. 13(5) - Maintainer Trust",
                    Description = "Exercise due diligence on third-party component maintainer reliability: contributor diversity, release discipline, community health",
                    Status = CraComplianceStatus.Review,
                    Evidence = "No maintainer trust data available (GitHub data not fetched)",
                    Recommendation = "Run without --skip-github to enable maintainer trust scoring"
                });
            }
            else
            {
                var criticalTrustPackages = packagesWithTrust
                    .Where(p => p.MaintainerTrust!.Score < 40)
                    .Select(p => p.PackageId)
                    .ToList();

                var lowTrustPackages = packagesWithTrust
                    .Where(p => p.MaintainerTrust!.Score >= 40 && p.MaintainerTrust.Score < 60)
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
        }

        // Calculate CRA Readiness Score
        var craReadinessScore = CalculateCraReadinessScore(complianceItems);

        // Collect dependency issues from all trees
        var versionConflictCount = _dependencyTrees.Sum(t => t.VersionConflictCount);
        var allDependencyIssues = _dependencyTrees.SelectMany(t => t.Issues).ToList();

        // Compute structured CI/CD policy fields from existing data
        var maxUnpatchedDays = _remediationData.Count > 0 ? (int?)_remediationData.Max(r => r.DaysSince) : null;
        var sbomCompleteness = _sbomValidation?.CompletenessPercent;
        var maxDepth = _dependencyTrees.Count > 0 ? (int?)_dependencyTrees.Max(t => t.MaxDepth) : null;
        var hasUnmaintained = _unmaintainedPackageNames.Count > 0;
        var minHealthPkg = healthReport.Packages.Count > 0 ? healthReport.Packages.MinBy(p => p.Score) : null;

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
            CraReadinessScore = craReadinessScore,
            MaxUnpatchedVulnerabilityDays = maxUnpatchedDays,
            SbomCompletenessPercentage = sbomCompleteness,
            MaxDependencyDepth = maxDepth,
            HasUnmaintainedPackages = hasUnmaintained,
            ReportableVulnerabilityCount = _reportingObligations.Count,
            DeprecatedPackages = _deprecatedPackages.ToList(),
            MinPackageHealthScore = minHealthPkg?.Score,
            MinHealthScorePackage = minHealthPkg?.PackageId,
            CriticalVulnerabilityCount = vulnerabilities.Values
                .SelectMany(v => v)
                .Count(v => v.Severity.Equals("CRITICAL", StringComparison.OrdinalIgnoreCase)),
            MaxInactiveMonths = _maxInactiveMonths,
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
    private static readonly FrozenDictionary<string, int> s_craWeights = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase)
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
        ["CRA Art. 14 - Incident Reporting"] = 12,
        ["CRA Art. 13(5) - Maintainer Trust"] = 8,
    }.ToFrozenDictionary(StringComparer.OrdinalIgnoreCase);

    public static int CalculateCraReadinessScore(List<CraComplianceItem> items)
    {
        double totalWeight = 0;
        double earnedWeight = 0;

        foreach (var item in items)
        {
            var weight = s_craWeights.GetValueOrDefault(item.Requirement, 2); // default weight for unknown items
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

    internal static CraComplianceStatus DetermineOverallStatus(List<CraComplianceItem> items)
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
        var sb = new StringBuilder(262144); // 256KB initial capacity to reduce reallocations
        var packages = report.Sbom.Packages.Skip(1).ToList(); // Skip root package
        var licenseFileName = licenseFilePath is not null ? Path.GetFileName(licenseFilePath) : null;
        var version = typeof(CraReportGenerator).Assembly.GetName().Version;
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

        // Cache filtered transitive list and sub-dependencies separately
        _actualTransitives = [];
        _subDependencies = [];
        if (_transitiveDataCache is not null)
        {
            foreach (var h in _transitiveDataCache)
            {
                if (h.DependencyType == DependencyType.Transitive)
                    _actualTransitives.Add(h);
                else if (h.DependencyType == DependencyType.SubDependency)
                    _subDependencies.Add(h);
            }
        }

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
            sb.AppendLine("        <li class=\"external-link-item\"><a href=\"" + EscapeHtml(licenseFileName) + "\" target=\"_blank\" class=\"external\">");
            sb.AppendLine("          <svg class=\"nav-icon\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\"><path d=\"M18 13v6a2 2 0 01-2 2H5a2 2 0 01-2-2V8a2 2 0 012-2h6\"/><polyline points=\"15 3 21 3 21 9\"/><line x1=\"10\" y1=\"14\" x2=\"21\" y2=\"3\"/></svg>");
            sb.AppendLine("          License File</a></li>");
        }
        sb.AppendLine("      </ul>");
        sb.AppendLine("    </div>");
        // CRA Details nav group
        sb.AppendLine("    <div class=\"nav-section\">");
        sb.AppendLine("      <div class=\"nav-label\">CRA Details</div>");
        sb.AppendLine("      <ul class=\"nav-links\">");
        {
            sb.AppendLine("        <li><a href=\"#\" onclick=\"showSection('reporting-obligations')\" data-section=\"reporting-obligations\">");
            sb.AppendLine("          <svg class=\"nav-icon\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\"><path d=\"M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z\"/><line x1=\"12\" y1=\"9\" x2=\"12\" y2=\"13\"/><line x1=\"12\" y1=\"17\" x2=\"12.01\" y2=\"17\"/></svg>");
            var art14Badge = _reportingObligations.Count > 0
                ? $"<span class=\"nav-badge critical\">{_reportingObligations.Count}</span>"
                : "";
            sb.AppendLine($"          Art. 14 Reporting{art14Badge}</a></li>");
        }
        {
            sb.AppendLine("        <li><a href=\"#\" onclick=\"showSection('remediation-roadmap')\" data-section=\"remediation-roadmap\">");
            sb.AppendLine("          <svg class=\"nav-icon\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\"><polyline points=\"22 12 18 12 15 21 9 3 6 12 2 12\"/></svg>");
            var roadmapBadge = _remediationRoadmap.Count > 0
                ? $"<span class=\"nav-badge\">{_remediationRoadmap.Count}</span>"
                : "";
            sb.AppendLine($"          Remediation Roadmap{roadmapBadge}</a></li>");
        }
        {
            // Release Readiness nav — always visible
            sb.AppendLine("        <li><a href=\"#\" onclick=\"showSection('release-readiness')\" data-section=\"release-readiness\">");
            sb.AppendLine("          <svg class=\"nav-icon\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\"><path d=\"M22 11.08V12a10 10 0 11-5.93-9.14\"/><polyline points=\"22 4 12 14.01 9 11.01\"/></svg>");
            var readinessBadge = _releaseReadiness is not null
                ? _releaseReadiness.IsReady
                    ? "<span class=\"nav-badge success\">GO</span>"
                    : $"<span class=\"nav-badge critical\">{_releaseReadiness.BlockingItems.Count}</span>"
                : "";
            sb.AppendLine($"          Release Readiness{readinessBadge}</a></li>");
        }
        {
            // Security Budget nav — always visible
            sb.AppendLine("        <li><a href=\"#\" onclick=\"showSection('security-budget')\" data-section=\"security-budget\">");
            sb.AppendLine("          <svg class=\"nav-icon\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\"><line x1=\"12\" y1=\"1\" x2=\"12\" y2=\"23\"/><path d=\"M17 5H9.5a3.5 3.5 0 000 7h5a3.5 3.5 0 010 7H6\"/></svg>");
            var budgetBadge = _securityBudget is not null
                ? $"<span class=\"nav-badge\">{_securityBudget.Items.Count(i => i.Tier == RemediationTier.HighROI)}</span>"
                : "";
            sb.AppendLine($"          Security Budget{budgetBadge}</a></li>");
        }
        if (HasPolicyData())
        {
            // Policy Violations nav — only if policy configured
            sb.AppendLine("        <li><a href=\"#\" onclick=\"showSection('policy-violations')\" data-section=\"policy-violations\">");
            sb.AppendLine("          <svg class=\"nav-icon\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\"><rect x=\"3\" y=\"3\" width=\"18\" height=\"18\" rx=\"2\" ry=\"2\"/><line x1=\"9\" y1=\"9\" x2=\"15\" y2=\"15\"/><line x1=\"15\" y1=\"9\" x2=\"9\" y2=\"15\"/></svg>");
            var policyCount = GetPolicyViolationCount();
            var policyBadge = policyCount > 0
                ? $"<span class=\"nav-badge critical\">{policyCount}</span>"
                : "";
            sb.AppendLine($"          Policy Violations{policyBadge}</a></li>");
        }
        if (_auditSimulation is not null)
        {
            sb.AppendLine("        <li><a href=\"#\" onclick=\"showSection('audit-simulation')\" data-section=\"audit-simulation\">");
            sb.AppendLine("          <svg class=\"nav-icon\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\"><path d=\"M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2\"/><rect x=\"9\" y=\"3\" width=\"6\" height=\"4\" rx=\"1\"/><path d=\"M9 14l2 2 4-4\"/></svg>");
            var auditBadgeClass = _auditSimulation.CriticalCount > 0 ? "critical" : _auditSimulation.HighCount > 0 ? "warning" : "";
            var auditBadge = _auditSimulation.Findings.Count > 0
                ? $"<span class=\"nav-badge {auditBadgeClass}\">{_auditSimulation.Findings.Count}</span>"
                : "<span class=\"nav-badge success\">0</span>";
            sb.AppendLine($"          Audit Simulation{auditBadge}</a></li>");
        }
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
        if (_trendSummary is not null && _trendSummary.Metrics.Count > 0)
        {
            sb.AppendLine("        <li><a href=\"#\" onclick=\"showSection('security-debt-trend')\" data-section=\"security-debt-trend\">");
            sb.AppendLine("          <svg class=\"nav-icon\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\"><polyline points=\"22 12 18 12 15 21 9 3 6 12 2 12\"/></svg>");
            var (trendIcon, trendColor) = _trendSummary.OverallDirection switch
            {
                TrendDirection.Improving => ("\u25b2", "var(--success)"),
                TrendDirection.Degrading => ("\u25bc", "var(--danger)"),
                _ => ("\u25cf", "var(--accent)")
            };
            sb.AppendLine($"          Security Debt Trend<span class=\"nav-badge\" style=\"background:{trendColor}\">{trendIcon}</span></a></li>");
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

        // CRA Detail Sections (v1.2+)
        sb.AppendLine("<section id=\"reporting-obligations\" class=\"section\">");
        GenerateReportingObligationsSection(sb);
        sb.AppendLine("</section>");

        sb.AppendLine("<section id=\"remediation-roadmap\" class=\"section\">");
        GenerateRemediationRoadmapSection(sb);
        sb.AppendLine("</section>");

        // Phase 1 Actionable Findings sections
        sb.AppendLine("<section id=\"release-readiness\" class=\"section\">");
        GenerateReleaseReadinessSection(sb);
        sb.AppendLine("</section>");

        sb.AppendLine("<section id=\"security-budget\" class=\"section\">");
        GenerateSecurityBudgetSection(sb);
        sb.AppendLine("</section>");

        if (HasPolicyData())
        {
            sb.AppendLine("<section id=\"policy-violations\" class=\"section\">");
            GeneratePolicyViolationsSection(sb);
            sb.AppendLine("</section>");
        }

        if (_auditSimulation is not null)
        {
            sb.AppendLine("<section id=\"audit-simulation\" class=\"section\">");
            GenerateAuditSimulationSection(sb);
            sb.AppendLine("</section>");
        }

        if (_maintainerTrustPackages is not null)
        {
            sb.AppendLine("<section id=\"maintainer-trust\" class=\"section\">");
            GenerateMaintainerTrustSection(sb);
            sb.AppendLine("</section>");
        }

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

        if (_trendSummary is not null && _trendSummary.Metrics.Count > 0)
        {
            sb.AppendLine("<section id=\"security-debt-trend\" class=\"section\">");
            GenerateTrendSection(sb);
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

    // Pre-computed indent strings to avoid per-node allocations in tree rendering
    private static readonly string[] IndentStrings = Enumerable.Range(0, 32)
        .Select(i => new string(' ', i * 2)).ToArray();

    private static string StatusToLower(HealthStatus status) => status switch
    {
        HealthStatus.Healthy => "healthy",
        HealthStatus.Watch => "watch",
        HealthStatus.Warning => "warning",
        HealthStatus.Critical => "critical",
        _ => "unknown"
    };

    private List<PackageHealth>? _healthDataCache;
    private List<PackageHealth>? _transitiveDataCache;
    private Dictionary<string, PackageHealth> _healthLookup = new(StringComparer.OrdinalIgnoreCase);
    private List<PackageHealth> _actualTransitives = [];
    private List<PackageHealth> _subDependencies = [];
    private List<DependencyTree> _dependencyTrees = [];
    private Dictionary<string, HashSet<string>> _parentLookup = new(StringComparer.OrdinalIgnoreCase);
    private bool _hasIncompleteTransitive;
    private bool _hasUnresolvedVersions;

    // Cached license data (computed once on first access)
    private List<(string PackageId, string? License)>? _packageLicensesCache;
    private LicenseReport? _licenseReportCache;

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
    private int? _maxInactiveMonths;

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

    // Phase 5: Art. 14 Reporting Obligations and Remediation Roadmap (v1.5)
    private List<ReportingObligation> _reportingObligations = [];
    private List<Scoring.RemediationRoadmapItem> _remediationRoadmap = [];

    // Phase 1 Actionable Findings — dashboard sections
    private SecurityBudgetResult? _securityBudget;
    private ReleaseReadinessResult? _releaseReadiness;
    private LicensePolicyResult? _licensePolicyResult;
    private CraConfig? _policyConfig;

    // Audit simulation (v2.4)
    private AuditSimulationResult? _auditSimulation;

    // Maintainer trust (v2.5)
    private IReadOnlyList<PackageHealth>? _maintainerTrustPackages;

    // Security debt trend (v2.6)
    private TrendSummary? _trendSummary;
    private List<TrendSnapshot>? _trendSnapshots;

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
    /// Set the maximum number of months any dependency has been inactive.
    /// </summary>
    public void SetMaxInactiveMonths(int? months)
    {
        _maxInactiveMonths = months;
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
    /// Set CRA Art. 14 reporting obligation analysis results.
    /// </summary>
    public void SetReportingObligations(List<ReportingObligation> obligations)
    {
        _reportingObligations = obligations;
    }

    /// <summary>
    /// Set the prioritized remediation roadmap for the report.
    /// </summary>
    public void SetRemediationRoadmap(List<RemediationRoadmapItem> roadmap)
    {
        _remediationRoadmap = roadmap;
    }

    /// <summary>
    /// Set the security budget optimization result for the dashboard.
    /// </summary>
    public void SetSecurityBudget(SecurityBudgetResult budget)
    {
        _securityBudget = budget;
    }

    /// <summary>
    /// Set the release readiness evaluation result for the dashboard.
    /// </summary>
    public void SetReleaseReadiness(ReleaseReadinessResult result)
    {
        _releaseReadiness = result;
    }

    /// <summary>
    /// Set the license policy evaluation result and config for the dashboard.
    /// </summary>
    public void SetPolicyViolations(LicensePolicyResult? licenseResult, CraConfig? config)
    {
        _licensePolicyResult = licenseResult;
        _policyConfig = config;
    }

    /// <summary>
    /// Set audit simulation findings for the dashboard (v2.4).
    /// </summary>
    public void SetAuditFindings(AuditSimulationResult result)
    {
        _auditSimulation = result;
    }

    public void SetMaintainerTrustData(IReadOnlyList<PackageHealth> packages)
    {
        _maintainerTrustPackages = packages;
    }

    /// <summary>
    /// Set security debt trend data for the HTML report section.
    /// </summary>
    public void SetTrendData(TrendSummary summary, List<TrendSnapshot>? snapshots = null)
    {
        _trendSummary = summary;
        _trendSnapshots = snapshots;
    }

    public SbomValidationResult? GetSbomValidation() => _sbomValidation;
    public List<ProvenanceResult> GetProvenanceResults() => _provenanceResults;
    public AttackSurfaceResult? GetAttackSurface() => _attackSurface;
    public AuditSimulationResult? GetAuditSimulation() => _auditSimulation;

    private bool HasPolicyData()
    {
        if (_policyConfig is null) return false;
        return _policyConfig.AllowedLicenses.Count > 0
            || _policyConfig.BlockedLicenses.Count > 0
            || _policyConfig.FailOnDeprecatedPackages
            || _policyConfig.MinHealthScore.HasValue;
    }

    private int GetPolicyViolationCount()
    {
        var count = _licensePolicyResult?.Violations.Count ?? 0;
        if (_policyConfig is not null)
        {
            if (_policyConfig.FailOnDeprecatedPackages)
                count += _deprecatedPackages.Count;
            if (_policyConfig.MinHealthScore.HasValue && _healthDataCache is not null)
            {
                count += _healthDataCache.Count(p => p.Score < _policyConfig.MinHealthScore.Value);
            }
        }
        return count;
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
                parents = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                _parentLookup[node.PackageId] = parents;
            }
            parents.Add(parentId);
        }

        // Process children
        foreach (var child in node.Children)
        {
            BuildParentLookupRecursive(child, node.PackageId);
        }
    }

    /// <summary>
    /// Generate JSON report.
    /// </summary>
    public string GenerateJson(CraReport report)
    {
        return JsonSerializer.Serialize(report, JsonDefaults.CamelCase);
    }
}
