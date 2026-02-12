using DepSafe.Models;
using DepSafe.Scoring;

namespace DepSafe.Compliance;

/// <summary>
/// Simulates a CRA compliance audit by evaluating 13 checks grounded in
/// specific EU Cyber Resilience Act articles and annexes.
/// </summary>
public static class AuditSimulator
{
    public static AuditSimulationResult Analyze(
        IReadOnlyList<PackageHealth> allPackages,
        IReadOnlyDictionary<string, List<VulnerabilityInfo>> allVulnerabilities,
        CraReport craReport,
        SbomValidationResult? sbomValidation,
        List<ProvenanceResult>? provenanceResults,
        AttackSurfaceResult? attackSurface,
        bool hasSecurityPolicy,
        int packagesWithSecurityPolicy,
        int packagesWithRepo,
        CraConfig? config,
        bool hasReadme,
        bool hasChangelog)
    {
        var findings = new List<AuditFinding>();

        // === Critical ===

        // 1. Annex I §1(2)(a) — No known exploitable vulnerabilities
        CheckKnownExploitableVulnerabilities(findings, allPackages, allVulnerabilities);

        // 2. Art. 14 — Actively exploited vulnerability reporting
        CheckActivelyExploitedVulnerabilities(findings, allPackages);

        // === High ===

        // 3. Annex I §2(2) — Remediate vulnerabilities without delay
        CheckUnpatchedVulnerabilities(findings, allPackages);

        // 4. Annex I §2(1) — SBOM completeness
        CheckSbomCompleteness(findings, sbomValidation);

        // 5. Art. 13(5) — Third-party component due diligence
        CheckComponentDueDiligence(findings, allPackages);

        // 5b. Art. 13(5) — Maintainer trust due diligence
        CheckMaintainerTrust(allPackages, findings);

        // 6. Annex I §2(7) — Secure update distribution
        CheckProvenanceVerification(findings, provenanceResults);

        // === Medium ===

        // 7. Annex I §2(5) — Coordinated vulnerability disclosure policy
        CheckVulnerabilityDisclosurePolicy(findings, packagesWithSecurityPolicy, packagesWithRepo);

        // 8. Annex I §2(6) — Vulnerability reporting contact
        CheckSecurityContact(findings, config, hasSecurityPolicy);

        // 9. Annex I §1(2)(j) — Attack surface minimization
        CheckAttackSurface(findings, attackSurface);

        // 10. Annex II — License documentation
        CheckLicenseDocumentation(findings, allPackages);

        // === Low ===

        // 11. Art. 13(8) — Support period declaration
        CheckSupportPeriod(findings, config);

        // 12. Annex II (documentation) — Product documentation
        CheckProductDocumentation(findings, hasReadme, hasChangelog);

        // Sort by severity: Critical (0) -> High (1) -> Medium (2) -> Low (3)
        findings.Sort((a, b) => a.Severity.CompareTo(b.Severity));

        var criticalCount = 0;
        var highCount = 0;
        var mediumCount = 0;
        var lowCount = 0;

        foreach (var f in findings)
        {
            switch (f.Severity)
            {
                case AuditSeverity.Critical: criticalCount++; break;
                case AuditSeverity.High: highCount++; break;
                case AuditSeverity.Medium: mediumCount++; break;
                case AuditSeverity.Low: lowCount++; break;
            }
        }

        return new AuditSimulationResult(findings, criticalCount, highCount, mediumCount, lowCount);
    }

    /// <summary>
    /// Check 1: Annex I §1(2)(a) — Products shall be delivered without known exploitable vulnerabilities.
    /// </summary>
    private static void CheckKnownExploitableVulnerabilities(
        List<AuditFinding> findings,
        IReadOnlyList<PackageHealth> allPackages,
        IReadOnlyDictionary<string, List<VulnerabilityInfo>> allVulnerabilities)
    {
        var affectedPackages = new List<string>();

        foreach (var pkg in allPackages)
        {
            if (!allVulnerabilities.TryGetValue(pkg.PackageId, out var vulns))
                continue;

            foreach (var vuln in vulns)
            {
                if (HealthScoreCalculator.IsAffected(pkg.Version, vuln))
                {
                    affectedPackages.Add(pkg.PackageId);
                    break; // One match is enough for this package
                }
            }
        }

        if (affectedPackages.Count > 0)
        {
            findings.Add(new AuditFinding(
                "CRA Annex I \u00a71(2)(a)",
                "Products shall be delivered without known exploitable vulnerabilities",
                $"{affectedPackages.Count} package(s) have known exploitable vulnerabilities affecting the installed version",
                AuditSeverity.Critical,
                affectedPackages));
        }
    }

    /// <summary>
    /// Check 2: Art. 14 — Actively exploited vulnerability reporting obligations.
    /// </summary>
    private static void CheckActivelyExploitedVulnerabilities(
        List<AuditFinding> findings,
        IReadOnlyList<PackageHealth> allPackages)
    {
        var affectedPackages = new List<string>();

        foreach (var pkg in allPackages)
        {
            if (pkg.HasKevVulnerability || pkg.MaxEpssProbability >= 0.5)
            {
                affectedPackages.Add(pkg.PackageId);
            }
        }

        if (affectedPackages.Count > 0)
        {
            findings.Add(new AuditFinding(
                "CRA Art. 14",
                "Actively exploited vulnerability reporting obligations",
                $"{affectedPackages.Count} package(s) have actively exploited or high-probability vulnerabilities requiring 24h notification",
                AuditSeverity.Critical,
                affectedPackages));
        }
    }

    /// <summary>
    /// Check 3: Annex I §2(2) — Remediate vulnerabilities without delay.
    /// </summary>
    private static void CheckUnpatchedVulnerabilities(
        List<AuditFinding> findings,
        IReadOnlyList<PackageHealth> allPackages)
    {
        var affectedPackages = new List<string>();

        foreach (var pkg in allPackages)
        {
            if (pkg.PatchAvailableNotAppliedCount > 0)
            {
                affectedPackages.Add(pkg.PackageId);
            }
        }

        if (affectedPackages.Count > 0)
        {
            findings.Add(new AuditFinding(
                "CRA Annex I \u00a72(2)",
                "Remediate vulnerabilities without delay",
                $"{affectedPackages.Count} package(s) have available patches not applied",
                AuditSeverity.High,
                affectedPackages));
        }
    }

    /// <summary>
    /// Check 4: Annex I §2(1) — SBOM completeness.
    /// </summary>
    private static void CheckSbomCompleteness(
        List<AuditFinding> findings,
        SbomValidationResult? sbomValidation)
    {
        if (sbomValidation is null)
            return;

        var hasMissingSupplier = sbomValidation.MissingSupplier.Count > 0;
        var hasMissingLicense = sbomValidation.MissingLicense.Count > 0;
        var hasMissingPurl = sbomValidation.MissingPurl.Count > 0;
        var hasMissingChecksum = sbomValidation.MissingChecksum.Count > 0;

        if (!hasMissingSupplier && !hasMissingLicense && !hasMissingPurl && !hasMissingChecksum)
            return;

        // Build list of missing field types
        var missingFields = new List<string>();
        if (hasMissingSupplier) missingFields.Add("supplier");
        if (hasMissingLicense) missingFields.Add("license");
        if (hasMissingPurl) missingFields.Add("PURL");
        if (hasMissingChecksum) missingFields.Add("checksum");

        // Union of all affected packages (distinct)
        var affectedPackages = sbomValidation.MissingSupplier
            .Concat(sbomValidation.MissingLicense)
            .Concat(sbomValidation.MissingPurl)
            .Concat(sbomValidation.MissingChecksum)
            .Distinct()
            .ToList();

        findings.Add(new AuditFinding(
            "CRA Annex I \u00a72(1)",
            "SBOM completeness",
            $"SBOM is incomplete \u2014 missing {string.Join(", ", missingFields)}",
            AuditSeverity.High,
            affectedPackages));
    }

    /// <summary>
    /// Check 5: Art. 13(5) — Third-party component due diligence.
    /// </summary>
    private static void CheckComponentDueDiligence(
        List<AuditFinding> findings,
        IReadOnlyList<PackageHealth> allPackages)
    {
        var affectedPackages = new List<string>();

        foreach (var pkg in allPackages)
        {
            if (pkg.Score < 40)
            {
                affectedPackages.Add(pkg.PackageId);
            }
        }

        if (affectedPackages.Count > 0)
        {
            findings.Add(new AuditFinding(
                "CRA Art. 13(5)",
                "Third-party component due diligence",
                $"{affectedPackages.Count} package(s) have critically low health scores (below 40), indicating insufficient due diligence",
                AuditSeverity.High,
                affectedPackages));
        }
    }

    /// <summary>
    /// Check 5b: Art. 13(5) — Third-party component maintainer due diligence.
    /// Packages with critical maintainer trust (score &lt; 40) indicate supply chain risk.
    /// </summary>
    private static void CheckMaintainerTrust(
        IReadOnlyList<PackageHealth> allPackages,
        List<AuditFinding> findings)
    {
        var criticalTrustPackages = allPackages
            .Where(p => p.MaintainerTrust is not null && p.MaintainerTrust.Score < 40)
            .Select(p => p.PackageId)
            .ToList();

        if (criticalTrustPackages.Count > 0)
        {
            findings.Add(new AuditFinding(
                ArticleReference: "CRA Art. 13(5) \u2014 Maintainer Due Diligence",
                Requirement: "Exercise due diligence regarding third-party component maintainer reliability",
                Finding: $"{criticalTrustPackages.Count} package(s) with critical maintainer trust score (< 40): single-maintainer risk, low community engagement, or stale maintenance",
                Severity: AuditSeverity.High,
                AffectedPackages: criticalTrustPackages));
        }
    }

    /// <summary>
    /// Check 6: Annex I §2(7) — Secure update distribution.
    /// </summary>
    private static void CheckProvenanceVerification(
        List<AuditFinding> findings,
        List<ProvenanceResult>? provenanceResults)
    {
        if (provenanceResults is null)
            return;

        var affectedPackages = new List<string>();

        foreach (var result in provenanceResults)
        {
            if (!result.IsVerified)
            {
                affectedPackages.Add(result.PackageId);
            }
        }

        if (affectedPackages.Count > 0)
        {
            findings.Add(new AuditFinding(
                "CRA Annex I \u00a72(7)",
                "Secure update distribution",
                $"{affectedPackages.Count} package(s) lack provenance verification (no repository or author signature)",
                AuditSeverity.High,
                affectedPackages));
        }
    }

    /// <summary>
    /// Check 7: Annex I §2(5) — Coordinated vulnerability disclosure policy.
    /// </summary>
    private static void CheckVulnerabilityDisclosurePolicy(
        List<AuditFinding> findings,
        int packagesWithSecurityPolicy,
        int packagesWithRepo)
    {
        if (packagesWithSecurityPolicy == 0 && packagesWithRepo > 0)
        {
            findings.Add(new AuditFinding(
                "CRA Annex I \u00a72(5)",
                "Coordinated vulnerability disclosure policy",
                "No upstream packages have a discoverable security policy (SECURITY.md)",
                AuditSeverity.Medium,
                []));
        }
    }

    /// <summary>
    /// Check 8: Annex I §2(6) — Vulnerability reporting contact.
    /// </summary>
    private static void CheckSecurityContact(
        List<AuditFinding> findings,
        CraConfig? config,
        bool hasSecurityPolicy)
    {
        if (string.IsNullOrEmpty(config?.SecurityContact) && !hasSecurityPolicy)
        {
            findings.Add(new AuditFinding(
                "CRA Annex I \u00a72(6)",
                "Vulnerability reporting contact",
                "No security contact declared in configuration or SECURITY.md",
                AuditSeverity.Medium,
                []));
        }
    }

    /// <summary>
    /// Check 9: Annex I §1(2)(j) — Attack surface minimization.
    /// </summary>
    private static void CheckAttackSurface(
        List<AuditFinding> findings,
        AttackSurfaceResult? attackSurface)
    {
        if (attackSurface is null)
            return;

        var isDeep = attackSurface.MaxDepth > 5;
        var hasHeavy = attackSurface.HeavyPackages.Count > 0;

        if (!isDeep && !hasHeavy)
            return;

        var heavyPackageIds = attackSurface.HeavyPackages
            .Select(hp => hp.PackageId)
            .ToList();

        var parts = new List<string>();
        if (isDeep)
            parts.Add($"Dependency tree depth is {attackSurface.MaxDepth} (threshold: 5)");
        if (hasHeavy)
            parts.Add($"{attackSurface.HeavyPackages.Count} package(s) have excessive transitive dependencies");

        findings.Add(new AuditFinding(
            "CRA Annex I \u00a71(2)(j)",
            "Attack surface minimization",
            string.Join("; ", parts),
            AuditSeverity.Medium,
            heavyPackageIds));
    }

    /// <summary>
    /// Check 10: Annex II — License documentation.
    /// </summary>
    private static void CheckLicenseDocumentation(
        List<AuditFinding> findings,
        IReadOnlyList<PackageHealth> allPackages)
    {
        var affectedPackages = new List<string>();

        foreach (var pkg in allPackages)
        {
            if (string.IsNullOrEmpty(pkg.License) ||
                pkg.License.Equals("Unknown", StringComparison.OrdinalIgnoreCase))
            {
                affectedPackages.Add(pkg.PackageId);
            }
        }

        if (affectedPackages.Count > 0)
        {
            findings.Add(new AuditFinding(
                "CRA Annex II",
                "License documentation",
                $"{affectedPackages.Count} package(s) have missing or unknown license declarations",
                AuditSeverity.Medium,
                affectedPackages));
        }
    }

    /// <summary>
    /// Check 11: Art. 13(8) — Support period declaration.
    /// </summary>
    private static void CheckSupportPeriod(
        List<AuditFinding> findings,
        CraConfig? config)
    {
        if (string.IsNullOrEmpty(config?.SupportPeriodEnd))
        {
            findings.Add(new AuditFinding(
                "CRA Art. 13(8)",
                "Support period declaration",
                "No product support period declared in .cra-config.json",
                AuditSeverity.Low,
                []));
        }
    }

    /// <summary>
    /// Check 12: Annex II (documentation) — Product documentation.
    /// </summary>
    private static void CheckProductDocumentation(
        List<AuditFinding> findings,
        bool hasReadme,
        bool hasChangelog)
    {
        if (hasReadme && hasChangelog)
            return;

        var missing = new List<string>();
        if (!hasReadme) missing.Add("README");
        if (!hasChangelog) missing.Add("CHANGELOG");

        findings.Add(new AuditFinding(
            "CRA Annex II (documentation)",
            "Product documentation",
            $"Missing project documentation: {string.Join(", ", missing)}",
            AuditSeverity.Low,
            []));
    }
}
