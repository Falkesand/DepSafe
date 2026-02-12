using DepSafe.Models;

namespace DepSafe.Compliance;

/// <summary>
/// Evaluates CRA policy rules against a report and produces structured violations.
/// All checks return PolicySeverity.Block and map to specific CRA articles.
/// </summary>
public static class PolicyEvaluator
{
    /// <summary>
    /// Evaluate all configured policy rules against the report, packages, and audit results.
    /// Returns structured violations with CRA article mapping and remediation guidance.
    /// </summary>
    public static PolicyEvaluationResult Evaluate(
        CraReport report,
        CraConfig? config,
        IReadOnlyList<PackageHealth>? packages = null,
        AuditSimulationResult? auditResult = null)
    {
        if (config is null)
            return new PolicyEvaluationResult([], 0);

        var violations = new List<PolicyViolation>();

        // 1. FailOnKev — check ComplianceItems for "CISA KEV" + NonCompliant
        if (config.FailOnKev)
        {
            var kevItem = report.ComplianceItems.Find(i =>
                i.Requirement.Contains("CISA KEV", StringComparison.OrdinalIgnoreCase)
                && i.Status == CraComplianceStatus.NonCompliant);

            if (kevItem is not null)
            {
                violations.Add(new PolicyViolation(
                    Rule: "FailOnKev",
                    Message: "CISA Known Exploited Vulnerability detected",
                    CraArticle: "Art. 10(6)",
                    Remediation: "Patch or remove packages with actively exploited vulnerabilities immediately",
                    Justification: null,
                    Severity: PolicySeverity.Block));
            }
        }

        // 2. FailOnEpssThreshold — check ComplianceItems for "EPSS" + not Compliant
        if (config.FailOnEpssThreshold.HasValue)
        {
            var epssItem = report.ComplianceItems.Find(i =>
                i.Requirement.Contains("EPSS", StringComparison.OrdinalIgnoreCase)
                && i.Status != CraComplianceStatus.Compliant);

            if (epssItem is not null)
            {
                violations.Add(new PolicyViolation(
                    Rule: "FailOnEpssThreshold",
                    Message: $"EPSS probability exceeds threshold of {config.FailOnEpssThreshold.Value:P0}",
                    CraArticle: "Art. 10(6)",
                    Remediation: "Prioritize patching vulnerabilities with high exploit probability",
                    Justification: null,
                    Severity: PolicySeverity.Block));
            }
        }

        // 3. NoCriticalVulnerabilities — report.CriticalVulnerabilityCount > 0
        if (config.NoCriticalVulnerabilities && report.CriticalVulnerabilityCount > 0)
        {
            violations.Add(new PolicyViolation(
                Rule: "NoCriticalVulnerabilities",
                Message: $"{report.CriticalVulnerabilityCount} critical-severity vulnerabilities detected",
                CraArticle: "Art. 10(6)",
                Remediation: "Resolve all critical-severity vulnerabilities before release",
                Justification: null,
                Severity: PolicySeverity.Block));
        }

        // 4. FailOnVulnerabilityCount — report.VulnerabilityCount > threshold
        if (config.FailOnVulnerabilityCount.HasValue
            && report.VulnerabilityCount > config.FailOnVulnerabilityCount.Value)
        {
            violations.Add(new PolicyViolation(
                Rule: "FailOnVulnerabilityCount",
                Message: $"Vulnerability count {report.VulnerabilityCount} exceeds threshold of {config.FailOnVulnerabilityCount.Value}",
                CraArticle: "Art. 10(6)",
                Remediation: $"Reduce vulnerability count to at most {config.FailOnVulnerabilityCount.Value}",
                Justification: null,
                Severity: PolicySeverity.Block));
        }

        // 5. FailOnCraReadinessBelow — report.CraReadinessScore < threshold
        if (config.FailOnCraReadinessBelow.HasValue
            && report.CraReadinessScore < config.FailOnCraReadinessBelow.Value)
        {
            violations.Add(new PolicyViolation(
                Rule: "FailOnCraReadinessBelow",
                Message: $"CRA readiness score {report.CraReadinessScore} is below threshold of {config.FailOnCraReadinessBelow.Value}",
                CraArticle: "Art. 10(1)",
                Remediation: $"Improve CRA readiness score to at least {config.FailOnCraReadinessBelow.Value}",
                Justification: null,
                Severity: PolicySeverity.Block));
        }

        // 6. FailOnReportableVulnerabilities — report.ReportableVulnerabilityCount > 0
        if (config.FailOnReportableVulnerabilities && report.ReportableVulnerabilityCount > 0)
        {
            violations.Add(new PolicyViolation(
                Rule: "FailOnReportableVulnerabilities",
                Message: $"{report.ReportableVulnerabilityCount} CRA Art. 14 reportable vulnerabilities detected",
                CraArticle: "Art. 14",
                Remediation: "Address reportable vulnerabilities (KEV or EPSS >= 0.5) before release",
                Justification: null,
                Severity: PolicySeverity.Block));
        }

        // 7. FailOnUnpatchedDaysOver — report.MaxUnpatchedVulnerabilityDays > threshold
        if (config.FailOnUnpatchedDaysOver.HasValue
            && report.MaxUnpatchedVulnerabilityDays.HasValue
            && report.MaxUnpatchedVulnerabilityDays.Value > config.FailOnUnpatchedDaysOver.Value)
        {
            violations.Add(new PolicyViolation(
                Rule: "FailOnUnpatchedDaysOver",
                Message: $"Oldest unpatched vulnerability is {report.MaxUnpatchedVulnerabilityDays.Value} days old (threshold: {config.FailOnUnpatchedDaysOver.Value})",
                CraArticle: "Art. 11(4)",
                Remediation: $"Patch vulnerabilities within {config.FailOnUnpatchedDaysOver.Value} days of disclosure",
                Justification: null,
                Severity: PolicySeverity.Block));
        }

        // 8. BlockUnmaintainedMonths takes precedence over FailOnUnmaintainedPackages
        if (config.BlockUnmaintainedMonths.HasValue)
        {
            if (report.MaxInactiveMonths.HasValue
                && report.MaxInactiveMonths.Value > config.BlockUnmaintainedMonths.Value)
            {
                violations.Add(new PolicyViolation(
                    Rule: "BlockUnmaintainedMonths",
                    Message: $"Dependency inactive for {report.MaxInactiveMonths.Value} months (threshold: {config.BlockUnmaintainedMonths.Value})",
                    CraArticle: "Art. 13(8)",
                    Remediation: $"Replace or fork dependencies inactive for more than {config.BlockUnmaintainedMonths.Value} months",
                    Justification: null,
                    Severity: PolicySeverity.Block));
            }
        }
        else if (config.FailOnUnmaintainedPackages && report.HasUnmaintainedPackages)
        {
            violations.Add(new PolicyViolation(
                Rule: "FailOnUnmaintainedPackages",
                Message: "Unmaintained dependencies detected (no activity for 2+ years)",
                CraArticle: "Art. 13(8)",
                Remediation: "Replace or fork unmaintained dependencies",
                Justification: null,
                Severity: PolicySeverity.Block));
        }

        // 9. FailOnSbomCompletenessBelow — report.SbomCompletenessPercentage < threshold
        if (config.FailOnSbomCompletenessBelow.HasValue
            && report.SbomCompletenessPercentage.HasValue
            && report.SbomCompletenessPercentage.Value < config.FailOnSbomCompletenessBelow.Value)
        {
            violations.Add(new PolicyViolation(
                Rule: "FailOnSbomCompletenessBelow",
                Message: $"SBOM completeness {report.SbomCompletenessPercentage.Value}% is below threshold of {config.FailOnSbomCompletenessBelow.Value}%",
                CraArticle: "Annex I Part II",
                Remediation: $"Improve SBOM completeness to at least {config.FailOnSbomCompletenessBelow.Value}%",
                Justification: null,
                Severity: PolicySeverity.Block));
        }

        // 10. FailOnAttackSurfaceDepthOver — report.MaxDependencyDepth > threshold
        if (config.FailOnAttackSurfaceDepthOver.HasValue
            && report.MaxDependencyDepth.HasValue
            && report.MaxDependencyDepth.Value > config.FailOnAttackSurfaceDepthOver.Value)
        {
            violations.Add(new PolicyViolation(
                Rule: "FailOnAttackSurfaceDepthOver",
                Message: $"Dependency depth {report.MaxDependencyDepth.Value} exceeds threshold of {config.FailOnAttackSurfaceDepthOver.Value}",
                CraArticle: "Annex I Part I(10)",
                Remediation: $"Reduce dependency tree depth to at most {config.FailOnAttackSurfaceDepthOver.Value}",
                Justification: null,
                Severity: PolicySeverity.Block));
        }

        // 11. License policy — packages + (AllowedLicenses or BlockedLicenses)
        if (packages is not null
            && (config.AllowedLicenses.Count > 0 || config.BlockedLicenses.Count > 0))
        {
            var licenseResult = LicensePolicyEvaluator.Evaluate(packages, config);
            foreach (var lv in licenseResult.Violations)
            {
                violations.Add(new PolicyViolation(
                    Rule: "LicensePolicy",
                    Message: $"Package '{lv.PackageId}': {lv.Reason}",
                    CraArticle: "Art. 13(6)",
                    Remediation: $"Replace '{lv.PackageId}' with a package using an approved license, or add '{lv.License}' to the allowed list",
                    Justification: GetJustification(config, lv.PackageId),
                    Severity: PolicySeverity.Block));
            }
        }

        // 12. FailOnDeprecatedPackages — foreach pkg in report.DeprecatedPackages
        if (config.FailOnDeprecatedPackages)
        {
            foreach (var pkgId in report.DeprecatedPackages)
            {
                violations.Add(new PolicyViolation(
                    Rule: "FailOnDeprecatedPackages",
                    Message: $"Package '{pkgId}' is deprecated",
                    CraArticle: "Art. 13(8)",
                    Remediation: $"Replace deprecated package '{pkgId}' with a maintained alternative",
                    Justification: GetJustification(config, pkgId),
                    Severity: PolicySeverity.Block));
            }
        }

        // 13. MinHealthScore — report.MinPackageHealthScore < threshold
        if (config.MinHealthScore.HasValue
            && report.MinPackageHealthScore.HasValue
            && report.MinPackageHealthScore.Value < config.MinHealthScore.Value)
        {
            var pkgId = report.MinHealthScorePackage;
            violations.Add(new PolicyViolation(
                Rule: "MinHealthScore",
                Message: $"Minimum package health score {report.MinPackageHealthScore.Value} is below threshold of {config.MinHealthScore.Value}"
                    + (pkgId is not null ? $" (package: {pkgId})" : ""),
                CraArticle: "Art. 10(1)",
                Remediation: pkgId is not null
                    ? $"Improve health of '{pkgId}' (score: {report.MinPackageHealthScore.Value}) or replace with a healthier alternative"
                    : $"Improve minimum package health score to at least {config.MinHealthScore.Value}",
                Justification: pkgId is not null ? GetJustification(config, pkgId) : null,
                Severity: PolicySeverity.Block));
        }

        // 14. MinPackageMaintainers — foreach pkg where MaintainerTrust?.ContributorCount < threshold
        if (config.MinPackageMaintainers.HasValue && packages is not null)
        {
            foreach (var pkg in packages)
            {
                if (pkg.MaintainerTrust is not null
                    && pkg.MaintainerTrust.ContributorCount < config.MinPackageMaintainers.Value)
                {
                    violations.Add(new PolicyViolation(
                        Rule: "MinPackageMaintainers",
                        Message: $"Package '{pkg.PackageId}' has {pkg.MaintainerTrust.ContributorCount} contributor(s), below minimum of {config.MinPackageMaintainers.Value}",
                        CraArticle: "Art. 13(5)",
                        Remediation: $"Evaluate bus-factor risk for '{pkg.PackageId}' ({pkg.MaintainerTrust.ContributorCount} contributor(s)) and consider alternatives with broader maintainer base",
                        Justification: GetJustification(config, pkg.PackageId),
                        Severity: PolicySeverity.Block));
                }
            }
        }

        // 15. Audit simulation — foreach finding with Critical or High severity
        if (auditResult is not null)
        {
            foreach (var finding in auditResult.Findings)
            {
                if (finding.Severity is AuditSeverity.Critical or AuditSeverity.High)
                {
                    violations.Add(new PolicyViolation(
                        Rule: "AuditSimulation",
                        Message: $"[{finding.Severity}] {finding.ArticleReference}: {finding.Finding}",
                        CraArticle: finding.ArticleReference,
                        Remediation: finding.Requirement,
                        Justification: null,
                        Severity: PolicySeverity.Block));
                }
            }
        }

        // Exit code: 2 if violations > 0, else 1 if NonCompliant, else 0
        int exitCode = violations.Count > 0
            ? 2
            : report.OverallComplianceStatus == CraComplianceStatus.NonCompliant
                ? 1
                : 0;

        return new PolicyEvaluationResult(violations, exitCode);
    }

    private static string? GetJustification(CraConfig config, string packageId)
    {
        return config.ComplianceNotes.TryGetValue(packageId, out var note) ? note : null;
    }
}
