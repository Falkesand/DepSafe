namespace DepSafe.Models;

/// <summary>
/// Configuration for CRA compliance scanning.
/// Loaded from .cra-config.json in project root.
/// </summary>
public sealed class CraConfig
{
    /// <summary>
    /// Override license detection for specific packages.
    /// Key: Package name (case-insensitive)
    /// Value: SPDX license identifier (e.g., "Apache-2.0", "MIT")
    /// </summary>
    /// <example>
    /// {
    ///   "licenseOverrides": {
    ///     "SixLabors.ImageSharp": "Apache-2.0",
    ///     "SomePackage": "MIT"
    ///   }
    /// }
    /// </example>
    public Dictionary<string, string> LicenseOverrides { get; set; } = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Packages to exclude from CRA analysis.
    /// Useful for internal/private packages.
    /// </summary>
    public List<string> ExcludePackages { get; set; } = [];

    /// <summary>
    /// Additional notes or justifications for compliance decisions.
    /// Key: Package name
    /// Value: Note explaining the decision
    /// </summary>
    public Dictionary<string, string> ComplianceNotes { get; set; } = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Declared end of support period (e.g., "2028-12").
    /// Used for CRA Annex II documentation compliance.
    /// </summary>
    public string? SupportPeriodEnd { get; set; }

    /// <summary>
    /// Security contact information (e.g., email or URL).
    /// Used for CRA Annex II documentation compliance.
    /// </summary>
    public string? SecurityContact { get; set; }

    /// <summary>
    /// License SPDX identifiers that are explicitly allowed.
    /// When set, any package with a license not in this list triggers a policy violation.
    /// Takes precedence over BlockedLicenses when both are configured.
    /// </summary>
    public List<string> AllowedLicenses { get; set; } = [];

    /// <summary>
    /// License SPDX identifiers that are explicitly blocked.
    /// Ignored when AllowedLicenses is configured.
    /// </summary>
    public List<string> BlockedLicenses { get; set; } = [];

    /// <summary>
    /// Fail the report if any deprecated packages are detected.
    /// Returns exit code 2 for CI/CD build gates.
    /// </summary>
    public bool FailOnDeprecatedPackages { get; set; }

    /// <summary>
    /// Minimum acceptable health score for any individual package (0-100).
    /// Returns exit code 2 if any package scores below this threshold.
    /// </summary>
    public int? MinHealthScore { get; set; }

    /// <summary>
    /// Fail the report if any CISA KEV vulnerability is present.
    /// Returns exit code 2 for CI/CD build gates.
    /// </summary>
    public bool FailOnKev { get; set; }

    /// <summary>
    /// Fail if any package has EPSS probability above this threshold (0.0-1.0).
    /// Returns exit code 2 for CI/CD build gates.
    /// </summary>
    public double? FailOnEpssThreshold { get; set; }

    /// <summary>
    /// Fail if total active vulnerability count exceeds this number.
    /// Returns exit code 2 for CI/CD build gates.
    /// </summary>
    public int? FailOnVulnerabilityCount { get; set; }

    /// <summary>
    /// Fail if CRA readiness score is below this value (0-100).
    /// Returns exit code 2 for CI/CD build gates.
    /// </summary>
    public int? FailOnCraReadinessBelow { get; set; }

    /// <summary>
    /// Fail if any CRA Art. 14 reportable vulnerabilities exist (KEV or EPSS >= 0.5).
    /// Returns exit code 2 for CI/CD build gates.
    /// </summary>
    public bool FailOnReportableVulnerabilities { get; set; }

    /// <summary>
    /// Fail if any vulnerability has been unpatched for more than this many days.
    /// Maps to CRA Art. 11(4) remediation timeliness requirement.
    /// Returns exit code 2 for CI/CD build gates.
    /// </summary>
    public int? FailOnUnpatchedDaysOver { get; set; }

    /// <summary>
    /// Fail if any dependency has had no activity for 2+ years.
    /// Maps to CRA Art. 13(8) support period requirement.
    /// Returns exit code 2 for CI/CD build gates.
    /// </summary>
    public bool FailOnUnmaintainedPackages { get; set; }

    /// <summary>
    /// Fail if SBOM completeness percentage is below this threshold (0-100).
    /// Maps to CRA Annex I Part II(1) SBOM completeness requirement.
    /// Returns exit code 2 for CI/CD build gates.
    /// </summary>
    public int? FailOnSbomCompletenessBelow { get; set; }

    /// <summary>
    /// Fail if maximum dependency tree depth exceeds this value.
    /// Maps to CRA Annex I Part I(10) attack surface minimization requirement.
    /// Returns exit code 2 for CI/CD build gates.
    /// </summary>
    public int? FailOnAttackSurfaceDepthOver { get; set; }
}
