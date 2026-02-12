# Phase 1.1: Policy as Code — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Expand the CraConfig threshold system into a structured policy engine with new rules, human-readable Spectre.Console table output, package exclusion, compliance notes, and CRA article references.

**Architecture:** Add 3 new CraConfig properties. Extract policy evaluation from inline `EvaluateExitCode` into a dedicated `PolicyEvaluator` static class returning structured `PolicyViolation` records. Wire `ExcludePackages` and `ComplianceNotes`. Replace bullet-point CLI output with Spectre.Console table. Upgrade HTML report policy section.

**Tech Stack:** .NET 10, System.Text.Json, Spectre.Console, xUnit

---

## Context for Implementer

### Current State
- `CraConfig` (17 properties) in `src/DepSafe/Models/CraConfig.cs`
- `EvaluateExitCode` method in `src/DepSafe/Commands/CraReportCommand.cs:3215-3303` — returns `(int ExitCode, List<string> Violations)` with 11 inline checks
- `LicensePolicyEvaluator` at `src/DepSafe/Compliance/LicensePolicyEvaluator.cs` — evaluates AllowedLicenses/BlockedLicenses
- `GeneratePolicyViolationsSection` at `src/DepSafe/Compliance/CraReportGenerator.Sections.cs:2001-2090` — renders license/deprecated/health violations
- `SetPolicyViolations(LicensePolicyResult?, CraConfig?)` at `src/DepSafe/Compliance/CraReportGenerator.cs:1352-1356`
- `ExcludePackages` and `ComplianceNotes` exist in CraConfig but are **not wired** anywhere
- `PackageHealth.MaintainerTrust?.ContributorCount` gives contributor count per package
- `CraReport` has `HasUnmaintainedPackages` (bool) but no month-level granularity
- `CraReport` has `VulnerabilityCount` (total) but no critical-severity count

### Key Files
| File | Purpose |
|------|---------|
| `src/DepSafe/Models/CraConfig.cs` | Config model (add 3 new properties) |
| `src/DepSafe/Compliance/CraReport.cs` | Report model (add 2 new fields) |
| `src/DepSafe/Compliance/PolicyEvaluator.cs` | **NEW** — Static evaluator class |
| `src/DepSafe/Models/PolicyViolation.cs` | **NEW** — Violation record |
| `src/DepSafe/Models/PolicySeverity.cs` | **NEW** — Severity enum |
| `src/DepSafe/Models/PolicyEvaluationResult.cs` | **NEW** — Result record |
| `src/DepSafe/Commands/CraReportCommand.cs` | Wire exclusion + replace EvaluateExitCode |
| `src/DepSafe/Compliance/CraReportGenerator.cs` | Update SetPolicyEvaluation |
| `src/DepSafe/Compliance/CraReportGenerator.Sections.cs` | Rewrite policy section + add excluded card |
| `tests/DepSafe.Tests/PolicyEvaluatorTests.cs` | **NEW** — 16 tests |

---

## Task 1: Create Policy Models

**Files:**
- Create: `src/DepSafe/Models/PolicySeverity.cs`
- Create: `src/DepSafe/Models/PolicyViolation.cs`
- Create: `src/DepSafe/Models/PolicyEvaluationResult.cs`

**Step 1: Create PolicySeverity enum**

```csharp
// src/DepSafe/Models/PolicySeverity.cs
namespace DepSafe.Models;

public enum PolicySeverity { Block, Warn }
```

**Step 2: Create PolicyViolation record**

```csharp
// src/DepSafe/Models/PolicyViolation.cs
namespace DepSafe.Models;

public sealed record PolicyViolation(
    string Rule,
    string Message,
    string? CraArticle,
    string? Remediation,
    string? Justification,
    PolicySeverity Severity);
```

**Step 3: Create PolicyEvaluationResult record**

```csharp
// src/DepSafe/Models/PolicyEvaluationResult.cs
namespace DepSafe.Models;

public sealed record PolicyEvaluationResult(
    List<PolicyViolation> Violations,
    int ExitCode);
```

**Step 4: Build**

Run: `dotnet build --no-restore`
Expected: 0 warnings, 0 errors

**Step 5: Commit**

```bash
git add src/DepSafe/Models/PolicySeverity.cs src/DepSafe/Models/PolicyViolation.cs src/DepSafe/Models/PolicyEvaluationResult.cs
git commit -m "feat: add PolicyViolation, PolicySeverity, PolicyEvaluationResult models"
```

---

## Task 2: Add New CraConfig Properties and CraReport Fields

**Files:**
- Modify: `src/DepSafe/Models/CraConfig.cs:130` (add 3 properties after last property)
- Modify: `src/DepSafe/Compliance/CraReport.cs:43` (add 2 fields before closing brace)

**Step 1: Add 3 new properties to CraConfig**

Add after line 130 (`FailOnAttackSurfaceDepthOver`), before the closing `}`:

```csharp
    /// <summary>
    /// Fail if any critical-severity vulnerability exists.
    /// Maps to CRA Art. 10(6) vulnerability management.
    /// Returns exit code 2 for CI/CD build gates.
    /// </summary>
    public bool NoCriticalVulnerabilities { get; set; }

    /// <summary>
    /// Minimum number of contributors for any package.
    /// Maps to CRA Art. 13(5) maintainer trust requirement.
    /// Returns exit code 2 if any package has fewer than this many contributors.
    /// </summary>
    public int? MinPackageMaintainers { get; set; }

    /// <summary>
    /// Fail if any dependency has been inactive for more than this many months.
    /// Maps to CRA Art. 13(8) support period requirement.
    /// Takes precedence over FailOnUnmaintainedPackages when set.
    /// Returns exit code 2 for CI/CD build gates.
    /// </summary>
    public int? BlockUnmaintainedMonths { get; set; }
```

**Step 2: Add 2 new fields to CraReport**

Add after line 42 (`MinHealthScorePackage`), before the closing `}`:

```csharp
    // Structured policy fields (v1.7 - Policy as Code)
    /// <summary>Count of critical-severity vulnerabilities (OSV severity = CRITICAL).</summary>
    public int CriticalVulnerabilityCount { get; init; }
    /// <summary>Maximum months since last commit across all dependencies (null if no GitHub data).</summary>
    public int? MaxInactiveMonths { get; init; }
```

**Step 3: Build**

Run: `dotnet build --no-restore`
Expected: 0 warnings, 0 errors

**Step 4: Commit**

```bash
git add src/DepSafe/Models/CraConfig.cs src/DepSafe/Compliance/CraReport.cs
git commit -m "feat: add NoCriticalVulnerabilities, MinPackageMaintainers, BlockUnmaintainedMonths config properties"
```

---

## Task 3: Write PolicyEvaluator Tests

**Files:**
- Create: `tests/DepSafe.Tests/PolicyEvaluatorTests.cs`

**Step 1: Write 12 PolicyEvaluator unit tests**

Create `tests/DepSafe.Tests/PolicyEvaluatorTests.cs` with these tests. Each test creates a `CraConfig`, `CraReport`, and optionally `List<PackageHealth>`, then calls `PolicyEvaluator.Evaluate(report, config, packages, null)` and asserts on the returned `PolicyEvaluationResult`.

```csharp
using DepSafe.Compliance;
using DepSafe.Models;

namespace DepSafe.Tests;

public class PolicyEvaluatorTests
{
    [Fact]
    public void NoCriticalVulnerabilities_WithCritical_ReturnsViolation()
    {
        var config = new CraConfig { NoCriticalVulnerabilities = true };
        var report = CreateReport(criticalVulnerabilityCount: 2);

        var result = PolicyEvaluator.Evaluate(report, config);

        var violation = Assert.Single(result.Violations);
        Assert.Equal("NoCriticalVulnerabilities", violation.Rule);
        Assert.Equal("Art. 10(6)", violation.CraArticle);
        Assert.Equal(PolicySeverity.Block, violation.Severity);
        Assert.Contains("2", violation.Message);
        Assert.Equal(2, result.ExitCode);
    }

    [Fact]
    public void NoCriticalVulnerabilities_NoCritical_NoViolation()
    {
        var config = new CraConfig { NoCriticalVulnerabilities = true };
        var report = CreateReport(criticalVulnerabilityCount: 0);

        var result = PolicyEvaluator.Evaluate(report, config);

        Assert.Empty(result.Violations);
    }

    [Fact]
    public void MinPackageMaintainers_BelowThreshold_ReturnsViolation()
    {
        var config = new CraConfig { MinPackageMaintainers = 2 };
        var report = CreateReport();
        var packages = new List<PackageHealth>
        {
            CreatePackage("PkgA", contributorCount: 1),
            CreatePackage("PkgB", contributorCount: 5)
        };

        var result = PolicyEvaluator.Evaluate(report, config, packages);

        var violation = Assert.Single(result.Violations);
        Assert.Equal("MinPackageMaintainers", violation.Rule);
        Assert.Equal("Art. 13(5)", violation.CraArticle);
        Assert.Contains("PkgA", violation.Message);
        Assert.Equal(2, result.ExitCode);
    }

    [Fact]
    public void MinPackageMaintainers_MeetsThreshold_NoViolation()
    {
        var config = new CraConfig { MinPackageMaintainers = 2 };
        var report = CreateReport();
        var packages = new List<PackageHealth>
        {
            CreatePackage("PkgA", contributorCount: 3),
            CreatePackage("PkgB", contributorCount: 5)
        };

        var result = PolicyEvaluator.Evaluate(report, config, packages);

        Assert.Empty(result.Violations);
    }

    [Fact]
    public void BlockUnmaintainedMonths_ExceedsThreshold_ReturnsViolation()
    {
        var config = new CraConfig { BlockUnmaintainedMonths = 12 };
        var report = CreateReport(maxInactiveMonths: 18);

        var result = PolicyEvaluator.Evaluate(report, config);

        var violation = Assert.Single(result.Violations);
        Assert.Equal("BlockUnmaintainedMonths", violation.Rule);
        Assert.Equal("Art. 13(8)", violation.CraArticle);
        Assert.Contains("18", violation.Message);
        Assert.Equal(2, result.ExitCode);
    }

    [Fact]
    public void BlockUnmaintainedMonths_TakesPrecedenceOverBool()
    {
        // Both set: BlockUnmaintainedMonths = 6, FailOnUnmaintainedPackages = true
        // MaxInactiveMonths = 10 months (violates BlockUnmaintainedMonths but not the 24-month FailOnUnmaintainedPackages)
        // Should produce 1 violation from BlockUnmaintainedMonths, NOT from FailOnUnmaintainedPackages
        var config = new CraConfig
        {
            BlockUnmaintainedMonths = 6,
            FailOnUnmaintainedPackages = true
        };
        var report = CreateReport(maxInactiveMonths: 10, hasUnmaintainedPackages: false);

        var result = PolicyEvaluator.Evaluate(report, config);

        var violation = Assert.Single(result.Violations);
        Assert.Equal("BlockUnmaintainedMonths", violation.Rule);
    }

    [Fact]
    public void ExistingFailOnRules_StillWork()
    {
        var config = new CraConfig
        {
            FailOnKev = true,
            FailOnVulnerabilityCount = 0,
            FailOnCraReadinessBelow = 80
        };
        var report = CreateReport(
            vulnerabilityCount: 3,
            craReadinessScore: 65,
            complianceItems: [
                new CraComplianceItem
                {
                    Requirement = "CISA KEV Vulnerabilities",
                    Status = CraComplianceStatus.NonCompliant,
                    Evidence = "1 KEV vulnerability found",
                    Recommendation = "Patch immediately"
                }
            ]);

        var result = PolicyEvaluator.Evaluate(report, config);

        Assert.Equal(3, result.Violations.Count);
        Assert.Equal(2, result.ExitCode);
        Assert.Contains(result.Violations, v => v.Rule == "FailOnKev");
        Assert.Contains(result.Violations, v => v.Rule == "FailOnVulnerabilityCount");
        Assert.Contains(result.Violations, v => v.Rule == "FailOnCraReadinessBelow");
    }

    [Fact]
    public void ComplianceNotes_AttachedToViolation()
    {
        var config = new CraConfig
        {
            MinHealthScore = 60,
            ComplianceNotes = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["WeakPkg"] = "Accepted risk: scheduled for replacement in Q3"
            }
        };
        var report = CreateReport(minPackageHealthScore: 40, minHealthScorePackage: "WeakPkg");

        var result = PolicyEvaluator.Evaluate(report, config);

        var violation = Assert.Single(result.Violations);
        Assert.Equal("Accepted risk: scheduled for replacement in Q3", violation.Justification);
    }

    [Fact]
    public void LicenseViolations_IncludedInResult()
    {
        var config = new CraConfig { AllowedLicenses = ["MIT", "Apache-2.0"] };
        var report = CreateReport();
        var packages = new List<PackageHealth>
        {
            CreatePackage("GplPkg", license: "GPL-3.0")
        };

        var result = PolicyEvaluator.Evaluate(report, config, packages);

        var violation = Assert.Single(result.Violations);
        Assert.Equal("LicensePolicy", violation.Rule);
        Assert.Equal("Art. 13(6)", violation.CraArticle);
        Assert.Contains("GplPkg", violation.Message);
        Assert.Equal(2, result.ExitCode);
    }

    [Fact]
    public void NoConfig_ReturnsEmpty()
    {
        var report = CreateReport();

        var result = PolicyEvaluator.Evaluate(report, null);

        Assert.Empty(result.Violations);
        Assert.Equal(0, result.ExitCode);
    }

    [Fact]
    public void MultipleViolations_AllCollected()
    {
        var config = new CraConfig
        {
            NoCriticalVulnerabilities = true,
            FailOnDeprecatedPackages = true
        };
        var report = CreateReport(
            criticalVulnerabilityCount: 1,
            deprecatedPackages: ["OldPkg"]);

        var result = PolicyEvaluator.Evaluate(report, config);

        Assert.Equal(2, result.Violations.Count);
        Assert.Equal(2, result.ExitCode);
    }

    [Fact]
    public void Remediation_IncludesPackageDetails()
    {
        var config = new CraConfig { MinPackageMaintainers = 3 };
        var report = CreateReport();
        var packages = new List<PackageHealth>
        {
            CreatePackage("TinyLib", contributorCount: 1)
        };

        var result = PolicyEvaluator.Evaluate(report, config, packages);

        var violation = Assert.Single(result.Violations);
        Assert.NotNull(violation.Remediation);
        Assert.Contains("TinyLib", violation.Remediation);
    }

    // --- Helper methods ---

    private static CraReport CreateReport(
        int vulnerabilityCount = 0,
        int criticalVulnerabilityCount = 0,
        int craReadinessScore = 85,
        int? maxInactiveMonths = null,
        bool hasUnmaintainedPackages = false,
        int? minPackageHealthScore = null,
        string? minHealthScorePackage = null,
        List<string>? deprecatedPackages = null,
        int? maxUnpatchedDays = null,
        int? sbomCompleteness = null,
        int? maxDepth = null,
        int reportableVulnCount = 0,
        List<CraComplianceItem>? complianceItems = null)
    {
        return new CraReport
        {
            GeneratedAt = DateTime.UtcNow,
            ProjectPath = "/test/project",
            HealthScore = 75,
            HealthStatus = HealthStatus.Good,
            ComplianceItems = complianceItems ?? [],
            OverallComplianceStatus = CraComplianceStatus.Compliant,
            Sbom = new SbomDocument { Components = [] },
            Vex = new VexDocument { Statements = [] },
            PackageCount = 10,
            TransitivePackageCount = 30,
            VulnerabilityCount = vulnerabilityCount,
            CriticalPackageCount = 0,
            CraReadinessScore = craReadinessScore,
            CriticalVulnerabilityCount = criticalVulnerabilityCount,
            MaxInactiveMonths = maxInactiveMonths,
            HasUnmaintainedPackages = hasUnmaintainedPackages,
            MinPackageHealthScore = minPackageHealthScore,
            MinHealthScorePackage = minHealthScorePackage,
            DeprecatedPackages = deprecatedPackages ?? [],
            MaxUnpatchedVulnerabilityDays = maxUnpatchedDays,
            SbomCompletenessPercentage = sbomCompleteness,
            MaxDependencyDepth = maxDepth,
            ReportableVulnerabilityCount = reportableVulnCount
        };
    }

    private static PackageHealth CreatePackage(
        string id = "TestPkg",
        int score = 75,
        int? contributorCount = null,
        string? license = "MIT")
    {
        MaintainerTrust? trust = contributorCount.HasValue
            ? new MaintainerTrust(
                Score: 60,
                Tier: MaintainerTrustTier.Moderate,
                ContributorCount: contributorCount.Value,
                TotalCommits: 100,
                TotalReleases: 10,
                ReleaseAuthorCount: 1,
                TopReleaseAuthor: null)
            : null;

        return new PackageHealth
        {
            PackageId = id,
            Version = "1.0.0",
            Score = score,
            Status = HealthStatus.Good,
            Metrics = new PackageMetrics(),
            License = license,
            MaintainerTrust = trust
        };
    }
}
```

**Step 2: Build (should compile but PolicyEvaluator does not exist yet, so build fails)**

Run: `dotnet build --no-restore`
Expected: Build error — `PolicyEvaluator` does not exist

**Step 3: Commit tests**

```bash
git add tests/DepSafe.Tests/PolicyEvaluatorTests.cs
git commit -m "test: add 12 failing tests for PolicyEvaluator"
```

---

## Task 4: Implement PolicyEvaluator

**Files:**
- Create: `src/DepSafe/Compliance/PolicyEvaluator.cs`

**Step 1: Implement PolicyEvaluator static class**

Create `src/DepSafe/Compliance/PolicyEvaluator.cs`:

```csharp
using DepSafe.Models;

namespace DepSafe.Compliance;

public static class PolicyEvaluator
{
    public static PolicyEvaluationResult Evaluate(
        CraReport report,
        CraConfig? config,
        IReadOnlyList<PackageHealth>? packages = null,
        AuditSimulationResult? auditResult = null)
    {
        var violations = new List<PolicyViolation>();

        if (config is not null)
        {
            // --- Vulnerability gates ---
            if (config.FailOnKev)
            {
                var kevItem = report.ComplianceItems.FirstOrDefault(i =>
                    i.Requirement.Contains("CISA KEV", StringComparison.OrdinalIgnoreCase));
                if (kevItem?.Status == CraComplianceStatus.NonCompliant)
                    violations.Add(new PolicyViolation(
                        Rule: "FailOnKev",
                        Message: "CISA KEV vulnerability detected",
                        CraArticle: "Art. 10(6)",
                        Remediation: "Patch all actively exploited vulnerabilities immediately",
                        Justification: null,
                        Severity: PolicySeverity.Block));
            }

            if (config.FailOnEpssThreshold.HasValue)
            {
                var epssItem = report.ComplianceItems.FirstOrDefault(i =>
                    i.Requirement.Contains("EPSS", StringComparison.OrdinalIgnoreCase));
                if (epssItem?.Status != CraComplianceStatus.Compliant)
                    violations.Add(new PolicyViolation(
                        Rule: "FailOnEpssThreshold",
                        Message: $"EPSS threshold exceeded ({config.FailOnEpssThreshold.Value:P0})",
                        CraArticle: "Art. 10(6)",
                        Remediation: "Prioritize patching high-EPSS vulnerabilities",
                        Justification: null,
                        Severity: PolicySeverity.Block));
            }

            if (config.NoCriticalVulnerabilities && report.CriticalVulnerabilityCount > 0)
                violations.Add(new PolicyViolation(
                    Rule: "NoCriticalVulnerabilities",
                    Message: $"{report.CriticalVulnerabilityCount} critical-severity vulnerability(ies) found",
                    CraArticle: "Art. 10(6)",
                    Remediation: "Upgrade affected packages to patched versions",
                    Justification: null,
                    Severity: PolicySeverity.Block));

            if (config.FailOnVulnerabilityCount.HasValue && report.VulnerabilityCount > config.FailOnVulnerabilityCount.Value)
                violations.Add(new PolicyViolation(
                    Rule: "FailOnVulnerabilityCount",
                    Message: $"Vulnerability count {report.VulnerabilityCount} exceeds threshold {config.FailOnVulnerabilityCount.Value}",
                    CraArticle: "Art. 10(6)",
                    Remediation: "Reduce active vulnerabilities by upgrading or replacing affected packages",
                    Justification: null,
                    Severity: PolicySeverity.Block));

            // --- CRA readiness ---
            if (config.FailOnCraReadinessBelow.HasValue && report.CraReadinessScore < config.FailOnCraReadinessBelow.Value)
                violations.Add(new PolicyViolation(
                    Rule: "FailOnCraReadinessBelow",
                    Message: $"CRA readiness score {report.CraReadinessScore} below threshold {config.FailOnCraReadinessBelow.Value}",
                    CraArticle: "Art. 10(1)",
                    Remediation: "Address compliance gaps identified in the CRA Compliance section",
                    Justification: null,
                    Severity: PolicySeverity.Block));

            // --- Reporting obligations ---
            if (config.FailOnReportableVulnerabilities && report.ReportableVulnerabilityCount > 0)
                violations.Add(new PolicyViolation(
                    Rule: "FailOnReportableVulnerabilities",
                    Message: $"CRA Art. 14 reportable vulnerabilities detected ({report.ReportableVulnerabilityCount})",
                    CraArticle: "Art. 14",
                    Remediation: "Review and report vulnerabilities per CRA incident reporting requirements",
                    Justification: null,
                    Severity: PolicySeverity.Block));

            // --- Patching timeliness ---
            if (config.FailOnUnpatchedDaysOver.HasValue && report.MaxUnpatchedVulnerabilityDays.HasValue
                && report.MaxUnpatchedVulnerabilityDays.Value > config.FailOnUnpatchedDaysOver.Value)
                violations.Add(new PolicyViolation(
                    Rule: "FailOnUnpatchedDaysOver",
                    Message: $"Unpatched vulnerability age {report.MaxUnpatchedVulnerabilityDays.Value} days exceeds threshold {config.FailOnUnpatchedDaysOver.Value}",
                    CraArticle: "Art. 11(4)",
                    Remediation: "Apply available patches for long-outstanding vulnerabilities",
                    Justification: null,
                    Severity: PolicySeverity.Block));

            // --- Maintenance gates (BlockUnmaintainedMonths takes precedence) ---
            if (config.BlockUnmaintainedMonths.HasValue)
            {
                if (report.MaxInactiveMonths.HasValue && report.MaxInactiveMonths.Value > config.BlockUnmaintainedMonths.Value)
                    violations.Add(new PolicyViolation(
                        Rule: "BlockUnmaintainedMonths",
                        Message: $"Dependency inactive for {report.MaxInactiveMonths.Value} months exceeds threshold {config.BlockUnmaintainedMonths.Value}",
                        CraArticle: "Art. 13(8)",
                        Remediation: "Replace unmaintained dependencies with actively maintained alternatives",
                        Justification: null,
                        Severity: PolicySeverity.Block));
            }
            else if (config.FailOnUnmaintainedPackages && report.HasUnmaintainedPackages)
            {
                violations.Add(new PolicyViolation(
                    Rule: "FailOnUnmaintainedPackages",
                    Message: "Unmaintained packages detected (no activity 2+ years)",
                    CraArticle: "Art. 13(8)",
                    Remediation: "Replace unmaintained dependencies with actively maintained alternatives",
                    Justification: null,
                    Severity: PolicySeverity.Block));
            }

            // --- SBOM completeness ---
            if (config.FailOnSbomCompletenessBelow.HasValue && report.SbomCompletenessPercentage.HasValue
                && report.SbomCompletenessPercentage.Value < config.FailOnSbomCompletenessBelow.Value)
                violations.Add(new PolicyViolation(
                    Rule: "FailOnSbomCompletenessBelow",
                    Message: $"SBOM completeness {report.SbomCompletenessPercentage.Value}% below threshold {config.FailOnSbomCompletenessBelow.Value}%",
                    CraArticle: "Annex I Part II",
                    Remediation: "Ensure all dependencies are captured in the SBOM",
                    Justification: null,
                    Severity: PolicySeverity.Block));

            // --- Attack surface ---
            if (config.FailOnAttackSurfaceDepthOver.HasValue && report.MaxDependencyDepth.HasValue
                && report.MaxDependencyDepth.Value > config.FailOnAttackSurfaceDepthOver.Value)
                violations.Add(new PolicyViolation(
                    Rule: "FailOnAttackSurfaceDepthOver",
                    Message: $"Dependency tree depth {report.MaxDependencyDepth.Value} exceeds threshold {config.FailOnAttackSurfaceDepthOver.Value}",
                    CraArticle: "Annex I Part I(10)",
                    Remediation: "Reduce transitive dependency depth by replacing deeply nested packages",
                    Justification: null,
                    Severity: PolicySeverity.Block));

            // --- License policy ---
            if (packages is not null && (config.AllowedLicenses.Count > 0 || config.BlockedLicenses.Count > 0))
            {
                var licenseResult = LicensePolicyEvaluator.Evaluate(packages, config);
                foreach (var v in licenseResult.Violations)
                    violations.Add(new PolicyViolation(
                        Rule: "LicensePolicy",
                        Message: $"License policy: {v.PackageId} \u2014 {v.Reason}",
                        CraArticle: "Art. 13(6)",
                        Remediation: $"Replace {v.PackageId} with an alternative using an allowed license",
                        Justification: GetJustification(config, v.PackageId),
                        Severity: PolicySeverity.Block));
            }

            // --- Deprecated packages ---
            if (config.FailOnDeprecatedPackages && report.DeprecatedPackages.Count > 0)
            {
                foreach (var pkg in report.DeprecatedPackages)
                    violations.Add(new PolicyViolation(
                        Rule: "FailOnDeprecatedPackages",
                        Message: $"Deprecated package: {pkg}",
                        CraArticle: "Art. 13(8)",
                        Remediation: $"Replace {pkg} with a maintained alternative",
                        Justification: GetJustification(config, pkg),
                        Severity: PolicySeverity.Block));
            }

            // --- Minimum health score ---
            if (config.MinHealthScore.HasValue && report.MinPackageHealthScore.HasValue
                && report.MinPackageHealthScore.Value < config.MinHealthScore.Value)
            {
                var pkgName = report.MinHealthScorePackage ?? "unknown";
                violations.Add(new PolicyViolation(
                    Rule: "MinHealthScore",
                    Message: $"Package '{pkgName}' health score {report.MinPackageHealthScore.Value} below minimum {config.MinHealthScore.Value}",
                    CraArticle: "Art. 10(1)",
                    Remediation: $"Upgrade or replace {pkgName} to improve its health score",
                    Justification: GetJustification(config, pkgName),
                    Severity: PolicySeverity.Block));
            }

            // --- Minimum maintainers ---
            if (config.MinPackageMaintainers.HasValue && packages is not null)
            {
                foreach (var pkg in packages)
                {
                    if (pkg.MaintainerTrust is not null && pkg.MaintainerTrust.ContributorCount < config.MinPackageMaintainers.Value)
                        violations.Add(new PolicyViolation(
                            Rule: "MinPackageMaintainers",
                            Message: $"Package '{pkg.PackageId}' has {pkg.MaintainerTrust.ContributorCount} contributor(s), minimum required is {config.MinPackageMaintainers.Value}",
                            CraArticle: "Art. 13(5)",
                            Remediation: $"Evaluate alternatives for {pkg.PackageId} with broader maintainer base",
                            Justification: GetJustification(config, pkg.PackageId),
                            Severity: PolicySeverity.Block));
                }
            }
        }

        // --- Audit simulation findings (Critical + High = violations) ---
        if (auditResult is not null)
        {
            foreach (var finding in auditResult.Findings.Where(f => f.Severity is AuditSeverity.Critical or AuditSeverity.High))
                violations.Add(new PolicyViolation(
                    Rule: "AuditSimulation",
                    Message: $"Audit: {finding.ArticleReference} \u2014 {finding.Requirement}",
                    CraArticle: finding.ArticleReference,
                    Remediation: finding.Recommendation,
                    Justification: null,
                    Severity: PolicySeverity.Block));
        }

        // Determine exit code
        int exitCode;
        if (violations.Count > 0)
            exitCode = 2;
        else if (report.OverallComplianceStatus == CraComplianceStatus.NonCompliant)
            exitCode = 1;
        else
            exitCode = 0;

        return new PolicyEvaluationResult(violations, exitCode);
    }

    private static string? GetJustification(CraConfig config, string packageId)
    {
        return config.ComplianceNotes.TryGetValue(packageId, out var note) ? note : null;
    }
}
```

**Step 2: Build and run tests**

Run: `dotnet build --no-restore && dotnet test --no-build --verbosity quiet`
Expected: All 12 new tests pass, all existing tests pass

**Step 3: Commit**

```bash
git add src/DepSafe/Compliance/PolicyEvaluator.cs
git commit -m "feat: implement PolicyEvaluator with structured violations and CRA article mapping"
```

---

## Task 5: Write Package Exclusion Tests

**Files:**
- Modify: `tests/DepSafe.Tests/PolicyEvaluatorTests.cs` (add 3 tests)

**Step 1: Add 3 package exclusion tests at the bottom of PolicyEvaluatorTests (before helper methods)**

These tests verify the static helper method `PolicyEvaluator.FilterExcludedPackages` which we'll add to PolicyEvaluator in the next task:

```csharp
    [Fact]
    public void ExcludePackages_RemovedBeforeScoring()
    {
        var packages = new List<PackageHealth>
        {
            CreatePackage("KeepMe"),
            CreatePackage("DropMe"),
            CreatePackage("AlsoKeep")
        };
        var excludeList = new List<string> { "DropMe" };

        var filtered = PolicyEvaluator.FilterExcludedPackages(packages, excludeList);

        Assert.Equal(2, filtered.Count);
        Assert.DoesNotContain(filtered, p => p.PackageId == "DropMe");
    }

    [Fact]
    public void ExcludePackages_CaseInsensitive()
    {
        var packages = new List<PackageHealth>
        {
            CreatePackage("Newtonsoft.Json")
        };
        var excludeList = new List<string> { "newtonsoft.json" };

        var filtered = PolicyEvaluator.FilterExcludedPackages(packages, excludeList);

        Assert.Empty(filtered);
    }

    [Fact]
    public void ExcludePackages_EmptyList_NoEffect()
    {
        var packages = new List<PackageHealth>
        {
            CreatePackage("PkgA"),
            CreatePackage("PkgB")
        };

        var filtered = PolicyEvaluator.FilterExcludedPackages(packages, []);

        Assert.Equal(2, filtered.Count);
    }
```

**Step 2: Build (fails — FilterExcludedPackages not implemented yet)**

Run: `dotnet build --no-restore`
Expected: Build error

**Step 3: Commit**

```bash
git add tests/DepSafe.Tests/PolicyEvaluatorTests.cs
git commit -m "test: add 3 package exclusion tests"
```

---

## Task 6: Implement Package Exclusion

**Files:**
- Modify: `src/DepSafe/Compliance/PolicyEvaluator.cs` (add FilterExcludedPackages method)

**Step 1: Add FilterExcludedPackages to PolicyEvaluator**

Add this public static method at the bottom of PolicyEvaluator (before closing brace):

```csharp
    public static List<PackageHealth> FilterExcludedPackages(
        IReadOnlyList<PackageHealth> packages,
        IReadOnlyList<string> excludePackages)
    {
        if (excludePackages.Count == 0)
            return packages.ToList();

        var excluded = new HashSet<string>(excludePackages, StringComparer.OrdinalIgnoreCase);
        return packages.Where(p => !excluded.Contains(p.PackageId)).ToList();
    }
```

**Step 2: Build and run tests**

Run: `dotnet build --no-restore && dotnet test --no-build --verbosity quiet`
Expected: All 15 tests pass (12 evaluator + 3 exclusion), all existing tests pass

**Step 3: Commit**

```bash
git add src/DepSafe/Compliance/PolicyEvaluator.cs
git commit -m "feat: implement FilterExcludedPackages with case-insensitive matching"
```

---

## Task 7: Write Integration Test

**Files:**
- Modify: `tests/DepSafe.Tests/PolicyEvaluatorTests.cs` (add 1 integration test)

**Step 1: Add integration test**

```csharp
    [Fact]
    public void PolicyEvaluation_EndToEnd()
    {
        var config = new CraConfig
        {
            NoCriticalVulnerabilities = true,
            MinPackageMaintainers = 2,
            FailOnDeprecatedPackages = true,
            MinHealthScore = 50,
            AllowedLicenses = ["MIT", "Apache-2.0"],
            ComplianceNotes = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["OldPkg"] = "Planned for removal in v2.0"
            }
        };
        var report = CreateReport(
            criticalVulnerabilityCount: 1,
            deprecatedPackages: ["OldPkg"],
            minPackageHealthScore: 40,
            minHealthScorePackage: "WeakPkg");
        var packages = new List<PackageHealth>
        {
            CreatePackage("GoodPkg", contributorCount: 5, license: "MIT"),
            CreatePackage("SoloPkg", contributorCount: 1, license: "MIT"),
            CreatePackage("GplPkg", contributorCount: 3, license: "GPL-3.0")
        };

        var result = PolicyEvaluator.Evaluate(report, config, packages);

        // Should have: NoCriticalVulnerabilities, MinPackageMaintainers (SoloPkg),
        // FailOnDeprecatedPackages (OldPkg), MinHealthScore (WeakPkg), LicensePolicy (GplPkg)
        Assert.Equal(5, result.Violations.Count);
        Assert.Equal(2, result.ExitCode);

        // All violations should have CRA article references
        Assert.All(result.Violations, v => Assert.NotNull(v.CraArticle));

        // OldPkg should have justification from ComplianceNotes
        var deprecatedViolation = result.Violations.First(v => v.Rule == "FailOnDeprecatedPackages");
        Assert.Equal("Planned for removal in v2.0", deprecatedViolation.Justification);
    }
```

**Step 2: Build and run tests**

Run: `dotnet build --no-restore && dotnet test --no-build --verbosity quiet`
Expected: All 16 tests pass, all existing tests pass

**Step 3: Commit**

```bash
git add tests/DepSafe.Tests/PolicyEvaluatorTests.cs
git commit -m "test: add end-to-end integration test for PolicyEvaluator"
```

---

## Task 8: Populate New CraReport Fields

**Files:**
- Modify: `src/DepSafe/Commands/CraReportCommand.cs` (populate CriticalVulnerabilityCount and MaxInactiveMonths)

**Context:** `CraReport` is constructed inside `CraReportGenerator.Generate()` at `src/DepSafe/Compliance/CraReportGenerator.cs`. But the fields are init-only, so they need to be set during construction. We need to find where `CraReport` is constructed and add the new fields.

**Step 1: Find CraReport construction**

Search for where `new CraReport` or `CriticalPackageCount =` is set. It's in `CraReportGenerator.cs` around line 587. Read that area to find the exact construction site.

The `CraReport` is built inside `CraReportGenerator.Generate()`. Add:
- `CriticalVulnerabilityCount` — count of vulnerabilities with Severity == "CRITICAL" from `_vulnerabilities` field
- `MaxInactiveMonths` — compute from `repoInfoMap` data already available in the generator

The `CraReportGenerator` already has `_vulnerabilities` (set via `SetVulnerabilities`) and maintenance data (set via `SetMaintenanceData`). Add these two new fields where the CraReport object is created.

For `CriticalVulnerabilityCount`: Count from `_vulnerabilities` where `Severity` equals "CRITICAL" (case-insensitive).

For `MaxInactiveMonths`: This needs to be computed from `repoInfoMap`. The easiest approach is to compute `MaxInactiveMonths` in the command pipeline (same place where `HasUnmaintainedPackages` is determined) and pass it to the generator via a new setter, or add it to the CraReport construction in the generator.

**Approach:** Add a `_maxInactiveMonths` field to `CraReportGenerator` with a public setter. Set it from the command pipeline where `HasUnmaintainedPackages` is already computed. Then include both new fields in the CraReport construction.

**Step 2: In `CraReportGenerator.cs`, add backing field and setter:**

Near the other backing fields (around `_trendSummary`, `_trendSnapshots`):
```csharp
private int? _maxInactiveMonths;

public void SetMaxInactiveMonths(int? months)
{
    _maxInactiveMonths = months;
}
```

**Step 3: In `CraReportGenerator.cs`, where CraReport is constructed (search for `CriticalPackageCount =`), add:**

```csharp
CriticalVulnerabilityCount = _vulnerabilities?.Count(v =>
    v.Severity?.Equals("CRITICAL", StringComparison.OrdinalIgnoreCase) == true) ?? 0,
MaxInactiveMonths = _maxInactiveMonths,
```

**Step 4: In `CraReportCommand.cs`, where `HasUnmaintainedPackages` is determined from `repoInfoMap` (in the maintenance data computation section), also compute `MaxInactiveMonths`:**

Search for where `report.HasUnmaintainedPackages` or unmaintained detection happens. It's in the `SetMaintenanceData` call flow. Look for where `daysSinceCommit > 730` or `unmaintained` lists are built.

Compute max inactive months from the same data:
```csharp
int? maxInactiveMonths = null;
// ... inside the repoInfoMap iteration where stale/unmaintained are computed:
var months = (int)((DateTime.UtcNow - info.LastCommitDate).TotalDays / 30.44);
if (!maxInactiveMonths.HasValue || months > maxInactiveMonths.Value)
    maxInactiveMonths = months;
// ... after the loop:
reportGenerator.SetMaxInactiveMonths(maxInactiveMonths);
```

Apply this in all code paths that compute maintenance data.

**Step 5: Build and run tests**

Run: `dotnet build --no-restore && dotnet test --no-build --verbosity quiet`
Expected: 0 warnings, all tests pass

**Step 6: Commit**

```bash
git add src/DepSafe/Compliance/CraReportGenerator.cs src/DepSafe/Commands/CraReportCommand.cs
git commit -m "feat: populate CriticalVulnerabilityCount and MaxInactiveMonths on CraReport"
```

---

## Task 9: Wire PolicyEvaluator into CraReportCommand

**Files:**
- Modify: `src/DepSafe/Commands/CraReportCommand.cs`

**Step 1: Replace EvaluateExitCode calls with PolicyEvaluator.Evaluate**

There are 2 call sites (lines 2308 and 3203):

```csharp
// OLD:
var (exitCode, violations) = EvaluateExitCode(craReport, config, allPackages, auditResultForExit);

// NEW:
var policyResult = PolicyEvaluator.Evaluate(craReport, config, allPackages, auditResultForExit);
var exitCode = policyResult.ExitCode;
var violations = policyResult.Violations.Select(v => v.Message).ToList();
```

**Step 2: Replace the inline violation display (the old bullet-point output) with the Spectre.Console table**

Delete the inline display logic from `EvaluateExitCode` and add a new `DisplayPolicyViolations` method:

```csharp
private static void DisplayPolicyViolations(PolicyEvaluationResult result)
{
    if (result.Violations.Count == 0)
        return;

    AnsiConsole.WriteLine();
    AnsiConsole.Write(new Rule("[red bold]CI/CD Policy Violations[/]").LeftJustified());

    var table = new Table()
        .Border(TableBorder.Rounded)
        .AddColumn(new TableColumn("Rule").NoWrap())
        .AddColumn(new TableColumn("Sev.").NoWrap())
        .AddColumn("Details")
        .AddColumn(new TableColumn("CRA Art.").NoWrap())
        .AddColumn("Remediation");

    foreach (var v in result.Violations)
    {
        var sevColor = v.Severity == PolicySeverity.Block ? "red" : "yellow";
        var sevLabel = v.Severity == PolicySeverity.Block ? "BLOCK" : "WARN";

        table.AddRow(
            $"[{sevColor}]{Markup.Escape(v.Rule)}[/]",
            $"[{sevColor} bold]{sevLabel}[/]",
            Markup.Escape(v.Message),
            v.CraArticle ?? "\u2014",
            Markup.Escape(v.Remediation ?? "\u2014"));

        if (v.Justification is not null)
            table.AddRow("", "", $"[dim]Justification: {Markup.Escape(v.Justification)}[/]", "", "");
    }

    AnsiConsole.Write(table);

    var blockCount = result.Violations.Count(v => v.Severity == PolicySeverity.Block);
    var warnCount = result.Violations.Count(v => v.Severity == PolicySeverity.Warn);
    var summary = new List<string>();
    if (blockCount > 0) summary.Add($"[red]{blockCount} blocking[/]");
    if (warnCount > 0) summary.Add($"[yellow]{warnCount} warnings[/]");
    AnsiConsole.MarkupLine($"\nSummary: {string.Join(", ", summary)} \u2014 exit code {result.ExitCode}");
}
```

**Step 3: Call DisplayPolicyViolations after PolicyEvaluator.Evaluate in both code paths**

Replace the old violation display with:
```csharp
var policyResult = PolicyEvaluator.Evaluate(craReport, config, allPackages, auditResultForExit);
DisplayPolicyViolations(policyResult);
var exitCode = policyResult.ExitCode;
var violations = policyResult.Violations.Select(v => v.Message).ToList();
```

**Step 4: Wire ExcludePackages filtering in each code path**

In each code path, after the `allPackages` list is assembled but before health scoring/vulnerability analysis, add:

```csharp
if (config?.ExcludePackages.Count > 0)
{
    var beforeCount = allPackages.Count;
    allPackages = PolicyEvaluator.FilterExcludedPackages(allPackages, config.ExcludePackages);
    if (beforeCount > allPackages.Count)
        AnsiConsole.MarkupLine($"[dim]Excluded {beforeCount - allPackages.Count} package(s) from analysis per .cra-config.json[/]");
}
```

Find the right insertion points:
- For ExecuteDotNetAsync: After the packages list is built from `allReferences`, before the health scoring loop
- For ExecuteNpmAsync: After `allDeps` is populated and packages list is built, before scoring
- For GenerateMixedReportAsync: After the combined `allPackages` list is created

**Step 5: Delete the old `EvaluateExitCode` method (lines 3215-3303)**

It is now replaced by `PolicyEvaluator.Evaluate`.

**Step 6: Build and run tests**

Run: `dotnet build --no-restore && dotnet test --no-build --verbosity quiet`
Expected: 0 warnings, all tests pass (including all 503 existing tests)

**Step 7: Commit**

```bash
git add src/DepSafe/Commands/CraReportCommand.cs
git commit -m "feat: wire PolicyEvaluator and ExcludePackages into command pipeline"
```

---

## Task 10: Update HTML Report — Policy Section and Excluded Packages

**Files:**
- Modify: `src/DepSafe/Compliance/CraReportGenerator.cs` (update SetPolicyViolations → SetPolicyEvaluation, add excluded packages data)
- Modify: `src/DepSafe/Compliance/CraReportGenerator.Sections.cs` (rewrite GeneratePolicyViolationsSection, add excluded packages card)

**Step 1: Update CraReportGenerator to accept PolicyEvaluationResult**

In `CraReportGenerator.cs`, replace the old fields and method:

```csharp
// OLD:
private LicensePolicyResult? _licensePolicyResult;
private CraConfig? _policyConfig;

public void SetPolicyViolations(LicensePolicyResult? licenseResult, CraConfig? config)
{
    _licensePolicyResult = licenseResult;
    _policyConfig = config;
}

// NEW:
private PolicyEvaluationResult? _policyEvaluation;
private List<string> _excludedPackages = [];
private Dictionary<string, string> _complianceNotes = new(StringComparer.OrdinalIgnoreCase);

public void SetPolicyEvaluation(
    PolicyEvaluationResult? result,
    IReadOnlyList<string>? excludedPackages = null,
    IReadOnlyDictionary<string, string>? complianceNotes = null)
{
    _policyEvaluation = result;
    if (excludedPackages is not null)
        _excludedPackages = excludedPackages.ToList();
    if (complianceNotes is not null)
        _complianceNotes = new Dictionary<string, string>(complianceNotes, StringComparer.OrdinalIgnoreCase);
}
```

Keep `_licensePolicyResult` and `_policyConfig` if they are referenced elsewhere, or migrate all references.

**Step 2: Update HasPolicyData and GetPolicyViolationCount**

```csharp
private bool HasPolicyData()
{
    return _policyEvaluation is not null;
}

private int GetPolicyViolationCount()
{
    return _policyEvaluation?.Violations.Count ?? 0;
}
```

**Step 3: Rewrite GeneratePolicyViolationsSection in CraReportGenerator.Sections.cs**

Replace the entire method body (lines 2001-2090) with a new implementation that renders the structured PolicyViolation table:

```csharp
private void GeneratePolicyViolationsSection(StringBuilder sb)
{
    sb.AppendLine("<div class=\"section-header\">");
    sb.AppendLine("  <h2>Policy Violations</h2>");
    sb.AppendLine("</div>");

    sb.AppendLine("<div class=\"info-box\">");
    sb.AppendLine("  <div class=\"info-box-title\">\u2139 What is this?</div>");
    sb.AppendLine("  <p>Your team has configured policy rules in .cra-config.json. This section shows which rules were violated. These are custom policies — not CRA legal requirements — but they represent your organization's standards.</p>");
    sb.AppendLine("</div>");

    // Excluded packages card (if any)
    if (_excludedPackages.Count > 0)
    {
        sb.AppendLine("<div class=\"card info-card\" style=\"margin-bottom: 16px;\">");
        sb.AppendLine($"  <h4>\u2139 {_excludedPackages.Count} package(s) excluded from analysis</h4>");
        sb.AppendLine("  <table class=\"policy-table\">");
        sb.AppendLine("    <thead><tr><th>Package</th><th>Justification</th></tr></thead>");
        sb.AppendLine("    <tbody>");
        foreach (var pkg in _excludedPackages)
        {
            var justification = _complianceNotes.TryGetValue(pkg, out var note)
                ? EscapeHtml(note)
                : "<em>No justification provided</em>";
            sb.AppendLine("      <tr>");
            sb.AppendLine($"        <td><strong>{EscapeHtml(pkg)}</strong></td>");
            sb.AppendLine($"        <td>{justification}</td>");
            sb.AppendLine("      </tr>");
        }
        sb.AppendLine("    </tbody>");
        sb.AppendLine("  </table>");
        sb.AppendLine("</div>");
    }

    if (_policyEvaluation is null || _policyEvaluation.Violations.Count == 0)
    {
        sb.AppendLine("<div class=\"card empty-state success\">");
        sb.AppendLine("  <div class=\"empty-icon\">\u2713</div>");
        sb.AppendLine("  <p>No policy violations found. All packages meet your configured rules.</p>");
        sb.AppendLine("</div>");
        return;
    }

    // Violations table
    sb.AppendLine("<div class=\"card\">");
    sb.AppendLine("  <table class=\"policy-table\">");
    sb.AppendLine("    <thead><tr><th>Rule</th><th>Severity</th><th>Details</th><th>CRA Article</th><th>Remediation</th></tr></thead>");
    sb.AppendLine("    <tbody>");
    foreach (var v in _policyEvaluation.Violations)
    {
        var sevClass = v.Severity == PolicySeverity.Block ? "risk-critical" : "risk-medium";
        var sevLabel = v.Severity == PolicySeverity.Block ? "BLOCK" : "WARN";
        sb.AppendLine($"      <tr class=\"{sevClass}\">");
        sb.AppendLine($"        <td><strong>{EscapeHtml(v.Rule)}</strong></td>");
        sb.AppendLine($"        <td>{sevLabel}</td>");
        sb.AppendLine($"        <td>{EscapeHtml(v.Message)}</td>");
        sb.AppendLine($"        <td>{EscapeHtml(v.CraArticle ?? "\u2014")}</td>");
        sb.AppendLine($"        <td>{EscapeHtml(v.Remediation ?? "\u2014")}</td>");
        sb.AppendLine("      </tr>");
        if (v.Justification is not null)
        {
            sb.AppendLine("      <tr>");
            sb.AppendLine($"        <td colspan=\"5\" style=\"color: var(--text-muted); font-style: italic; padding-left: 24px;\">Justification: {EscapeHtml(v.Justification)}</td>");
            sb.AppendLine("      </tr>");
        }
    }
    sb.AppendLine("    </tbody>");
    sb.AppendLine("  </table>");
    sb.AppendLine("</div>");
}
```

**Step 4: Update callers in CraReportCommand.cs**

Replace all `SetPolicyViolations(licenseResult, config)` calls with:
```csharp
// No longer call SetPolicyViolations — policy evaluation is unified
// The SetPolicyEvaluation call happens after PolicyEvaluator.Evaluate
reportGenerator.SetPolicyEvaluation(
    policyResult,
    config?.ExcludePackages,
    config?.ComplianceNotes);
```

Move this call to happen AFTER `PolicyEvaluator.Evaluate` but BEFORE `GenerateHtml`.

**Step 5: Update the nav badge to use red for violations present, green checkmark for clean**

In CraReportGenerator.cs, update the nav item rendering (around line 828-835):

```csharp
var policyCount = GetPolicyViolationCount();
var policyBadge = policyCount > 0
    ? $"<span class=\"nav-badge\" style=\"background: var(--danger)\">{policyCount}</span>"
    : "<span class=\"nav-badge\" style=\"background: var(--success)\">\u2713</span>";
```

**Step 6: Build and run tests**

Run: `dotnet build --no-restore && dotnet test --no-build --verbosity quiet`
Expected: 0 warnings, all tests pass

**Step 7: Commit**

```bash
git add src/DepSafe/Compliance/CraReportGenerator.cs src/DepSafe/Compliance/CraReportGenerator.Sections.cs src/DepSafe/Commands/CraReportCommand.cs
git commit -m "feat: upgrade HTML report with structured policy violations table and excluded packages card"
```

---

## Task 11: Final Build, Test, and Cleanup

**Step 1: Full build**

Run: `dotnet build --no-restore`
Expected: 0 warnings, 0 errors

**Step 2: Run all tests**

Run: `dotnet test --no-build --verbosity quiet`
Expected: 519+ tests pass (503 existing + 16 new), 0 failures

**Step 3: Delete old EvaluateExitCode method if not already removed**

Verify the old `EvaluateExitCode` method no longer exists:
- Search for `EvaluateExitCode` in `CraReportCommand.cs`
- If still present, delete it

**Step 4: Verify no references to old SetPolicyViolations remain**

Search for `SetPolicyViolations` across the codebase. All references should be replaced with `SetPolicyEvaluation`.

**Step 5: Final commit if any cleanup was needed**

```bash
git add -A
git commit -m "chore: remove deprecated EvaluateExitCode and SetPolicyViolations"
```
