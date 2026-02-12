# Phase 1.1: Policy as Code — Design Document

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Expand the existing CraConfig threshold system into a structured policy engine with new rules, human-readable violation output, package exclusion, compliance notes, and CRA article references.

**Architecture:** Enhance the typed CraConfig model with 3 new properties and wire 2 unused fields. Extract policy evaluation into a dedicated `PolicyEvaluator` static class that returns structured `PolicyViolation` records. Replace inline bullet-point output with a Spectre.Console table.

**Tech Stack:** .NET 10, System.Text.Json, Spectre.Console, xUnit

---

## 1. Policy Rule Model and New Rules

### New CraConfig Properties

| Property | Type | Default | CRA Article | Description |
|----------|------|---------|-------------|-------------|
| `NoCriticalVulnerabilities` | `bool` | `false` | Art. 10(6) | Exit code 2 if any critical-severity vulnerability exists |
| `MinPackageMaintainers` | `int?` | `null` | Art. 13(5) | Exit code 2 if any package has fewer than N contributors |
| `BlockUnmaintainedMonths` | `int?` | `null` | Art. 13(8) | Exit code 2 if any dependency inactive for N months. Takes precedence over `FailOnUnmaintainedPackages` when set |

### Wired Existing Fields

- **ExcludePackages** — Packages in this list are skipped during health scoring, vulnerability analysis, and policy evaluation. Applied after parsing, before scoring.
- **ComplianceNotes** — When a violation fires for a package with a compliance note, the note is shown as "Justification" in the output table.

### PolicyViolation Model

```csharp
public sealed record PolicyViolation(
    string Rule,           // e.g., "NoCriticalVulnerabilities"
    string Message,        // Human-readable description
    string? CraArticle,    // e.g., "Art. 10(6)"
    string? Remediation,   // e.g., "Upgrade Newtonsoft.Json to 13.0.4"
    string? Justification, // From ComplianceNotes if present
    PolicySeverity Severity);

public enum PolicySeverity { Block, Warn }
```

All existing `FailOn*` rules produce `Block` severity. Future work could add `Warn` to individual rules.

### PolicyEvaluationResult

```csharp
public sealed record PolicyEvaluationResult(
    List<PolicyViolation> Violations,
    int ExitCode);  // 0=pass, 1=non-compliant, 2=block violations exist
```

---

## 2. Package Exclusion Pipeline

Exclusion is applied at the earliest practical point — after package parsing, before health scoring and vulnerability analysis.

```csharp
if (config?.ExcludePackages.Count > 0)
{
    var excluded = new HashSet<string>(config.ExcludePackages, StringComparer.OrdinalIgnoreCase);
    packages = packages.Where(p => !excluded.Contains(p.Id)).ToList();
    AnsiConsole.MarkupLine($"[dim]Excluded {excluded.Count} package(s) from analysis per .cra-config.json[/]");
}
```

Applied in all three execution paths (DotNet, Npm, Mixed). Excluded packages:
- Are not scored by HealthScoreCalculator
- Are not checked for vulnerabilities via OSV
- Are not included in SBOM generation
- Do not appear in the HTML report
- Do not trigger any policy violations

Case-insensitive matching via `StringComparer.OrdinalIgnoreCase`.

### Config Example

```json
{
  "excludePackages": ["MyCompany.Internal.Utils", "TestHelpers"]
}
```

---

## 3. Policy Evaluation and Structured Output

### PolicyEvaluator

Static class at `Compliance/PolicyEvaluator.cs`. Replaces the inline `EvaluateExitCode` logic in `CraReportCommand`.

**Signature:**
```csharp
public static PolicyEvaluationResult Evaluate(
    CraReport report,
    CraConfig? config,
    IReadOnlyList<PackageHealth>? packages,
    AuditSimulationResult? auditResult)
```

### CRA Article Mapping

| Rule | CRA Article |
|------|-------------|
| FailOnKev | Art. 10(6) |
| FailOnEpssThreshold | Art. 10(6) |
| NoCriticalVulnerabilities | Art. 10(6) |
| FailOnVulnerabilityCount | Art. 10(6) |
| FailOnCraReadinessBelow | Art. 10(1) |
| FailOnReportableVulnerabilities | Art. 14 |
| FailOnUnpatchedDaysOver | Art. 11(4) |
| FailOnUnmaintainedPackages / BlockUnmaintainedMonths | Art. 13(8) |
| FailOnSbomCompletenessBelow | Annex I Part II |
| FailOnAttackSurfaceDepthOver | Annex I Part I(10) |
| MinPackageMaintainers | Art. 13(5) |
| FailOnDeprecatedPackages | Art. 13(8) |
| MinHealthScore | Art. 10(1) |
| AllowedLicenses / BlockedLicenses | Art. 13(6) |

### CLI Table Output (Spectre.Console)

```
┌───────────────────────────┬──────┬─────────┬───────────┬────────────┬───────────────────────────┐
│ Rule                      │ Sev. │ Actual  │ Threshold │ CRA Art.   │ Remediation               │
├───────────────────────────┼──────┼─────────┼───────────┼────────────┼───────────────────────────┤
│ NoCriticalVulnerabilities │ BLOCK│ 2 found │ 0         │ Art. 10(6) │ Upgrade pkg X to v1.2.3   │
│ MinPackageMaintainers     │ BLOCK│ 1       │ 2         │ Art. 13(5) │ Evaluate alternative pkgs │
└───────────────────────────┴──────┴─────────┴───────────┴────────────┴───────────────────────────┘
Summary: 2 blocking violations — exit code 2
```

Red rows for Block severity. Replaces the existing inline bullet-point output.

---

## 4. HTML Report Integration

### Excluded Packages Card

Added to the overview/summary section. Only rendered when `ExcludePackages` has entries. Collapsible info card with blue accent:

```html
<div class="card info-card collapsible">
  <h3>ℹ 2 packages excluded from analysis</h3>
  <table>
    <tr><td>MyCompany.Internal.Utils</td><td>Internal package, not distributed</td></tr>
    <tr><td>TestHelpers</td><td><em>No justification provided</em></td></tr>
  </table>
</div>
```

Justification column pulls from `ComplianceNotes` dictionary.

### Enhanced Policy Violations Section

Upgraded from plain text bullets to a structured table matching the CLI output:
- Columns: Rule, Severity, Details, CRA Article, Remediation
- Row color: red for Block, yellow for Warn (future)
- Justification shown as sub-row when present
- Nav badge: red with count if blocking violations, green checkmark if clean

### Data Flow

1. `CraReportCommand` calls `PolicyEvaluator.Evaluate(...)` -> `PolicyEvaluationResult`
2. Calls `reportGenerator.SetPolicyEvaluation(result, config.ExcludePackages, config.ComplianceNotes)`
3. Generator renders excluded packages card + violations table
4. Replaces current `SetPolicyViolations(licenseResult, config)` — license violations now part of unified result

No new CSS classes — reuses `.card`, `.info-card`, `.risk-high`, `.risk-critical`.

---

## 5. Testing Strategy

### PolicyEvaluator Tests (12 tests)

1. `NoCriticalVulnerabilities_WithCritical_ReturnsViolation`
2. `NoCriticalVulnerabilities_NoCritical_NoViolation`
3. `MinPackageMaintainers_BelowThreshold_ReturnsViolation`
4. `MinPackageMaintainers_MeetsThreshold_NoViolation`
5. `BlockUnmaintainedMonths_ExceedsThreshold_ReturnsViolation`
6. `BlockUnmaintainedMonths_TakesPrecedenceOverBool`
7. `ExistingFailOnRules_StillWork` — All 11 existing FailOn* gates produce correct PolicyViolation records
8. `ComplianceNotes_AttachedToViolation` — Package with note gets justification populated
9. `LicenseViolations_IncludedInResult` — AllowedLicenses/BlockedLicenses produce violations with Art. 13(6)
10. `NoConfig_ReturnsEmpty` — Null config returns zero violations
11. `MultipleViolations_AllCollected` — Multiple rules firing returns all violations
12. `Remediation_IncludesPackageDetails` — Violation includes upgrade hint

### Package Exclusion Tests (3 tests)

13. `ExcludePackages_RemovedBeforeScoring`
14. `ExcludePackages_CaseInsensitive`
15. `ExcludePackages_EmptyList_NoEffect`

### Integration Test (1 test)

16. `PolicyEvaluation_EndToEnd` — Config with multiple rules, verify exit code, violation count, CRA articles

**Total: 16 new tests. All 503 existing tests must continue passing.**
