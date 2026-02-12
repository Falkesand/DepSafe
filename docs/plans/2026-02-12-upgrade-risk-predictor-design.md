# Phase 2.5 Upgrade Risk Predictor — Design

## Context

The remediation roadmap already computes multi-tier upgrade paths (Patch/Minor/Major) with CVE-fix counts per tier. MaintainerTrust scores exist per package. What's missing is a composite risk assessment that helps developers understand *how risky* each upgrade path is — beyond just the semver tier signal.

## Design Decisions

- **Changelog analysis**: Pattern matching on GitHub release note bodies for breaking/deprecation keywords. No NLP or LLM dependencies.
- **Display approach**: Enrich existing UpgradeTier rows in the remediation roadmap table. No new section.
- **Fetch scope**: Only fetch release notes for packages already in the roadmap (max 20). Minimizes API calls.

---

## Section 1: Data Model

### New Models

```csharp
public sealed record UpgradeRiskAssessment(
    int RiskScore,                    // 0-100 (0=safe, 100=very risky)
    UpgradeRiskLevel RiskLevel,       // Low/Medium/High/Critical
    int BreakingChangeSignals,        // Count of breaking keywords found
    int DeprecationSignals,           // Count of deprecation keywords found
    List<string> RiskFactors,         // Human-readable reasons
    int ReleasesBetween,              // Releases between current and target
    TimeSpan TimeBetween);            // Time gap between current and target

public enum UpgradeRiskLevel { Low, Medium, High, Critical }

public sealed record ReleaseNote(
    string TagName,
    string? Body,
    DateTime PublishedAt);

public sealed record ChangelogSignals(
    int BreakingChangeCount,
    int DeprecationCount,
    List<string> BreakingSnippets,
    List<string> DeprecationSnippets,
    int ReleaseCount);
```

### Changes to RemediationRoadmapItem

Add per-tier risk assessments:

```csharp
public Dictionary<string, UpgradeRiskAssessment>? TierRiskAssessments { get; init; }
```

Keyed by target version string. Null when no GitHub repo available (graceful degradation).

### Risk Score Formula (0-100)

| Factor | Weight | Calculation |
|--------|--------|-------------|
| Semver signal | 40% | Patch=0, Minor=25, Major=50 |
| Changelog signals | 35% | min(breaking*10 + deprecation*5, 100) |
| Stability | 15% | 100 - (trust?.Score ?? 50) |
| Time gap | 10% | min(days/730*100, 100) |

Risk levels: 0-25 Low, 26-50 Medium, 51-75 High, 76-100 Critical.

---

## Section 2: Changelog Fetching & Parsing

### GitHubApiClient Extension

New method to fetch release notes:

```csharp
public async Task<Result<List<ReleaseNote>>> GetReleaseNotesAsync(
    string owner, string repo, int count = 50, CancellationToken ct = default)
```

GraphQL query fetches `tagName`, `description`, `publishedAt` for last 50 releases. Uses existing `ResponseCache` (24h TTL). 50 releases covers the range between current and target versions for most packages.

### ChangelogAnalyzer (static class)

```csharp
public static ChangelogSignals Analyze(
    IReadOnlyList<ReleaseNote> releases,
    string fromVersion,
    string toVersion)
```

1. Filter releases to those between `fromVersion` and `toVersion` (parse tag names as NuGet versions).
2. Scan each body for keyword patterns (case-insensitive):
   - **Breaking**: `breaking`, `removed`, `renamed`, `incompatible`, `migration required`, `no longer supports`
   - **Deprecation**: `deprecated`, `obsolete`, `will be removed`, `end of life`
3. Return counts and matching snippets (truncated to first 50 chars each).

---

## Section 3: Risk Score Computation & Wiring

### UpgradeRiskCalculator (static class)

```csharp
public static UpgradeRiskAssessment Assess(
    UpgradeTier tier,
    ChangelogSignals? signals,
    MaintainerTrust? trust,
    int releasesBetween,
    TimeSpan timeBetween)
```

Builds human-readable `RiskFactors` list from inputs (e.g. "3 breaking changes detected", "Low maintainer trust (score: 25)", "18 months between versions").

### Wiring in CraReportCommand

After `PrioritizeUpdates()` and before `SetRemediationRoadmap()`:

1. Collect roadmap packages that have GitHubRepoInfo (owner/repo known)
2. Batch-fetch release notes via `GetReleaseNotesAsync()`
3. For each tier, run `ChangelogAnalyzer.Analyze()` + `UpgradeRiskCalculator.Assess()`
4. Attach `TierRiskAssessments` dictionary to roadmap item

Packages without GitHub repos get null assessment (no risk badge shown).

---

## Section 4: HTML Rendering & Testing

### HTML Changes

In `GenerateRemediationRoadmapSection`, enrich each tier row:

- Risk badge next to effort badge: `<span class="risk-badge low">Low Risk</span>`
- Colors: green (Low), yellow (Medium), orange (High), red (Critical)
- Risk factors shown as compact text below version transition
- Score indicator on recommended tier: `Risk: 23/100`
- No badge when assessment is null

### Testing (~12 tests)

**ChangelogAnalyzerTests** (5):
1. BreakingKeywords_CountsCorrectly
2. NoSignals_ReturnsZeroCounts
3. FiltersReleasesOutsideVersionRange
4. CaseInsensitiveMatching
5. EmptyReleaseBody_Skipped

**UpgradeRiskCalculatorTests** (5):
1. PatchWithNoSignals_LowRisk
2. MajorWithBreakingChanges_HighRisk
3. LowMaintainerTrust_IncreasesRisk
4. LongTimeGap_IncreasesRisk
5. NullSignals_UsesOnlySemverAndTrust

**Integration** (2):
1. GenerateHtml_RoadmapWithRiskAssessment_RendersRiskBadge
2. Optimize_RoadmapItemsWithRisk_PreservesAssessment
