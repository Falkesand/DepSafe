# Phase 1.4 Security Budget Optimizer — Design

## Context

The Security Budget Optimizer already exists with ROI-tiered remediation (SecurityBudgetOptimizer, TieredRemediationItem, HTML + CLI rendering, 8 tests). Two gaps remain:

1. **Non-vulnerability remediation items** — the optimizer only handles packages with CVEs. It doesn't suggest replacing unmaintained or deprecated packages.
2. **Transitive pinning recommendations** — no "pin transitive X" suggestions with parent chain context.

## Design Decisions

- **Model approach**: Extend existing `RemediationRoadmapItem` with a `RemediationReason` enum and optional fields. Keep one unified list, one optimizer, one table.
- **Transitive scope**: Vulnerable transitives only (data already available). No deep-scan requirement.
- **Action text**: Show parent chain for transitives ("Pin yaml-parser 2.1.4 via Newtonsoft.Json → yaml-parser").

---

## Section 1: Model Changes

### New Enum — `RemediationReason`

```csharp
public enum RemediationReason
{
    Vulnerability,  // Has CVEs (existing behavior)
    Deprecated,     // Marked deprecated by registry
    Unmaintained,   // No activity 2+ years or archived
    LowBusFactor    // Single maintainer
}
```

### Changes to `RemediationRoadmapItem`

- Add: `RemediationReason Reason { get; init; } = RemediationReason.Vulnerability`
- Add: `DependencyType DependencyType { get; init; } = DependencyType.Direct`
- Add: `string? ParentChain { get; init; }` — e.g. "Newtonsoft.Json → yaml-parser"
- Add: `string? ActionText { get; init; }` — human-readable action
- Change: `CveCount` from `required` to defaulted (`= 0`)
- Change: `CveIds` from `required` to defaulted (`= []`)

### Priority Scoring for Non-Vulnerability Items

| Reason | Base Priority Score |
|--------|-------------------|
| Archived | 300 |
| Deprecated | 200 |
| Unmaintained (2+ years stale) | 150 |
| LowBusFactor | 100 |

All use `Effort = Major` (replacing a package is typically a major change). Scaled by same Patch=1/Minor=2/Major=3 effort weights in optimizer.

---

## Section 2: Non-Vulnerability Item Generation

New static method on `RemediationPrioritizer`:

```csharp
public static List<RemediationRoadmapItem> PrioritizeMaintenanceItems(
    IReadOnlyList<PackageHealth> allPackages,
    IReadOnlyList<string> deprecatedPackages,
    IReadOnlyDictionary<string, GitHubRepoInfo?>? repoInfoMap)
```

### What It Generates

1. **Deprecated packages** — Reason=Deprecated, PriorityScore=200, Effort=Major, ActionText="Replace deprecated package"
2. **Unmaintained/archived packages** — from repoInfoMap: archived → PriorityScore=300, stale (2+ years) → PriorityScore=150, Effort=Major, ActionText="Replace archived dependency" or "Replace unmaintained dependency (N months inactive)"

### Deduplication

If a package already has CVEs (will appear in vulnerability roadmap), skip it in maintenance items. Deduplicate by package ID. Caller passes vulnerability roadmap package IDs as exclusion set.

### Wiring

In CraReportCommand, after `PrioritizeUpdates()`:

```csharp
var maintenanceItems = RemediationPrioritizer.PrioritizeMaintenanceItems(
    allPackages, deprecatedPackages ?? [], repoInfoMap);
roadmap.AddRange(maintenanceItems);
```

Then pass combined `roadmap` to `SecurityBudgetOptimizer.Optimize()` as before.

---

## Section 3: Transitive Vulnerability Pinning

### Changes to `PrioritizeUpdates()`

1. **New parameter**: `IReadOnlyList<DependencyTree>? dependencyTrees = null`
2. **Set DependencyType** on each item from `PackageHealth.DependencyType`
3. **Resolve parent chain** for transitives via dependency tree traversal
4. **Set ActionText**: Direct → "Upgrade {current} → {recommended}", Transitive → "Pin {packageId} to {recommended} (via {parentChain})"

### Parent Chain Resolution

```csharp
private static string? FindParentChain(
    string packageId,
    IReadOnlyList<DependencyTree> trees)
```

Walk each tree's nodes recursively. When packageId is found, return path from root. Max 3 levels (truncate with "…" if deeper). Cache lookup in Dictionary built once per call.

### Rendering

`ActionText` replaces the current hardcoded "Upgrade X → Y" in:
- HTML table "What To Do" column (CraReportGenerator.Sections.cs)
- CLI table (if ActionText is set, use it; otherwise fall back to existing format)

---

## Section 4: Testing Strategy

### New Tests (~10 total)

**RemediationPrioritizerTests** (existing file):
1. `PrioritizeMaintenanceItems_DeprecatedPackage_ReturnsItem`
2. `PrioritizeMaintenanceItems_ArchivedPackage_ReturnsHigherPriority`
3. `PrioritizeMaintenanceItems_NoIssues_ReturnsEmpty`
4. `PrioritizeMaintenanceItems_AlsoInVulnRoadmap_Deduplicates`
5. `PrioritizeUpdates_TransitivePackage_SetsDependencyType`
6. `PrioritizeUpdates_TransitivePackage_ResolvesParentChain`
7. `FindParentChain_DeepNesting_TruncatesAt3Levels`

**SecurityBudgetOptimizerTests** (existing file):
8. `Optimize_MixedVulnAndMaintenance_SortsByRoi`
9. `Optimize_MaintenanceItemMajorEffort_LowerRoi`

**CraReportGeneratorTests** (existing file):
10. `GenerateHtml_SecurityBudgetWithMaintenanceItems_RendersActionText`
