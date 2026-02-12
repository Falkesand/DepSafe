# Security Budget Optimizer Enhancement — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Extend the Security Budget Optimizer to include non-vulnerability remediation items (deprecated, unmaintained, archived packages) and transitive pinning recommendations with parent chain context.

**Architecture:** Add `RemediationReason` enum and new optional fields to `RemediationRoadmapItem`. Add `PrioritizeMaintenanceItems()` to `RemediationPrioritizer`. Enhance `PrioritizeUpdates()` to set `DependencyType`, `ParentChain`, and `ActionText` for transitive packages. Wire both into `CraReportCommand`. Update HTML/CLI rendering to use `ActionText`.

**Tech Stack:** .NET 10, xUnit, NuGet.Versioning

---

## Existing Code Context

**Key files to understand before starting:**
- `src/DepSafe/Scoring/RemediationRoadmapItem.cs` — current model (all fields `required`, vulnerability-centric)
- `src/DepSafe/Scoring/RemediationPrioritizer.cs` — `PrioritizeUpdates()` static method, processes only packages with CVEs
- `src/DepSafe/Scoring/SecurityBudgetOptimizer.cs` — `Optimize()` uses `PriorityScore / EffortWeight` for ROI
- `src/DepSafe/Models/PackageHealth.cs` — has `DependencyType` field (Direct/Transitive)
- `src/DepSafe/Models/DependencyTree.cs` — tree with `Roots: List<DependencyTreeNode>`
- `src/DepSafe/Models/DependencyTreeNode.cs` — `PackageId`, `Version`, `Children`, `Depth`
- `src/DepSafe/Commands/CraReportCommand.cs` — wiring: `GenerateMixedReportAsync` (line ~2164) and `GenerateReportAsync` (line ~3071) call `PrioritizeUpdates()`. Both methods have `dependencyTrees`, `deprecatedPackages`, `repoInfoMap` in scope.
- `src/DepSafe/Compliance/CraReportGenerator.Sections.cs` — `GenerateSecurityBudgetSection()` renders "What To Do" column as hardcoded `"Upgrade {current} → {recommended}"`
- `tests/DepSafe.Tests/RemediationPrioritizerTests.cs` — 22 existing tests with `CreatePackage()` and `CreateVuln()` helpers
- `tests/DepSafe.Tests/SecurityBudgetOptimizerTests.cs` — 8 existing tests with `CreateItem()` helper

---

## Task 1: Add RemediationReason Enum and Extend Model

**Files:**
- Create: `src/DepSafe/Scoring/RemediationReason.cs`
- Modify: `src/DepSafe/Scoring/RemediationRoadmapItem.cs`

**Step 1: Create the RemediationReason enum**

Create `src/DepSafe/Scoring/RemediationReason.cs`:

```csharp
namespace DepSafe.Scoring;

/// <summary>
/// Categorizes why a package appears in the remediation roadmap.
/// </summary>
public enum RemediationReason
{
    /// <summary>Package has known CVEs affecting the installed version.</summary>
    Vulnerability,
    /// <summary>Package is marked deprecated by the registry.</summary>
    Deprecated,
    /// <summary>Package has no activity for 2+ years or is archived.</summary>
    Unmaintained,
    /// <summary>Package has too few maintainers (bus factor risk).</summary>
    LowBusFactor,
}
```

**Step 2: Extend RemediationRoadmapItem**

In `src/DepSafe/Scoring/RemediationRoadmapItem.cs`, change:

Before:
```csharp
public required string PackageId { get; init; }
public required string CurrentVersion { get; init; }
public required string RecommendedVersion { get; init; }
public required int CveCount { get; init; }
public required List<string> CveIds { get; init; }
public required int ScoreLift { get; init; }
public required UpgradeEffort Effort { get; init; }
```

After:
```csharp
public required string PackageId { get; init; }
public required string CurrentVersion { get; init; }
public string RecommendedVersion { get; init; } = "";
public int CveCount { get; init; }
public List<string> CveIds { get; init; } = [];
public int ScoreLift { get; init; }
public required UpgradeEffort Effort { get; init; }
```

Add these new properties after `UpgradeTiers`:

```csharp
/// <summary>Why this package appears in the roadmap.</summary>
public RemediationReason Reason { get; init; } = RemediationReason.Vulnerability;

/// <summary>Direct or transitive dependency.</summary>
public DependencyType DependencyType { get; init; } = DependencyType.Direct;

/// <summary>Parent dependency chain for transitives (e.g. "Newtonsoft.Json → yaml-parser").</summary>
public string? ParentChain { get; init; }

/// <summary>Human-readable action text (e.g. "Upgrade 1.0 → 2.0", "Replace deprecated package").</summary>
public string? ActionText { get; init; }
```

Note: `DependencyType` requires adding `using DepSafe.Models;` at the top of the file.

**Step 3: Build and verify no compilation errors**

Run: `dotnet build --no-restore`
Expected: 0 warnings, 0 errors. All 22 existing `RemediationPrioritizerTests` and 8 `SecurityBudgetOptimizerTests` still pass because existing callers set `CveCount`, `CveIds`, `ScoreLift` explicitly (they just become optional defaults now).

Run: `dotnet test --no-build --verbosity quiet`
Expected: All 519 tests pass.

**Step 4: Commit**

```bash
git add src/DepSafe/Scoring/RemediationReason.cs src/DepSafe/Scoring/RemediationRoadmapItem.cs
git commit -m "feat: add RemediationReason enum and extend RemediationRoadmapItem with optional fields"
```

---

## Task 2: Write Failing Tests for PrioritizeMaintenanceItems

**Files:**
- Modify: `tests/DepSafe.Tests/RemediationPrioritizerTests.cs`

**Step 1: Add 4 failing tests**

Add to `RemediationPrioritizerTests.cs` after the existing tests. Use the existing `CreatePackage()` helper.

```csharp
[Fact]
public void PrioritizeMaintenanceItems_DeprecatedPackage_ReturnsItem()
{
    var packages = new[] { CreatePackage("DeprecatedPkg") };
    var deprecated = new List<string> { "DeprecatedPkg" };

    var result = RemediationPrioritizer.PrioritizeMaintenanceItems(
        packages, deprecated, null);

    var item = Assert.Single(result);
    Assert.Equal("DeprecatedPkg", item.PackageId);
    Assert.Equal(RemediationReason.Deprecated, item.Reason);
    Assert.Equal(200, item.PriorityScore);
    Assert.Equal(UpgradeEffort.Major, item.Effort);
    Assert.Contains("deprecated", item.ActionText, StringComparison.OrdinalIgnoreCase);
}

[Fact]
public void PrioritizeMaintenanceItems_ArchivedPackage_ReturnsHigherPriority()
{
    var packages = new[] { CreatePackage("ArchivedPkg") };
    var repoInfoMap = new Dictionary<string, GitHubRepoInfo?>
    {
        ["ArchivedPkg"] = new GitHubRepoInfo
        {
            IsArchived = true,
            LastCommitDate = DateTime.UtcNow.AddYears(-3),
        },
    };

    var result = RemediationPrioritizer.PrioritizeMaintenanceItems(
        packages, [], repoInfoMap);

    var item = Assert.Single(result);
    Assert.Equal(RemediationReason.Unmaintained, item.Reason);
    Assert.Equal(300, item.PriorityScore);
    Assert.Contains("archived", item.ActionText, StringComparison.OrdinalIgnoreCase);
}

[Fact]
public void PrioritizeMaintenanceItems_NoIssues_ReturnsEmpty()
{
    var packages = new[] { CreatePackage("HealthyPkg") };
    var repoInfoMap = new Dictionary<string, GitHubRepoInfo?>
    {
        ["HealthyPkg"] = new GitHubRepoInfo
        {
            IsArchived = false,
            LastCommitDate = DateTime.UtcNow.AddDays(-30),
        },
    };

    var result = RemediationPrioritizer.PrioritizeMaintenanceItems(
        packages, [], repoInfoMap);

    Assert.Empty(result);
}

[Fact]
public void PrioritizeMaintenanceItems_AlsoInVulnRoadmap_Deduplicates()
{
    var packages = new[] { CreatePackage("DualPkg") };
    var deprecated = new List<string> { "DualPkg" };
    var vulnRoadmapIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "DualPkg" };

    var result = RemediationPrioritizer.PrioritizeMaintenanceItems(
        packages, deprecated, null, vulnRoadmapIds);

    Assert.Empty(result);
}
```

Note: `GitHubRepoInfo` requires `using DepSafe.Models;` — check if already imported (it should be from existing `PackageHealth` usage). If `GitHubRepoInfo` needs more required fields, check the model and add defaults. The `PrioritizeMaintenanceItems` method doesn't exist yet, so this will fail to compile.

**Step 2: Verify tests fail to compile**

Run: `dotnet build`
Expected: CS0117 or similar — `RemediationPrioritizer` does not contain `PrioritizeMaintenanceItems`.

**Step 3: Commit failing tests**

```bash
git add tests/DepSafe.Tests/RemediationPrioritizerTests.cs
git commit -m "test: add 4 failing tests for PrioritizeMaintenanceItems"
```

---

## Task 3: Implement PrioritizeMaintenanceItems

**Files:**
- Modify: `src/DepSafe/Scoring/RemediationPrioritizer.cs`

**Step 1: Add the method**

Add after `PrioritizeUpdates()` in `RemediationPrioritizer.cs`:

```csharp
/// <summary>
/// Generate remediation items for non-vulnerability maintenance issues
/// (deprecated, unmaintained, archived packages).
/// </summary>
/// <param name="allPackages">All packages with health data.</param>
/// <param name="deprecatedPackages">Package IDs marked deprecated by registry.</param>
/// <param name="repoInfoMap">GitHub repo data keyed by package ID (nullable).</param>
/// <param name="excludePackageIds">Package IDs already in the vulnerability roadmap (for deduplication).</param>
public static List<RemediationRoadmapItem> PrioritizeMaintenanceItems(
    IReadOnlyList<PackageHealth> allPackages,
    IReadOnlyList<string> deprecatedPackages,
    IReadOnlyDictionary<string, GitHubRepoInfo?>? repoInfoMap,
    IReadOnlySet<string>? excludePackageIds = null)
{
    var items = new List<RemediationRoadmapItem>();
    var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
    if (excludePackageIds is not null)
    {
        foreach (var id in excludePackageIds)
            seen.Add(id);
    }

    // Build a quick lookup for package versions
    var packageLookup = new Dictionary<string, PackageHealth>(allPackages.Count, StringComparer.OrdinalIgnoreCase);
    foreach (var pkg in allPackages)
        packageLookup.TryAdd(pkg.PackageId, pkg);

    // 1. Deprecated packages
    var deprecatedSet = new HashSet<string>(deprecatedPackages, StringComparer.OrdinalIgnoreCase);
    foreach (var pkgId in deprecatedPackages)
    {
        if (!seen.Add(pkgId)) continue;
        packageLookup.TryGetValue(pkgId, out var pkg);
        items.Add(new RemediationRoadmapItem
        {
            PackageId = pkgId,
            CurrentVersion = pkg?.Version ?? "unknown",
            Effort = UpgradeEffort.Major,
            PriorityScore = 200,
            Reason = RemediationReason.Deprecated,
            ActionText = "Replace deprecated package",
        });
    }

    // 2. Unmaintained/archived packages (from repo info)
    if (repoInfoMap is not null)
    {
        foreach (var (pkgId, info) in repoInfoMap)
        {
            if (info is null || !seen.Add(pkgId)) continue;
            // Skip if also deprecated (already handled above with higher priority)
            if (deprecatedSet.Contains(pkgId)) continue;

            if (info.IsArchived)
            {
                packageLookup.TryGetValue(pkgId, out var pkg);
                items.Add(new RemediationRoadmapItem
                {
                    PackageId = pkgId,
                    CurrentVersion = pkg?.Version ?? "unknown",
                    Effort = UpgradeEffort.Major,
                    PriorityScore = 300,
                    Reason = RemediationReason.Unmaintained,
                    ActionText = "Replace archived dependency",
                });
            }
            else
            {
                var daysSince = (DateTime.UtcNow - info.LastCommitDate).TotalDays;
                if (daysSince > 730) // 2+ years
                {
                    int months = (int)(daysSince / 30.44);
                    packageLookup.TryGetValue(pkgId, out var pkg);
                    items.Add(new RemediationRoadmapItem
                    {
                        PackageId = pkgId,
                        CurrentVersion = pkg?.Version ?? "unknown",
                        Effort = UpgradeEffort.Major,
                        PriorityScore = 150,
                        Reason = RemediationReason.Unmaintained,
                        ActionText = $"Replace unmaintained dependency ({months} months inactive)",
                    });
                }
            }
        }
    }

    items.Sort((a, b) => b.PriorityScore.CompareTo(a.PriorityScore));
    return items;
}
```

Note: `GitHubRepoInfo` is in `DepSafe.Models` — add `using DepSafe.Models;` if not already present (it is — the file already imports it).

**Step 2: Build and run tests**

Run: `dotnet build --no-restore && dotnet test --no-build --verbosity quiet`
Expected: All tests pass including the 4 new ones.

**Step 3: Commit**

```bash
git add src/DepSafe/Scoring/RemediationPrioritizer.cs
git commit -m "feat: implement PrioritizeMaintenanceItems for deprecated and unmaintained packages"
```

---

## Task 4: Write Failing Tests for Transitive Parent Chain and ActionText

**Files:**
- Modify: `tests/DepSafe.Tests/RemediationPrioritizerTests.cs`

**Step 1: Add a helper to create dependency trees**

Add this helper at the top of the test class, after the existing helpers:

```csharp
private static DependencyTree CreateTree(params DependencyTreeNode[] roots) => new()
{
    ProjectPath = "/test",
    ProjectType = ProjectType.Sdk,
    Roots = roots.ToList(),
};

private static DependencyTreeNode CreateNode(
    string id, string version = "1.0.0", params DependencyTreeNode[] children) => new()
{
    PackageId = id,
    Version = version,
    DependencyType = children.Length > 0 ? DependencyType.Direct : DependencyType.Transitive,
    Depth = 0,
    Children = children.ToList(),
};
```

**Step 2: Add 3 failing tests**

```csharp
[Fact]
public void PrioritizeUpdates_TransitivePackage_SetsDependencyType()
{
    var packages = new[]
    {
        CreatePackage("DirectPkg", dependencyType: DependencyType.Direct),
        CreatePackage("TransitivePkg", dependencyType: DependencyType.Transitive),
    };
    var vulns = new Dictionary<string, List<VulnerabilityInfo>>
    {
        ["DirectPkg"] = [CreateVuln()],
        ["TransitivePkg"] = [CreateVuln()],
    };

    var result = RemediationPrioritizer.PrioritizeUpdates(
        packages, vulns, 50, EmptyCompliance);

    var directItem = result.First(r => r.PackageId == "DirectPkg");
    var transitiveItem = result.First(r => r.PackageId == "TransitivePkg");
    Assert.Equal(DependencyType.Direct, directItem.DependencyType);
    Assert.Equal(DependencyType.Transitive, transitiveItem.DependencyType);
}

[Fact]
public void PrioritizeUpdates_TransitivePackage_ResolvesParentChain()
{
    var packages = new[]
    {
        CreatePackage("TransitivePkg", dependencyType: DependencyType.Transitive),
    };
    var vulns = new Dictionary<string, List<VulnerabilityInfo>>
    {
        ["TransitivePkg"] = [CreateVuln()],
    };
    var tree = CreateTree(
        CreateNode("DirectPkg", "1.0.0",
            CreateNode("TransitivePkg")));

    var result = RemediationPrioritizer.PrioritizeUpdates(
        packages, vulns, 50, EmptyCompliance, dependencyTrees: [tree]);

    var item = Assert.Single(result);
    Assert.Equal("DirectPkg \u2192 TransitivePkg", item.ParentChain);
    Assert.Contains("Pin", item.ActionText);
    Assert.Contains("via", item.ActionText);
}

[Fact]
public void PrioritizeUpdates_DeepNesting_TruncatesParentChain()
{
    var packages = new[]
    {
        CreatePackage("DeepPkg", dependencyType: DependencyType.Transitive),
    };
    var vulns = new Dictionary<string, List<VulnerabilityInfo>>
    {
        ["DeepPkg"] = [CreateVuln()],
    };
    var tree = CreateTree(
        CreateNode("Root", "1.0.0",
            CreateNode("Mid1", "1.0.0",
                CreateNode("Mid2", "1.0.0",
                    CreateNode("Mid3", "1.0.0",
                        CreateNode("DeepPkg"))))));

    var result = RemediationPrioritizer.PrioritizeUpdates(
        packages, vulns, 50, EmptyCompliance, dependencyTrees: [tree]);

    var item = Assert.Single(result);
    Assert.Contains("Root", item.ParentChain);
    Assert.Contains("\u2026", item.ParentChain); // Ellipsis for truncation
    Assert.Contains("DeepPkg", item.ParentChain);
}
```

Note: The existing `CreatePackage()` helper doesn't have a `dependencyType` parameter. You'll need to add it:

Change `CreatePackage` to:
```csharp
private static PackageHealth CreatePackage(
    string id = "TestPkg",
    string version = "1.0.0",
    string? latestVersion = "2.0.0",
    bool hasKev = false,
    double? maxEpss = null,
    DependencyType dependencyType = DependencyType.Direct) => new()
{
    PackageId = id,
    Version = version,
    Score = 60,
    Status = HealthStatus.Watch,
    Metrics = new PackageMetrics { TotalDownloads = 1000 },
    LatestVersion = latestVersion,
    HasKevVulnerability = hasKev,
    MaxEpssProbability = maxEpss,
    DependencyType = dependencyType,
};
```

**Step 2: Verify tests fail**

Run: `dotnet build`
Expected: Fails — `PrioritizeUpdates` doesn't accept `dependencyTrees` parameter yet, and doesn't set `DependencyType`/`ParentChain`/`ActionText`.

**Step 3: Commit failing tests**

```bash
git add tests/DepSafe.Tests/RemediationPrioritizerTests.cs
git commit -m "test: add 3 failing tests for transitive parent chain and ActionText"
```

---

## Task 5: Implement Transitive Support in PrioritizeUpdates

**Files:**
- Modify: `src/DepSafe/Scoring/RemediationPrioritizer.cs`

**Step 1: Add `dependencyTrees` parameter to `PrioritizeUpdates`**

Change the signature from:
```csharp
public static List<RemediationRoadmapItem> PrioritizeUpdates(
    IReadOnlyList<PackageHealth> allPackages,
    IReadOnlyDictionary<string, List<VulnerabilityInfo>> allVulnerabilities,
    int currentCraScore,
    List<CraComplianceItem> currentComplianceItems,
    IReadOnlyDictionary<string, List<string>>? availableVersions = null)
```

To:
```csharp
public static List<RemediationRoadmapItem> PrioritizeUpdates(
    IReadOnlyList<PackageHealth> allPackages,
    IReadOnlyDictionary<string, List<VulnerabilityInfo>> allVulnerabilities,
    int currentCraScore,
    List<CraComplianceItem> currentComplianceItems,
    IReadOnlyDictionary<string, List<string>>? availableVersions = null,
    IReadOnlyList<DependencyTree>? dependencyTrees = null)
```

**Step 2: Build parent chain lookup**

At the start of `PrioritizeUpdates`, after the `items` declaration, add:

```csharp
// Build parent chain lookup for transitive packages
var parentChainLookup = dependencyTrees is not null
    ? BuildParentChainLookup(dependencyTrees)
    : new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
```

**Step 3: Set DependencyType, ParentChain, ActionText on each item**

In the `items.Add(new RemediationRoadmapItem { ... })` block (around line 118-132), add these properties:

```csharp
DependencyType = pkg.DependencyType,
ParentChain = pkg.DependencyType == DependencyType.Transitive
    ? parentChainLookup.GetValueOrDefault(pkg.PackageId)
    : null,
ActionText = pkg.DependencyType == DependencyType.Transitive
    ? $"Pin {pkg.PackageId} to {recommendedVersion}"
        + (parentChainLookup.TryGetValue(pkg.PackageId, out var chain) ? $" (via {chain})" : "")
    : $"Upgrade {pkg.Version} \u2192 {recommendedVersion}",
```

**Step 4: Add the BuildParentChainLookup and FindPath helper methods**

Add these private methods at the end of the class:

```csharp
/// <summary>
/// Build a lookup mapping transitive package IDs to their parent chain strings.
/// Example: "DirectPkg → IntermediatePkg → TransitivePkg"
/// Chains longer than 3 nodes are truncated with "…".
/// </summary>
private static Dictionary<string, string> BuildParentChainLookup(
    IReadOnlyList<DependencyTree> trees)
{
    var lookup = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

    foreach (var tree in trees)
    {
        foreach (var root in tree.Roots)
        {
            var path = new List<string> { root.PackageId };
            CollectParentChains(root, path, lookup);
        }
    }

    return lookup;
}

private static void CollectParentChains(
    DependencyTreeNode node,
    List<string> path,
    Dictionary<string, string> lookup)
{
    foreach (var child in node.Children)
    {
        path.Add(child.PackageId);

        // Only record for transitive nodes (depth > 0 in path means it has a parent)
        if (path.Count > 1 && !lookup.ContainsKey(child.PackageId))
        {
            lookup[child.PackageId] = FormatParentChain(path);
        }

        CollectParentChains(child, path, lookup);
        path.RemoveAt(path.Count - 1);
    }
}

private static string FormatParentChain(List<string> path)
{
    const int maxNodes = 3;
    if (path.Count <= maxNodes)
        return string.Join(" \u2192 ", path);

    // Show first, ellipsis, last
    return $"{path[0]} \u2192 \u2026 \u2192 {path[^1]}";
}
```

**Step 5: Build and run tests**

Run: `dotnet build --no-restore && dotnet test --no-build --verbosity quiet`
Expected: All tests pass including the 3 new transitive tests and all 22 existing tests (unchanged — they don't pass `dependencyTrees`, so it defaults to null).

**Step 6: Commit**

```bash
git add src/DepSafe/Scoring/RemediationPrioritizer.cs
git commit -m "feat: add transitive parent chain resolution and ActionText to PrioritizeUpdates"
```

---

## Task 6: Write Failing Tests for SecurityBudgetOptimizer Mixed Items

**Files:**
- Modify: `tests/DepSafe.Tests/SecurityBudgetOptimizerTests.cs`

**Step 1: Add 2 tests**

Add to `SecurityBudgetOptimizerTests.cs`. Use the existing `CreateItem()` helper — it already works since `CveCount` and `CveIds` are now optional:

```csharp
[Fact]
public void Optimize_MixedVulnAndMaintenance_SortsByRoi()
{
    var vulnItem = CreateItem(id: "VulnPkg", priorityScore: 500, effort: UpgradeEffort.Patch);
    var maintItem = CreateItem(id: "DeprecatedPkg", priorityScore: 200, effort: UpgradeEffort.Major);

    var result = SecurityBudgetOptimizer.Optimize([vulnItem, maintItem]);

    // VulnPkg: ROI = 500/1 = 500. DeprecatedPkg: ROI = 200/3 ≈ 67.
    Assert.Equal("VulnPkg", result.Items[0].Item.PackageId);
    Assert.Equal("DeprecatedPkg", result.Items[1].Item.PackageId);
}

[Fact]
public void Optimize_MaintenanceItemMajorEffort_LowerRoi()
{
    // Same priority score but Major effort should have lower ROI
    var patchItem = CreateItem(id: "PatchPkg", priorityScore: 300, effort: UpgradeEffort.Patch);
    var majorItem = CreateItem(id: "MajorPkg", priorityScore: 300, effort: UpgradeEffort.Major);

    var result = SecurityBudgetOptimizer.Optimize([patchItem, majorItem]);

    Assert.Equal("PatchPkg", result.Items[0].Item.PackageId);
    Assert.True(result.Items[0].RoiScore > result.Items[1].RoiScore);
}
```

**Step 2: Run tests — should pass immediately**

These tests don't need code changes since they use the existing optimizer. They just verify that maintenance items (which have Major effort) correctly get lower ROI.

Run: `dotnet test --no-build --verbosity quiet`
Expected: All tests pass.

**Step 3: Commit**

```bash
git add tests/DepSafe.Tests/SecurityBudgetOptimizerTests.cs
git commit -m "test: add 2 tests for mixed vulnerability and maintenance items in optimizer"
```

---

## Task 7: Wire PrioritizeMaintenanceItems into CraReportCommand

**Files:**
- Modify: `src/DepSafe/Commands/CraReportCommand.cs`

**Step 1: Update both call sites to pass dependencyTrees**

In `GenerateMixedReportAsync` (~line 2164), change:
```csharp
roadmap = RemediationPrioritizer.PrioritizeUpdates(allPackages, allVulnerabilities, craReport.CraReadinessScore, craReport.ComplianceItems, availableVersions);
```
To:
```csharp
roadmap = RemediationPrioritizer.PrioritizeUpdates(allPackages, allVulnerabilities, craReport.CraReadinessScore, craReport.ComplianceItems, availableVersions, dependencyTrees);
```

In `GenerateReportAsync` (~line 3071), change:
```csharp
roadmap = RemediationPrioritizer.PrioritizeUpdates(allPackages, allVulnerabilities, craReport.CraReadinessScore, craReport.ComplianceItems, availableVersions);
```
To:
```csharp
roadmap = RemediationPrioritizer.PrioritizeUpdates(allPackages, allVulnerabilities, craReport.CraReadinessScore, craReport.ComplianceItems, availableVersions, dependencyTree is not null ? [dependencyTree] : null);
```

Note: `GenerateMixedReportAsync` has `List<DependencyTree> dependencyTrees` parameter. `GenerateReportAsync` has `DependencyTree? dependencyTree` (singular). Wrap the singular one in a list.

**Step 2: Add PrioritizeMaintenanceItems calls**

In `GenerateMixedReportAsync`, after the `PrioritizeUpdates` line and before `reportGenerator.SetRemediationRoadmap(roadmap);`, add:

```csharp
var vulnPackageIds = new HashSet<string>(roadmap.Select(r => r.PackageId), StringComparer.OrdinalIgnoreCase);
var maintenanceItems = RemediationPrioritizer.PrioritizeMaintenanceItems(
    allPackages, deprecatedPackages ?? [], repoInfoMap, vulnPackageIds);
roadmap.AddRange(maintenanceItems);
```

In `GenerateReportAsync`, add the same block after `PrioritizeUpdates` and before `SetRemediationRoadmap`:

```csharp
var vulnPackageIds = new HashSet<string>(roadmap.Select(r => r.PackageId), StringComparer.OrdinalIgnoreCase);
var maintenanceItems = RemediationPrioritizer.PrioritizeMaintenanceItems(
    allPackages, deprecatedPackages ?? [], repoInfoMap, vulnPackageIds);
roadmap.AddRange(maintenanceItems);
```

**Step 3: Build and run tests**

Run: `dotnet build --no-restore && dotnet test --no-build --verbosity quiet`
Expected: All tests pass.

**Step 4: Commit**

```bash
git add src/DepSafe/Commands/CraReportCommand.cs
git commit -m "feat: wire PrioritizeMaintenanceItems and dependency trees into command pipeline"
```

---

## Task 8: Update HTML and CLI Rendering to Use ActionText

**Files:**
- Modify: `src/DepSafe/Compliance/CraReportGenerator.Sections.cs`
- Modify: `src/DepSafe/Commands/CraReportCommand.cs`

**Step 1: Update HTML "What To Do" column**

In `GenerateSecurityBudgetSection` at `src/DepSafe/Compliance/CraReportGenerator.Sections.cs`, find the two lines that render the "What To Do" column (lines ~1966 and ~1989):

Change (high-ROI table):
```csharp
sb.AppendLine($"        <td>Upgrade {EscapeHtml(item.Item.CurrentVersion)} \u2192 {EscapeHtml(item.Item.RecommendedVersion)}</td>");
```
To:
```csharp
sb.AppendLine($"        <td>{EscapeHtml(item.Item.ActionText ?? $"Upgrade {item.Item.CurrentVersion} \u2192 {item.Item.RecommendedVersion}")}</td>");
```

Change (low-ROI table) the same way — same replacement for the second occurrence.

**Step 2: Update HTML "CVEs Fixed" column for non-vuln items**

In both the high-ROI and low-ROI table rows, the `{item.Item.CveCount}` column should show a dash for non-vulnerability items:

Change:
```csharp
sb.AppendLine($"        <td>{item.Item.CveCount}</td>");
```
To:
```csharp
sb.AppendLine($"        <td>{(item.Item.CveCount > 0 ? item.Item.CveCount.ToString() : "\u2014")}</td>");
```

Apply this change in both the high-ROI and low-ROI table blocks.

**Step 3: Build and run tests**

Run: `dotnet build --no-restore && dotnet test --no-build --verbosity quiet`
Expected: All tests pass.

**Step 4: Commit**

```bash
git add src/DepSafe/Compliance/CraReportGenerator.Sections.cs
git commit -m "feat: update HTML rendering to use ActionText and handle non-vulnerability items"
```

---

## Task 9: Add HTML Rendering Test

**Files:**
- Modify: `tests/DepSafe.Tests/CraReportGeneratorTests.cs`

**Step 1: Add test for ActionText rendering**

Find the existing `GenerateHtml_SecurityBudgetWithItems_RendersTieredTables` test for reference. Add a new test after it:

```csharp
[Fact]
public void GenerateHtml_SecurityBudgetWithMaintenanceItems_RendersActionText()
{
    var generator = CreateGenerator();
    generator.SetSecurityBudget(new SecurityBudgetResult
    {
        Items =
        [
            new TieredRemediationItem
            {
                Item = new RemediationRoadmapItem
                {
                    PackageId = "OldPkg",
                    CurrentVersion = "1.0.0",
                    Effort = UpgradeEffort.Major,
                    PriorityScore = 200,
                    Reason = RemediationReason.Deprecated,
                    ActionText = "Replace deprecated package",
                },
                Tier = RemediationTier.HighROI,
                RoiScore = 67,
                CumulativeRiskReductionPercent = 100,
            },
        ],
        TotalRiskScore = 200,
        HighROIRiskReduction = 200,
        HighROIPercentage = 100,
    });

    var html = generator.Generate(CreateHealthReport(), CreateVulnerabilities(), CreateSbom(), CreateVex(), DateTime.UtcNow);

    Assert.Contains("Replace deprecated package", html);
    Assert.Contains("\u2014", html); // Em-dash for 0 CVEs
}
```

Note: This test requires the same helper methods used in other `CraReportGeneratorTests`. Check what `CreateGenerator()`, `CreateHealthReport()`, `CreateVulnerabilities()`, `CreateSbom()`, and `CreateVex()` look like. If they don't exist by those exact names, use whatever factory helpers are in the test file. Read the test file to find the correct helper names.

**Step 2: Run tests**

Run: `dotnet test --no-build --verbosity quiet`
Expected: All tests pass.

**Step 3: Commit**

```bash
git add tests/DepSafe.Tests/CraReportGeneratorTests.cs
git commit -m "test: add HTML rendering test for maintenance items with ActionText"
```

---

## Task 10: Final Build and Verification

**Step 1: Full build**

Run: `dotnet build --no-incremental`
Expected: 0 warnings, 0 errors.

**Step 2: Run all tests**

Run: `dotnet test --no-build`
Expected: All tests pass (519 existing + ~9 new = ~528).

**Step 3: Verify git log**

Run: `git log --oneline feature/security-budget-optimizer --not main`
Expected: ~9 commits.
