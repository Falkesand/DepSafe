# Reachability / Code Path Awareness — Design Document

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:writing-plans to create the implementation plan from this design.

**Goal:** Determine whether vulnerable packages are actually imported in application source code and display reachability status on vulnerability cards in the CRA report.

**Scope:** Import-level analysis (not function-level). Scans source files for `using`/`import`/`require` statements that reference vulnerable package names or namespaces.

**Scoring impact:** Display only — no changes to health scores, CRA readiness, or CI/CD thresholds.

---

## Architecture

### New Types

**`ReachabilityStatus` enum** (`src/DepSafe/Models/ReachabilityStatus.cs`)

```csharp
namespace DepSafe.Models;

public enum ReachabilityStatus
{
    Unknown,      // Source files not found or ecosystem not supported
    Reachable,    // Package namespace/name found in source imports
    Unreachable   // Source scanned, no import of this package found
}
```

**`ReachabilityAnalyzer`** (`src/DepSafe/Compliance/ReachabilityAnalyzer.cs`)

Static class with a single public entry point:

```csharp
public static Dictionary<string, ReachabilityStatus> Analyze(
    string projectDirectory,
    ProjectType projectType,
    IReadOnlyDictionary<string, List<VulnerabilityInfo>> vulnerabilities)
```

- Key = package ID (from `VulnerabilityInfo.PackageId`)
- Returns one status per unique vulnerable package (not per vulnerability)
- Packages without vulnerabilities are not analyzed

### VulnerabilityInfo Change

Add one mutable property to `VulnerabilityInfo`:

```csharp
public ReachabilityStatus Reachability { get; set; } = ReachabilityStatus.Unknown;
```

Uses `{ get; set; }` like the existing `EpssProbability`/`EpssPercentile` properties, since it's enriched after initial construction.

---

## Source File Scanning

### File Discovery

Discover source files recursively from the project directory (derived from the project file path already available in `CraReportCommand`).

**Extensions by ecosystem:**
- **.NET:** `*.cs` — exclude `bin/`, `obj/`, `Properties/`, `Migrations/`
- **npm:** `*.js`, `*.ts`, `*.jsx`, `*.tsx` — exclude `node_modules/`, `dist/`, `build/`

**Safety cap:** 5,000 files maximum. If exceeded, unmatched packages get `Unknown` (not `Unreachable`) since we can't be confident we scanned everything.

### Pattern Matching

**.NET** — scan each `.cs` file for `using` directives:
- `using {PackageId}` — prefix match (e.g., `using Newtonsoft.Json.Linq` matches package `Newtonsoft.Json`)
- `using static {PackageId}` — same prefix match
- Case-sensitive (C# namespaces are case-sensitive)

**.NET namespace heuristic:** Most NuGet packages use the package ID as the root namespace (~90%). For edge cases where they differ, the result naturally falls to `Unknown` — no false `Unreachable` since we just won't find a match in an unusual namespace. This is acceptable for import-level scope.

**npm** — scan each source file for:
- `require('package-name')` or `require("package-name")`
- `import ... from 'package-name'` or `from "package-name"`
- `import('package-name')` — dynamic imports
- Scoped packages: `@scope/name` matched exactly

**npm matching:** Exact package name match on the module specifier. Subpath imports like `import x from 'lodash/merge'` match `lodash` via starts-with on the specifier portion.

### Implementation Strategy

The analyzer reads file contents once and checks all vulnerable package names against each file, avoiding repeated I/O. Pseudocode:

```
1. Collect unique packageIds from vulnerabilities dictionary keys
2. Discover source files (respecting ecosystem + exclusion dirs + 5K cap)
3. For each file:
   a. Read content
   b. Extract import statements via regex
   c. For each import, check against packageId set (prefix for .NET, exact/startsWith for npm)
   d. Mark matched packages as Reachable
4. Any packages not matched: Unreachable (if under file cap) or Unknown (if cap hit)
```

---

## Integration into CraReportCommand

### Data Flow

In `CraReportCommand`, after `allVulnerabilities` is populated and version-filtered, before report generation:

```csharp
// Analyze reachability
var projectDir = Path.GetDirectoryName(projectFilePath)!;
var reachability = ReachabilityAnalyzer.Analyze(projectDir, projectType, allVulnerabilities);

// Enrich VulnerabilityInfo objects
foreach (var (packageId, vulns) in allVulnerabilities)
{
    if (reachability.TryGetValue(packageId, out var status))
    {
        foreach (var vuln in vulns)
            vuln.Reachability = status;
    }
}
```

This follows the same pattern as EPSS enrichment (`EnrichWithEpssScores`).

### CraReportGenerator Integration

Add a new setter for reachability summary data:

```csharp
public void SetReachabilityData(Dictionary<string, ReachabilityStatus> reachability)
{
    _reachabilityLookup = reachability;
}
```

The generator uses `_reachabilityLookup` when rendering:
- VEX vulnerability cards (reachability badge)
- Dependency Issues stats summary (reachable/unreachable/unknown counts)
- Remediation Roadmap entries (badge on each entry)

---

## HTML Display

### Vulnerability Card Badge

Each vulnerability card already shows a severity status badge and optional EPSS badge. The reachability badge goes in the `vuln-header` div, after the existing status badge:

```html
<span class="reachability-badge reachable" title="Package imported in source code">Reachable</span>
<span class="reachability-badge unreachable" title="Package not imported in source code">Unreachable</span>
<span class="reachability-badge unknown" title="Reachability could not be determined">Unknown</span>
```

### CSS (in `report-styles.css`)

Three badge variants using existing CSS variables:

```css
.reachability-badge {
    display: inline-block;
    padding: 2px 8px;
    border-radius: 4px;
    font-size: 0.75rem;
    font-weight: 600;
    text-transform: uppercase;
    margin-left: 8px;
}
.reachability-badge.reachable { background: var(--danger); color: white; }
.reachability-badge.unreachable { background: var(--success); color: white; }
.reachability-badge.unknown { background: var(--border-color); color: var(--text-secondary); }
```

### Stats Summary

The Dependency Issues section header gets a reachability summary line:

```
12 vulnerabilities (3 reachable, 5 unreachable, 4 unknown)
```

### No Changes To

- Health scores or `PackageHealth`
- CRA readiness score or compliance items
- CI/CD thresholds or exit codes
- Risk heatmap visualization
- SBOM output
- Typosquatting detection

---

## Testing Strategy

### Unit Tests: `ReachabilityAnalyzerTests.cs`

1. **.NET reachable** — `.cs` file with `using Newtonsoft.Json;` → package `Newtonsoft.Json` is `Reachable`
2. **.NET unreachable** — `.cs` file with no matching `using` → `Unreachable`
3. **.NET prefix match** — `using Newtonsoft.Json.Linq;` matches `Newtonsoft.Json`
4. **.NET case sensitivity** — `using newtonsoft.json;` does NOT match `Newtonsoft.Json`
5. **npm reachable (require)** — `require('lodash')` → `Reachable`
6. **npm reachable (import)** — `import x from 'lodash'` → `Reachable`
7. **npm subpath** — `import x from 'lodash/merge'` matches `lodash`
8. **npm scoped** — `import x from '@angular/core'` matches `@angular/core`
9. **npm unreachable** — no import found → `Unreachable`
10. **File cap exceeded** — 5001 files → unmatched packages get `Unknown`
11. **Empty vulnerabilities** — returns empty dictionary
12. **Excluded directories** — files in `bin/`, `node_modules/` are not scanned

### Integration Tests: `CraReportGeneratorTests.cs`

1. **Reachable badge rendered** — when reachability data has `Reachable` status
2. **Unreachable badge rendered** — when `Unreachable`
3. **No badge on Unknown** — or a dimmed gray badge
4. **Stats summary includes counts** — "N reachable, N unreachable"

---

## Decisions Log

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Analysis scope | Import-level | OSV lacks function data for .NET/npm; import scanning adds genuine signal without heavyweight compiler deps |
| Integration point | Enrich vulnerability cards | Fits existing data flow; badges are familiar UX pattern |
| Scoring impact | Display only | Import != invocation; false positive rate too high for score adjustment |
| Namespace mapping | Package ID = namespace heuristic | ~90% accurate for NuGet; edge cases fall to Unknown safely |
| File cap | 5,000 files | Bounds scan time; monorepos won't hang |
| Unknown semantics | "Could not determine" | Avoids false Unreachable when scanning is incomplete |
