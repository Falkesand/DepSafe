# Design: Security Debt Trend (Phase 2.3)

## Problem

DepSafe generates a point-in-time compliance snapshot on each run. Teams cannot see whether their security posture is improving or degrading over time. Without historical context, a CRA readiness score of 72 tells you nothing about trajectory — are you climbing from 60 or sliding from 85? The CRA requires continuous vulnerability handling (Art. 11(4)), but no tooling tracks whether "continuous" is actually happening.

## Solution

Add `--snapshot` flag to `cra-report`. When active, save a lightweight project-level snapshot to disk and compare against prior snapshots to produce trend deltas. Trends appear as a CLI table and a new HTML report section with SVG sparklines.

## Snapshot Storage

### Location

`%LocalAppData%/DepSafe/snapshots/{project-hash}/` where project-hash is SHA256 of the normalized project path (first 12 hex chars).

### File Naming

`{ISO-timestamp}.json` (e.g., `2026-02-12T143022Z.json`). Lexicographic sort = chronological order. No index file needed.

### Size

~200 bytes per snapshot. A year of daily CI runs = ~73KB.

## Models

### TrendSnapshot

```csharp
// File: src/DepSafe/Models/TrendSnapshot.cs
public sealed record TrendSnapshot(
    DateTime CapturedAt,
    string ProjectPath,
    int HealthScore,
    int CraReadinessScore,
    int VulnerabilityCount,
    int CriticalPackageCount,
    int ReportableVulnerabilityCount,
    int? MaxUnpatchedVulnerabilityDays,
    int? SbomCompletenessPercentage,
    int? MaxDependencyDepth,
    bool HasUnmaintainedPackages,
    int PackageCount,
    int TransitivePackageCount);
```

### TrendDirection

```csharp
// File: src/DepSafe/Models/TrendDirection.cs
public enum TrendDirection { Improving, Stable, Degrading }
```

### TrendMetric

```csharp
// File: src/DepSafe/Models/TrendMetric.cs
public sealed record TrendMetric(
    string Name,
    int CurrentValue,
    int? PreviousValue,
    int? Delta,
    TrendDirection Direction,
    bool HigherIsBetter);
```

### TrendSummary

```csharp
// File: src/DepSafe/Models/TrendSummary.cs
public sealed record TrendSummary(
    List<TrendMetric> Metrics,
    int SnapshotCount,
    DateTime? FirstSnapshot,
    DateTime? LastSnapshot,
    TrendDirection OverallDirection);
```

## Persistence (TrendSnapshotStore)

Sealed class in `src/DepSafe/Persistence/TrendSnapshotStore.cs`. Uses `System.Text.Json` — no new dependencies.

```csharp
public sealed class TrendSnapshotStore
{
    public TrendSnapshotStore(string? basePath = null);  // defaults to %LocalAppData%/DepSafe/snapshots
    public async Task SaveAsync(TrendSnapshot snapshot, CancellationToken ct = default);
    public async Task<List<TrendSnapshot>> LoadAsync(string projectPath, int? maxCount = null, CancellationToken ct = default);
}
```

- `SaveAsync`: Creates directory if needed, serializes to `{timestamp}.json`.
- `LoadAsync`: Reads all `.json` files in the project directory, deserializes, sorts chronologically, returns last N if maxCount specified. Corrupted files are skipped with a stderr warning.

Project directory key: `SHA256(NormalizePath(projectPath))[0:12]`.

## Analysis (TrendAnalyzer)

Static class in `src/DepSafe/Scoring/TrendAnalyzer.cs`. Pure computation, no I/O.

```csharp
public static class TrendAnalyzer
{
    public static TrendSummary Analyze(IReadOnlyList<TrendSnapshot> snapshots);
}
```

### Delta Calculation

Compares the last snapshot (current) against the second-to-last (previous) for each of the 7 metrics.

### Direction Logic

Looks at the last N snapshots (up to 10). If 3+ consecutive moves in the same direction for a metric → `Improving` or `Degrading`. Otherwise → `Stable`.

### Tracked Metrics (7 total)

| Metric | Higher Is Better |
|--------|-----------------|
| Health Score | Yes |
| CRA Readiness Score | Yes |
| Vulnerability Count | No |
| Critical Package Count | No |
| Reportable Vulnerability Count | No |
| SBOM Completeness % | Yes |
| Max Unpatched Days | No |

### Overall Direction

Majority direction of the 7 metrics. Ties → `Stable`.

## CLI Output

Printed to console after the report path when `--snapshot` is active and 2+ snapshots exist. Uses Spectre.Console (already a dependency).

```
Security Debt Trend (5 snapshots, since 2026-01-15)

  Metric                      Current   Previous   Delta   Trend
  Health Score                    78         72       +6    ▲ Improving
  CRA Readiness Score             84         84        0    ● Stable
  Vulnerability Count              3          5       -2    ▲ Improving
  Critical Packages                0          1       -1    ▲ Improving
  Reportable Vulnerabilities       1          1        0    ● Stable
  SBOM Completeness              92%        88%       +4    ▲ Improving
  Max Unpatched Days              14         30      -16    ▲ Improving

  Overall: ▲ Improving
```

Direction indicators: `▲ Improving` (green), `● Stable` (blue), `▼ Degrading` (red).

## HTML Report Section

Rendered only when trend data exists (2+ snapshots).

### Navigation

"Security Debt Trend" nav item with chart icon. Badge shows overall direction arrow.

### Layout

1. **Summary card** — Overall direction with color. Text: "Security posture is improving over 5 snapshots since Jan 15, 2026."

2. **Sparkline charts** — One row per metric. Inline SVG polyline (last 10 data points) with current value and delta badge. No external charting library — pure server-side SVG generation. ~80px wide, colored by direction.

3. **History table** — Collapsible. Last 10 snapshots as rows, 7 metrics as columns. Most recent on top. Cells colored by delta direction.

### Empty State

When only 1 snapshot exists: card with "First snapshot recorded. Run again to see trends."

### CSS

New classes in `report-styles.css`: `.trend-sparkline`, `.trend-delta`, `.trend-card`, `.trend-improving`/`.trend-stable`/`.trend-degrading`. Uses existing `--success`/`--danger` CSS variables.

## Command Integration

### Flag

`--snapshot` on `cra-report`. No value needed — boolean flag.

### Data Flow

```
CraReportCommand
  → Generate CraReport as normal
  → Write report file
  → If --snapshot:
    1. Build TrendSnapshot from CraReport
    2. Load existing snapshots via TrendSnapshotStore.LoadAsync()
    3. Save current snapshot via TrendSnapshotStore.SaveAsync()
    4. Run TrendAnalyzer.Analyze() on all snapshots
    5. If 2+ snapshots: print CLI trend table
    6. Pass TrendSummary to reportGenerator.SetTrendData()
    7. Re-generate HTML to include trend section
```

### No New Command

Trends are a feature of `cra-report`, not a separate command.

## Scope

### In scope

- `--snapshot` flag on cra-report
- TrendSnapshot, TrendDirection, TrendMetric, TrendSummary models
- TrendSnapshotStore (JSON file persistence)
- TrendAnalyzer (delta + direction computation)
- CLI trend table via Spectre.Console
- HTML trend section with SVG sparklines and history table
- Unit tests for store, analyzer, and snapshot building

### Out of scope (YAGNI)

- Per-package trend tracking (project-level only)
- Automatic snapshot on every run (explicit `--snapshot` flag required)
- SQLite or database persistence
- External charting libraries (Chart.js, D3.js)
- Trend-based CI/CD thresholds (e.g., "fail if degrading")
- Snapshot pruning / retention policy
- Cross-project trend comparison
- Trend export as standalone report

## Testing

Unit tests:

**TrendSnapshotStoreTests** (6 tests):
1. Save and load round-trip — snapshot survives serialization
2. Load returns empty list for new project (no snapshot directory)
3. Multiple saves — loaded in chronological order
4. MaxCount parameter — returns only the N most recent
5. Different project paths — isolated snapshot directories
6. Corrupted JSON file — skipped gracefully, other snapshots still loaded

**TrendAnalyzerTests** (10 tests):
1. Empty snapshot list — returns empty metrics, null dates
2. Single snapshot — returns empty metrics (need 2+ for deltas)
3. Two snapshots — correct delta calculation for each metric
4. Higher-is-better metric improving — Direction = Improving
5. Lower-is-better metric decreasing — Direction = Improving (not Degrading)
6. Stable values across 3+ snapshots — Direction = Stable
7. 3 consecutive degrading moves — Direction = Degrading
8. Mixed directions — Direction = Stable (no clear trend)
9. Overall direction — majority of 7 metrics determines result
10. Null previous values (e.g., MaxUnpatchedDays) — Delta = null, Direction = Stable

**Integration test** (1 test):
11. Build TrendSnapshot from a CraReport — verify all fields mapped correctly

Total: 17 new tests.
