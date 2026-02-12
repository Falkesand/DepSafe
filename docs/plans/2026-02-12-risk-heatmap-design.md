# Phase 3.1 Transitive Dependency Risk Heatmap — Design

## Context

The HTML report already has a tree-based dependency view (expand/collapse hierarchy) but lacks a visual graph showing how packages interconnect and where risk concentrates. A force-directed graph lets developers instantly spot high-risk hubs — packages that many others depend on with poor health or known vulnerabilities.

## Design Decisions

- **Vanilla JS + SVG**: No external libraries. A ~120-line Fruchterman-Reingold simulation embedded inline keeps the report self-contained and offline-capable. D3.js adds 260KB; we need only basic force layout.
- **Data reuse**: `_dependencyTrees`, `_healthLookup`, and `_parentLookup` already contain everything needed. No new data service or Set* method required — the graph section reads from existing caches populated by `SetDependencyTree()` and `SetHealthData()`.
- **Placement**: New section `risk-heatmap` in the "Compliance" nav group, between "Dependency Tree" and "Dependency Issues". Always visible when dependency trees exist.
- **Performance cap**: Flatten and deduplicate nodes. If >150 unique packages, show the top 80 by risk (health score ascending) plus their direct connections. Prevents SVG/simulation overload.

---

## Section 1: Graph Data Model (C# server-side)

### Flattening Logic

New private method `BuildGraphData()` in `CraReportGenerator.Sections.cs`:

1. Walk all `_dependencyTrees` recursively, collecting unique nodes by PackageId
2. For each node, record: `id`, `healthScore` (from `_healthLookup`), `hasVulnerabilities`, `hasKevVulnerability`, `depth`, `ecosystem`
3. For each parent→child edge, record: `source` (parent id), `target` (child id)
4. Compute `reverseDepCount` per node from `_parentLookup` (how many packages depend on it)
5. Deduplicate edges (same source→target pair)

### JSON Embedding

Emit the graph as inline JSON in a `<script>` tag:

```json
{
  "nodes": [
    { "id": "Newtonsoft.Json", "score": 42, "vuln": true, "kev": false, "depth": 1, "deps": 12, "eco": "nuget" },
    ...
  ],
  "edges": [
    { "source": "MyApp", "target": "Newtonsoft.Json" },
    ...
  ]
}
```

`deps` = reverse dependency count (how many packages depend on this one). `score` = health score (0-100, lower is worse).

---

## Section 2: Force-Directed Layout (Client-side JS)

### Simulation

Fruchterman-Reingold algorithm (~120 lines vanilla JS):

1. Initialize nodes at random positions within SVG viewport
2. Repulsive force between all node pairs: `F_rep = k² / d` (Coulomb-like)
3. Attractive force along edges: `F_att = d² / k` (spring-like)
4. `k = sqrt(area / nodeCount)` — optimal spacing
5. Temperature cooling: start at `width/10`, decay by 0.95 per iteration
6. Run 200 iterations synchronously on section activation (not on page load — only when user navigates to heatmap)

### Rendering

SVG elements:
- **Edges**: `<line>` with `stroke: var(--border-primary)`, `stroke-opacity: 0.3`
- **Nodes**: `<circle>` with:
  - `r` = `4 + sqrt(reverseDepCount) * 3` (clamped 4-30px)
  - `fill` = health score mapped: >=80 green (`--success`), 60-79 yellow (`--watch`), 40-59 orange (`--warning`), <40 red (`--danger`)
  - `stroke` = `var(--danger)` with `stroke-width: 3` if `hasVulnerabilities`, `stroke-width: 4` + dashed if `hasKevVulnerability`, else `none`
- **Labels**: `<text>` for nodes with `reverseDepCount >= 3` or `hasVulnerabilities` (avoids label clutter)
- **Tooltip**: Hovering shows package name, health score, vulnerability count, reverse dep count via a positioned `<div>`

### Interactivity

- **Drag**: mousedown/mousemove/mouseup on nodes, pin dragged node
- **Zoom**: wheel event scales SVG viewBox (scroll-to-zoom)
- **Hover**: highlight node + connected edges, dim others
- **Click**: scroll to package in Packages section
- **Legend**: color legend + size legend in top-right corner
- **Filter**: toggle NuGet/npm ecosystems (reuse ecosystem filter pattern)

---

## Section 3: CSS Styling

Add to `report-styles.css`:

```css
.risk-heatmap-container { position: relative; width: 100%; height: 600px; border: 1px solid var(--border-primary); border-radius: var(--radius); overflow: hidden; background: var(--bg-secondary); }
.risk-heatmap-container svg { width: 100%; height: 100%; }
.heatmap-tooltip { position: absolute; padding: 8px 12px; background: var(--bg-primary); border: 1px solid var(--border-primary); border-radius: var(--radius-sm); font-size: 0.8rem; pointer-events: none; opacity: 0; transition: opacity 0.15s; z-index: 10; }
.heatmap-legend { position: absolute; top: 12px; right: 12px; background: var(--bg-primary); border: 1px solid var(--border-primary); border-radius: var(--radius-sm); padding: 8px 12px; font-size: 0.75rem; }
```

Dark mode: inherits from existing CSS variable system (`[data-theme="dark"]`).

---

## Section 4: Integration & Empty State

### Nav Item

Add in "Compliance" group between "Dependency Tree" and "Dependency Issues":

```html
<li><a href="#" onclick="showSection('risk-heatmap')" data-section="risk-heatmap">
  <svg class="nav-icon" viewBox="0 0 24 24" ...>[grid/network icon]</svg>
  Risk Heatmap</a></li>
```

Always visible when `_dependencyTrees.Count > 0`.

### Section Rendering

```html
<section id="risk-heatmap" class="section">
  [GenerateRiskHeatmapSection()]
</section>
```

Between tree section and issues section in Generate().

### Empty State

If no dependency trees: show standard `card empty-state success` with "No dependency data available for visualization."

### Lazy Initialization

The force simulation runs only when the user navigates to the heatmap section (triggered by `showSection('risk-heatmap')`). This prevents startup overhead. The simulation result is cached — navigating away and back does not re-run it.

---

## Section 5: Testing (~8 tests)

**GraphDataBuilderTests** (4):
1. `FlattensTrees_UniqueNodes` — no duplicate PackageIds
2. `ComputesReverseDependencyCount_FromParentLookup`
3. `CapsAt80Nodes_WhenOver150Packages` — filtering works
4. `EmptyTree_ReturnsEmptyGraph`

**Integration** (4):
1. `GenerateHtml_WithDependencyTree_RendersHeatmapSection` — section present
2. `GenerateHtml_WithDependencyTree_EmbedsGraphJson` — JSON data block present
3. `GenerateHtml_NoDependencyTree_ShowsEmptyState`
4. `GenerateHtml_HeatmapNavItem_Visible`

Force simulation logic is pure math (deterministic with seed), but client-side JS — not unit-testable in xUnit. Verified manually via report inspection.

---

## Summary

| Component | Location | Lines (est.) |
|-----------|----------|-------------|
| Graph data builder | CraReportGenerator.Sections.cs | ~80 |
| Force simulation JS | CraReportGenerator.Scripts.cs | ~150 |
| SVG rendering JS | CraReportGenerator.Scripts.cs | ~100 |
| CSS | report-styles.css | ~30 |
| Nav + section wiring | CraReportGenerator.cs + .Sections.cs | ~30 |
| Tests | RiskHeatmapTests.cs | ~120 |
| **Total** | | **~510** |
