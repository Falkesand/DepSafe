# Risk Heatmap Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add an interactive force-directed dependency graph to the HTML report showing risk concentration across the dependency tree.

**Architecture:** C# server-side flattens dependency trees into a JSON graph (nodes + edges). Vanilla JS Fruchterman-Reingold simulation lays out the graph on section activation. SVG rendering with node size = reverse dep count, color = health score, border = vulnerability status.

**Tech Stack:** C# (data flattening, JSON embedding), Vanilla JS (force simulation, SVG rendering, interactivity), CSS (styling, dark mode via existing CSS variables)

---

### Task 1: Graph Data Model — C# Flattening Logic

Build the server-side graph data builder that flattens `DependencyTree` into a flat node+edge JSON structure.

**Files:**
- Create: `src/DepSafe/Compliance/GraphDataBuilder.cs`
- Test: `tests/DepSafe.Tests/GraphDataBuilderTests.cs`

**Context:**
- `CraReportGenerator` already has `_dependencyTrees` (line 1105), `_healthLookup` (line 1102), and `_parentLookup` (line 1106) in `CraReportGenerator.cs`
- `DependencyTreeNode` has `PackageId`, `Version`, `Depth`, `Children`, `HasVulnerabilities`, `HasKevVulnerability`, `Ecosystem`
- `_parentLookup` is `Dictionary<string, HashSet<string>>` mapping child → set of parents

**Step 1: Write 4 failing tests**

File: `tests/DepSafe.Tests/GraphDataBuilderTests.cs`

```csharp
using DepSafe.Compliance;
using DepSafe.Models;

namespace DepSafe.Tests;

public class GraphDataBuilderTests
{
    [Fact]
    public void Build_FlattensTrees_UniqueNodes()
    {
        // Same package "B" appears as child of both "A" and "C" — should produce 3 unique nodes
        var trees = new List<DependencyTree>
        {
            new()
            {
                ProjectPath = "test.csproj",
                ProjectType = ProjectType.DotNet,
                Roots = [
                    new DependencyTreeNode
                    {
                        PackageId = "A", Version = "1.0.0", Depth = 0,
                        DependencyType = DependencyType.Direct,
                        Children = [
                            new DependencyTreeNode
                            {
                                PackageId = "B", Version = "2.0.0", Depth = 1,
                                DependencyType = DependencyType.Transitive,
                            }
                        ]
                    },
                    new DependencyTreeNode
                    {
                        PackageId = "C", Version = "1.0.0", Depth = 0,
                        DependencyType = DependencyType.Direct,
                        Children = [
                            new DependencyTreeNode
                            {
                                PackageId = "B", Version = "2.0.0", Depth = 1,
                                DependencyType = DependencyType.Transitive,
                            }
                        ]
                    }
                ]
            }
        };
        var health = new Dictionary<string, PackageHealth>(StringComparer.OrdinalIgnoreCase)
        {
            ["A"] = MakeHealth("A", 90),
            ["B"] = MakeHealth("B", 40),
            ["C"] = MakeHealth("C", 75),
        };

        var (nodes, edges) = GraphDataBuilder.Build(trees, health);

        Assert.Equal(3, nodes.Count);
        Assert.Contains(nodes, n => n.Id == "A");
        Assert.Contains(nodes, n => n.Id == "B");
        Assert.Contains(nodes, n => n.Id == "C");
        // B's score comes from health lookup
        Assert.Equal(40, nodes.First(n => n.Id == "B").Score);
    }

    [Fact]
    public void Build_ComputesReverseDependencyCount()
    {
        // A→B, C→B — B has 2 reverse deps
        var trees = new List<DependencyTree>
        {
            new()
            {
                ProjectPath = "test.csproj",
                ProjectType = ProjectType.DotNet,
                Roots = [
                    new DependencyTreeNode
                    {
                        PackageId = "A", Version = "1.0.0", Depth = 0,
                        DependencyType = DependencyType.Direct,
                        Children = [
                            new DependencyTreeNode { PackageId = "B", Version = "1.0.0", Depth = 1, DependencyType = DependencyType.Transitive }
                        ]
                    },
                    new DependencyTreeNode
                    {
                        PackageId = "C", Version = "1.0.0", Depth = 0,
                        DependencyType = DependencyType.Direct,
                        Children = [
                            new DependencyTreeNode { PackageId = "B", Version = "1.0.0", Depth = 1, DependencyType = DependencyType.Transitive }
                        ]
                    }
                ]
            }
        };
        var health = new Dictionary<string, PackageHealth>(StringComparer.OrdinalIgnoreCase);

        var (nodes, edges) = GraphDataBuilder.Build(trees, health);

        Assert.Equal(2, nodes.First(n => n.Id == "B").ReverseDepCount);
        Assert.Equal(0, nodes.First(n => n.Id == "A").ReverseDepCount);
    }

    [Fact]
    public void Build_CapsAt80Nodes_WhenOver150Packages()
    {
        // Generate 160 root nodes, no children — should cap at 80
        var roots = Enumerable.Range(0, 160).Select(i =>
            new DependencyTreeNode
            {
                PackageId = $"Pkg{i}",
                Version = "1.0.0",
                Depth = 0,
                DependencyType = DependencyType.Direct,
            }).ToList();
        var trees = new List<DependencyTree>
        {
            new()
            {
                ProjectPath = "test.csproj",
                ProjectType = ProjectType.DotNet,
                Roots = roots,
            }
        };
        var health = new Dictionary<string, PackageHealth>(StringComparer.OrdinalIgnoreCase);
        // Give some nodes low health so they get prioritized
        for (var i = 0; i < 160; i++)
            health[$"Pkg{i}"] = MakeHealth($"Pkg{i}", i); // Pkg0=0, Pkg159=159

        var (nodes, _) = GraphDataBuilder.Build(trees, health);

        // Should keep top 80 by lowest health score (worst first) + their connections
        Assert.True(nodes.Count <= 80 + 10, $"Expected <= 90 nodes (80 + buffer for connections), got {nodes.Count}");
        // Lowest-health packages should be included
        Assert.Contains(nodes, n => n.Id == "Pkg0");
        Assert.Contains(nodes, n => n.Id == "Pkg10");
    }

    [Fact]
    public void Build_EmptyTree_ReturnsEmptyGraph()
    {
        var trees = new List<DependencyTree>();
        var health = new Dictionary<string, PackageHealth>(StringComparer.OrdinalIgnoreCase);

        var (nodes, edges) = GraphDataBuilder.Build(trees, health);

        Assert.Empty(nodes);
        Assert.Empty(edges);
    }

    private static PackageHealth MakeHealth(string id, int score) => new()
    {
        PackageId = id,
        Version = "1.0.0",
        Score = score,
        Status = score >= 80 ? HealthStatus.Healthy : score >= 60 ? HealthStatus.Watch : score >= 40 ? HealthStatus.Warning : HealthStatus.Critical,
        Metrics = new PackageMetrics(),
        Ecosystem = PackageEcosystem.NuGet,
        DependencyType = DependencyType.Direct,
    };
}
```

**Step 2: Run tests to verify they fail**

Run: `dotnet test tests/DepSafe.Tests --filter "FullyQualifiedName~GraphDataBuilderTests" --no-restore`
Expected: Build failure — `GraphDataBuilder` does not exist yet.

**Step 3: Write minimal implementation**

File: `src/DepSafe/Compliance/GraphDataBuilder.cs`

```csharp
using DepSafe.Models;

namespace DepSafe.Compliance;

/// <summary>
/// Flattens dependency trees into a node+edge graph for the risk heatmap visualization.
/// </summary>
public static class GraphDataBuilder
{
    private const int MaxNodesBeforeCap = 150;
    private const int CappedNodeCount = 80;

    public sealed record GraphNode(
        string Id,
        int Score,
        bool HasVulnerabilities,
        bool HasKevVulnerability,
        int Depth,
        int ReverseDepCount,
        string Ecosystem);

    public sealed record GraphEdge(string Source, string Target);

    public static (List<GraphNode> Nodes, List<GraphEdge> Edges) Build(
        IReadOnlyList<DependencyTree> trees,
        IReadOnlyDictionary<string, PackageHealth> healthLookup)
    {
        if (trees.Count == 0)
            return ([], []);

        var nodeMap = new Dictionary<string, GraphNode>(StringComparer.OrdinalIgnoreCase);
        var edgeSet = new HashSet<(string Source, string Target)>(
            new EdgeComparer());
        var parentLookup = new Dictionary<string, HashSet<string>>(StringComparer.OrdinalIgnoreCase);

        foreach (var tree in trees)
        {
            foreach (var root in tree.Roots)
            {
                CollectRecursive(root, null, nodeMap, edgeSet, parentLookup, healthLookup);
            }
        }

        // Update reverse dep counts from parent lookup
        var nodes = new List<GraphNode>();
        foreach (var kvp in nodeMap)
        {
            var reverseCount = parentLookup.TryGetValue(kvp.Key, out var parents) ? parents.Count : 0;
            nodes.Add(kvp.Value with { ReverseDepCount = reverseCount });
        }

        // Cap at CappedNodeCount if over MaxNodesBeforeCap
        if (nodes.Count > MaxNodesBeforeCap)
        {
            var topNodes = nodes
                .OrderBy(n => n.Score) // Worst health first
                .Take(CappedNodeCount)
                .ToList();

            var topIds = new HashSet<string>(topNodes.Select(n => n.Id), StringComparer.OrdinalIgnoreCase);

            // Also include direct connections of top nodes
            var connectedIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var edge in edgeSet)
            {
                if (topIds.Contains(edge.Source) && !topIds.Contains(edge.Target))
                    connectedIds.Add(edge.Target);
                if (topIds.Contains(edge.Target) && !topIds.Contains(edge.Source))
                    connectedIds.Add(edge.Source);
            }

            foreach (var connId in connectedIds)
            {
                var connNode = nodes.FirstOrDefault(n => string.Equals(n.Id, connId, StringComparison.OrdinalIgnoreCase));
                if (connNode is not null)
                    topNodes.Add(connNode);
            }

            nodes = topNodes;
        }

        var nodeIds = new HashSet<string>(nodes.Select(n => n.Id), StringComparer.OrdinalIgnoreCase);
        var edges = edgeSet
            .Where(e => nodeIds.Contains(e.Source) && nodeIds.Contains(e.Target))
            .Select(e => new GraphEdge(e.Source, e.Target))
            .ToList();

        return (nodes, edges);
    }

    private static void CollectRecursive(
        DependencyTreeNode node,
        string? parentId,
        Dictionary<string, GraphNode> nodeMap,
        HashSet<(string, string)> edgeSet,
        Dictionary<string, HashSet<string>> parentLookup,
        IReadOnlyDictionary<string, PackageHealth> healthLookup)
    {
        if (!nodeMap.ContainsKey(node.PackageId))
        {
            var score = healthLookup.TryGetValue(node.PackageId, out var health)
                ? health.Score
                : 50; // Default score when no health data

            nodeMap[node.PackageId] = new GraphNode(
                node.PackageId,
                score,
                node.HasVulnerabilities,
                node.HasKevVulnerability,
                node.Depth,
                0, // Will be updated after collection
                node.Ecosystem.ToString().ToLowerInvariant());
        }
        else
        {
            // Update vulnerability flags if they're true in this occurrence
            var existing = nodeMap[node.PackageId];
            if (node.HasVulnerabilities || node.HasKevVulnerability)
            {
                nodeMap[node.PackageId] = existing with
                {
                    HasVulnerabilities = existing.HasVulnerabilities || node.HasVulnerabilities,
                    HasKevVulnerability = existing.HasKevVulnerability || node.HasKevVulnerability,
                    Depth = Math.Min(existing.Depth, node.Depth),
                };
            }
        }

        if (parentId is not null)
        {
            edgeSet.Add((parentId, node.PackageId));

            if (!parentLookup.TryGetValue(node.PackageId, out var parents))
            {
                parents = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                parentLookup[node.PackageId] = parents;
            }
            parents.Add(parentId);
        }

        foreach (var child in node.Children)
        {
            CollectRecursive(child, node.PackageId, nodeMap, edgeSet, parentLookup, healthLookup);
        }
    }

    private sealed class EdgeComparer : IEqualityComparer<(string Source, string Target)>
    {
        public bool Equals((string Source, string Target) x, (string Source, string Target) y) =>
            string.Equals(x.Source, y.Source, StringComparison.OrdinalIgnoreCase) &&
            string.Equals(x.Target, y.Target, StringComparison.OrdinalIgnoreCase);

        public int GetHashCode((string Source, string Target) obj) =>
            HashCode.Combine(
                StringComparer.OrdinalIgnoreCase.GetHashCode(obj.Source),
                StringComparer.OrdinalIgnoreCase.GetHashCode(obj.Target));
    }
}
```

**Step 4: Run tests to verify they pass**

Run: `dotnet test tests/DepSafe.Tests --filter "FullyQualifiedName~GraphDataBuilderTests" --no-restore`
Expected: 4 tests pass.

**Step 5: Commit**

```bash
git add src/DepSafe/Compliance/GraphDataBuilder.cs tests/DepSafe.Tests/GraphDataBuilderTests.cs
git commit -m "feat: add GraphDataBuilder for risk heatmap data flattening"
```

---

### Task 2: CSS Styles for Risk Heatmap

Add CSS classes for the heatmap container, tooltip, and legend to `report-styles.css`.

**Files:**
- Modify: `src/DepSafe/Resources/report-styles.css` (append at end, after line 3133)

**Context:**
- CSS uses CSS variables: `--bg-primary`, `--bg-secondary`, `--border-primary`, `--radius`, `--radius-sm`, `--success`, `--watch`, `--warning`, `--danger`, `--accent`, `--card-bg`
- Dark mode handled automatically via `[data-theme="dark"]` CSS variable overrides
- No tests needed for CSS — verified via integration tests in Task 7

**Step 1: Add heatmap CSS**

Append to end of `src/DepSafe/Resources/report-styles.css`:

```css

/* ── Risk Heatmap ── */
.risk-heatmap-container {
    position: relative;
    width: 100%;
    height: 600px;
    border: 1px solid var(--border-primary);
    border-radius: var(--radius);
    overflow: hidden;
    background: var(--bg-secondary);
}
.risk-heatmap-container svg {
    width: 100%;
    height: 100%;
    cursor: grab;
}
.risk-heatmap-container svg:active {
    cursor: grabbing;
}
.risk-heatmap-container svg circle {
    cursor: pointer;
    transition: opacity 0.15s;
}
.risk-heatmap-container svg text {
    font-family: var(--font-mono, 'IBM Plex Mono', monospace);
    font-size: 10px;
    fill: var(--text-primary);
    pointer-events: none;
    user-select: none;
}
.heatmap-tooltip {
    position: absolute;
    padding: 8px 12px;
    background: var(--bg-primary);
    border: 1px solid var(--border-primary);
    border-radius: var(--radius-sm);
    font-size: 0.8rem;
    pointer-events: none;
    opacity: 0;
    transition: opacity 0.15s;
    z-index: 10;
    max-width: 280px;
    box-shadow: 0 2px 8px rgba(0,0,0,0.15);
}
.heatmap-tooltip.visible {
    opacity: 1;
}
.heatmap-tooltip .tt-name {
    font-weight: 600;
    margin-bottom: 4px;
}
.heatmap-tooltip .tt-row {
    display: flex;
    justify-content: space-between;
    gap: 12px;
    font-size: 0.75rem;
    color: var(--text-secondary);
}
.heatmap-legend {
    position: absolute;
    top: 12px;
    right: 12px;
    background: var(--bg-primary);
    border: 1px solid var(--border-primary);
    border-radius: var(--radius-sm);
    padding: 10px 14px;
    font-size: 0.75rem;
    line-height: 1.6;
    z-index: 5;
    opacity: 0.92;
}
.heatmap-legend-title {
    font-weight: 600;
    margin-bottom: 4px;
}
.heatmap-legend-item {
    display: flex;
    align-items: center;
    gap: 6px;
}
.heatmap-legend-swatch {
    width: 12px;
    height: 12px;
    border-radius: 50%;
    flex-shrink: 0;
}
.heatmap-controls {
    display: flex;
    gap: 8px;
    margin-bottom: 12px;
    flex-wrap: wrap;
    align-items: center;
}
.heatmap-controls .tree-btn {
    /* Reuses existing tree-btn style */
}
```

**Step 2: Commit**

```bash
git add src/DepSafe/Resources/report-styles.css
git commit -m "feat: add CSS styles for risk heatmap visualization"
```

---

### Task 3: Nav Item + Section Wiring

Add the "Risk Heatmap" navigation item and section placeholder in the main report generator.

**Files:**
- Modify: `src/DepSafe/Compliance/CraReportGenerator.cs`
  - Nav item: insert after "Dependency Tree" nav (after line 769)
  - Section: insert after tree section (after line 969)

**Context:**
- Nav items follow pattern: `<li><a href="#" onclick="showSection('section-id')" data-section="section-id">` with SVG icon
- Sections follow pattern: `<section id="section-id" class="section">` wrapping a `Generate*Section(sb)` call
- The heatmap section should always appear when `_dependencyTrees.Count > 0`

**Step 1: Add nav item**

In `CraReportGenerator.cs`, after the "Dependency Tree" nav item (after line 769), add:

```csharp
        if (_dependencyTrees.Count > 0)
        {
            sb.AppendLine("        <li><a href=\"#\" onclick=\"showSection('risk-heatmap')\" data-section=\"risk-heatmap\">");
            sb.AppendLine("          <svg class=\"nav-icon\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\"><circle cx=\"6\" cy=\"6\" r=\"3\"/><circle cx=\"18\" cy=\"6\" r=\"3\"/><circle cx=\"6\" cy=\"18\" r=\"3\"/><circle cx=\"18\" cy=\"18\" r=\"3\"/><line x1=\"9\" y1=\"6\" x2=\"15\" y2=\"6\"/><line x1=\"6\" y1=\"9\" x2=\"6\" y2=\"15\"/><line x1=\"18\" y1=\"9\" x2=\"18\" y2=\"15\"/><line x1=\"9\" y1=\"18\" x2=\"15\" y2=\"18\"/><line x1=\"9\" y1=\"8\" x2=\"15\" y2=\"16\"/></svg>");
            sb.AppendLine("          Risk Heatmap</a></li>");
        }
```

**Step 2: Add section rendering**

In `CraReportGenerator.cs`, after the tree section (after line 969), add:

```csharp
        // Risk Heatmap Section
        if (_dependencyTrees.Count > 0)
        {
            sb.AppendLine("<section id=\"risk-heatmap\" class=\"section\">");
            GenerateRiskHeatmapSection(sb);
            sb.AppendLine("</section>");
        }
```

**Step 3: Run all tests to verify nothing breaks**

Run: `dotnet test tests/DepSafe.Tests --no-restore`
Expected: All existing tests pass. (Build may fail since `GenerateRiskHeatmapSection` doesn't exist yet — add a stub in Task 4.)

**Step 4: Commit**

```bash
git add src/DepSafe/Compliance/CraReportGenerator.cs
git commit -m "feat: wire risk heatmap nav item and section in report"
```

---

### Task 4: Section HTML Generation (Server-side)

Generate the risk heatmap section HTML including the SVG container, legend, controls, tooltip div, and embedded graph JSON data.

**Files:**
- Modify: `src/DepSafe/Compliance/CraReportGenerator.Sections.cs` (add `GenerateRiskHeatmapSection` method)

**Context:**
- `_dependencyTrees` and `_healthLookup` are available as instance fields
- Use `GraphDataBuilder.Build()` from Task 1 to flatten trees
- Emit JSON via `System.Text.Json.JsonSerializer.Serialize()`
- Section pattern: header div, content card, empty state when no data
- `EscapeHtml()` is available for string escaping
- File ends at line 2405

**Step 1: Add the section method**

Add to `CraReportGenerator.Sections.cs` before the closing `}` (before line 2405):

```csharp
    private void GenerateRiskHeatmapSection(StringBuilder sb)
    {
        sb.AppendLine("<div class=\"section-header\">");
        sb.AppendLine("  <h2>Dependency Risk Heatmap</h2>");
        sb.AppendLine("  <p>Interactive visualization showing dependency relationships and risk concentration. Node size reflects how many packages depend on it. Color indicates health score.</p>");
        sb.AppendLine("</div>");

        if (_dependencyTrees.Count == 0)
        {
            sb.AppendLine("<div class=\"card empty-state success\">");
            sb.AppendLine("  <p>No dependency data available for visualization.</p>");
            sb.AppendLine("</div>");
            return;
        }

        var (nodes, edges) = GraphDataBuilder.Build(_dependencyTrees, _healthLookup);

        if (nodes.Count == 0)
        {
            sb.AppendLine("<div class=\"card empty-state success\">");
            sb.AppendLine("  <p>No dependency data available for visualization.</p>");
            sb.AppendLine("</div>");
            return;
        }

        // Stats summary
        var vulnCount = nodes.Count(n => n.HasVulnerabilities);
        var kevCount = nodes.Count(n => n.HasKevVulnerability);
        var avgScore = (int)nodes.Average(n => n.Score);

        sb.AppendLine("<div class=\"stat-grid\">");
        sb.AppendLine($"  <div class=\"stat-card\"><div class=\"stat-value\">{nodes.Count}</div><div class=\"stat-label\">Packages Shown</div></div>");
        sb.AppendLine($"  <div class=\"stat-card\"><div class=\"stat-value\">{edges.Count}</div><div class=\"stat-label\">Dependencies</div></div>");
        sb.AppendLine($"  <div class=\"stat-card\"><div class=\"stat-value\">{vulnCount}</div><div class=\"stat-label\">Vulnerable</div></div>");
        if (kevCount > 0)
            sb.AppendLine($"  <div class=\"stat-card\"><div class=\"stat-value\" style=\"color: var(--danger)\">{kevCount}</div><div class=\"stat-label\">KEV Listed</div></div>");
        sb.AppendLine($"  <div class=\"stat-card\"><div class=\"stat-value\">{avgScore}</div><div class=\"stat-label\">Avg Health</div></div>");
        sb.AppendLine("</div>");

        // Controls
        sb.AppendLine("<div class=\"heatmap-controls\">");
        sb.AppendLine("  <button class=\"tree-btn\" onclick=\"resetHeatmapZoom()\">Reset Zoom</button>");
        sb.AppendLine("  <button class=\"tree-btn\" onclick=\"toggleHeatmapLabels()\">Toggle Labels</button>");
        sb.AppendLine("</div>");

        // Container with SVG, tooltip, legend
        sb.AppendLine("<div class=\"risk-heatmap-container\" id=\"heatmap-container\">");
        sb.AppendLine("  <svg id=\"heatmap-svg\"></svg>");
        sb.AppendLine("  <div class=\"heatmap-tooltip\" id=\"heatmap-tooltip\"></div>");
        sb.AppendLine("  <div class=\"heatmap-legend\">");
        sb.AppendLine("    <div class=\"heatmap-legend-title\">Health Score</div>");
        sb.AppendLine("    <div class=\"heatmap-legend-item\"><span class=\"heatmap-legend-swatch\" style=\"background: var(--success)\"></span> Healthy (80-100)</div>");
        sb.AppendLine("    <div class=\"heatmap-legend-item\"><span class=\"heatmap-legend-swatch\" style=\"background: var(--watch)\"></span> Watch (60-79)</div>");
        sb.AppendLine("    <div class=\"heatmap-legend-item\"><span class=\"heatmap-legend-swatch\" style=\"background: var(--warning)\"></span> Warning (40-59)</div>");
        sb.AppendLine("    <div class=\"heatmap-legend-item\"><span class=\"heatmap-legend-swatch\" style=\"background: var(--danger)\"></span> Critical (&lt;40)</div>");
        sb.AppendLine("    <div class=\"heatmap-legend-title\" style=\"margin-top: 8px\">Borders</div>");
        sb.AppendLine("    <div class=\"heatmap-legend-item\"><span class=\"heatmap-legend-swatch\" style=\"border: 2px solid var(--danger); background: transparent\"></span> Has Vulnerabilities</div>");
        sb.AppendLine("    <div class=\"heatmap-legend-item\"><span class=\"heatmap-legend-swatch\" style=\"border: 2px dashed var(--danger); background: transparent\"></span> KEV Listed</div>");
        sb.AppendLine("    <div class=\"heatmap-legend-title\" style=\"margin-top: 8px\">Node Size</div>");
        sb.AppendLine("    <div class=\"heatmap-legend-item\">\u2014 Proportional to reverse dependency count</div>");
        sb.AppendLine("  </div>");
        sb.AppendLine("</div>");

        // Embed graph data as JSON
        var nodesJson = System.Text.Json.JsonSerializer.Serialize(nodes.Select(n => new
        {
            id = n.Id,
            score = n.Score,
            vuln = n.HasVulnerabilities,
            kev = n.HasKevVulnerability,
            depth = n.Depth,
            deps = n.ReverseDepCount,
            eco = n.Ecosystem,
        }));
        var edgesJson = System.Text.Json.JsonSerializer.Serialize(edges.Select(e => new
        {
            source = e.Source,
            target = e.Target,
        }));
        sb.AppendLine($"<script id=\"heatmap-graph-data\" type=\"application/json\">{{\"nodes\":{nodesJson},\"edges\":{edgesJson}}}</script>");
    }
```

**Step 2: Run all tests**

Run: `dotnet test tests/DepSafe.Tests --no-restore`
Expected: All tests pass (including the 4 GraphDataBuilder tests from Task 1).

**Step 3: Commit**

```bash
git add src/DepSafe/Compliance/CraReportGenerator.Sections.cs
git commit -m "feat: generate risk heatmap section HTML with graph JSON"
```

---

### Task 5: Force-Directed Layout JavaScript

Add the Fruchterman-Reingold simulation and SVG rendering to the Scripts partial.

**Files:**
- Modify: `src/DepSafe/Compliance/CraReportGenerator.Scripts.cs`
  - Add heatmap JS before the closing `</script>` (before line 787)

**Context:**
- Scripts file uses C# interpolated verbatim strings with `{{` for JS `{` and `}}` for JS `}`
- `showSection(sectionId)` at line 36 needs to be extended to trigger heatmap init on first visit
- Graph data is in `<script id="heatmap-graph-data" type="application/json">`
- CSS color vars: `--success`, `--watch`, `--warning`, `--danger`, `--border-primary`, `--text-primary`

**Step 1: Add heatmap initialization hook to showSection**

Modify the `showSection` function (line 36-41) to add a lazy-init call:

Replace:
```javascript
function showSection(sectionId) {{
  document.querySelectorAll('.section').forEach(s => s.classList.remove('active'));
  document.querySelectorAll('.nav-links a').forEach(a => a.classList.remove('active'));
  document.getElementById(sectionId).classList.add('active');
  document.querySelector(`[data-section='${{sectionId}}']`).classList.add('active');
}}
```

With:
```javascript
function showSection(sectionId) {{
  document.querySelectorAll('.section').forEach(s => s.classList.remove('active'));
  document.querySelectorAll('.nav-links a').forEach(a => a.classList.remove('active'));
  document.getElementById(sectionId).classList.add('active');
  document.querySelector(`[data-section='${{sectionId}}']`).classList.add('active');
  if (sectionId === 'risk-heatmap' && typeof initHeatmap === 'function') initHeatmap();
}}
```

**Step 2: Add heatmap JS functions**

Before the closing `</script>"` (before line 787), add the full heatmap module:

```javascript
// ── Risk Heatmap: Force-directed graph ──
var _heatmapInitialized = false;
var _heatmapLabelsVisible = true;
var _heatmapTransform = {{ x: 0, y: 0, scale: 1 }};

function initHeatmap() {{
  if (_heatmapInitialized) return;
  var dataEl = document.getElementById('heatmap-graph-data');
  if (!dataEl) return;
  _heatmapInitialized = true;
  var graph = JSON.parse(dataEl.textContent);
  if (!graph.nodes.length) return;
  runHeatmapLayout(graph);
}}

function runHeatmapLayout(graph) {{
  var svg = document.getElementById('heatmap-svg');
  var container = document.getElementById('heatmap-container');
  var W = container.clientWidth || 800;
  var H = container.clientHeight || 600;
  svg.setAttribute('viewBox', '0 0 ' + W + ' ' + H);

  var nodes = graph.nodes;
  var edges = graph.edges;
  var nodeMap = {{}};
  var rng = 1;
  nodes.forEach(function(n) {{
    rng = (rng * 16807 + 0) % 2147483647;
    n.x = 50 + (rng % (W - 100));
    rng = (rng * 16807 + 0) % 2147483647;
    n.y = 50 + (rng % (H - 100));
    n.vx = 0;
    n.vy = 0;
    n.r = Math.min(30, Math.max(4, 4 + Math.sqrt(n.deps) * 3));
    nodeMap[n.id] = n;
  }});

  // Resolve edge references
  var resolvedEdges = [];
  edges.forEach(function(e) {{
    var s = nodeMap[e.source];
    var t = nodeMap[e.target];
    if (s && t) resolvedEdges.push({{ source: s, target: t }});
  }});

  // Fruchterman-Reingold
  var area = W * H;
  var k = Math.sqrt(area / nodes.length);
  var temp = W / 10;
  var iterations = 200;

  for (var iter = 0; iter < iterations; iter++) {{
    // Repulsive forces
    for (var i = 0; i < nodes.length; i++) {{
      nodes[i].vx = 0;
      nodes[i].vy = 0;
      for (var j = 0; j < nodes.length; j++) {{
        if (i === j) continue;
        var dx = nodes[i].x - nodes[j].x;
        var dy = nodes[i].y - nodes[j].y;
        var dist = Math.sqrt(dx * dx + dy * dy) || 0.01;
        var force = (k * k) / dist;
        nodes[i].vx += (dx / dist) * force;
        nodes[i].vy += (dy / dist) * force;
      }}
    }}
    // Attractive forces
    resolvedEdges.forEach(function(e) {{
      var dx = e.target.x - e.source.x;
      var dy = e.target.y - e.source.y;
      var dist = Math.sqrt(dx * dx + dy * dy) || 0.01;
      var force = (dist * dist) / k;
      var fx = (dx / dist) * force;
      var fy = (dy / dist) * force;
      e.source.vx += fx;
      e.source.vy += fy;
      e.target.vx -= fx;
      e.target.vy -= fy;
    }});
    // Apply with temperature limit
    nodes.forEach(function(n) {{
      var disp = Math.sqrt(n.vx * n.vx + n.vy * n.vy) || 0.01;
      var scale = Math.min(disp, temp) / disp;
      n.x += n.vx * scale;
      n.y += n.vy * scale;
      n.x = Math.max(n.r + 10, Math.min(W - n.r - 10, n.x));
      n.y = Math.max(n.r + 10, Math.min(H - n.r - 10, n.y));
    }});
    temp *= 0.95;
  }}

  renderHeatmap(svg, nodes, resolvedEdges, W, H);
  setupHeatmapInteraction(svg, nodes, container, W, H);
}}

function nodeColor(score) {{
  if (score >= 80) return 'var(--success)';
  if (score >= 60) return 'var(--watch)';
  if (score >= 40) return 'var(--warning)';
  return 'var(--danger)';
}}

function renderHeatmap(svg, nodes, edges, W, H) {{
  svg.innerHTML = '';
  var g = document.createElementNS('http://www.w3.org/2000/svg', 'g');
  g.setAttribute('id', 'heatmap-root');

  // Edges
  edges.forEach(function(e) {{
    var line = document.createElementNS('http://www.w3.org/2000/svg', 'line');
    line.setAttribute('x1', e.source.x);
    line.setAttribute('y1', e.source.y);
    line.setAttribute('x2', e.target.x);
    line.setAttribute('y2', e.target.y);
    line.setAttribute('stroke', 'var(--border-primary)');
    line.setAttribute('stroke-opacity', '0.25');
    line.setAttribute('stroke-width', '1');
    line.dataset.source = e.source.id;
    line.dataset.target = e.target.id;
    g.appendChild(line);
  }});

  // Nodes
  nodes.forEach(function(n) {{
    var circle = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
    circle.setAttribute('cx', n.x);
    circle.setAttribute('cy', n.y);
    circle.setAttribute('r', n.r);
    circle.setAttribute('fill', nodeColor(n.score));
    circle.setAttribute('fill-opacity', '0.85');
    if (n.kev) {{
      circle.setAttribute('stroke', 'var(--danger)');
      circle.setAttribute('stroke-width', '3');
      circle.setAttribute('stroke-dasharray', '4 2');
    }} else if (n.vuln) {{
      circle.setAttribute('stroke', 'var(--danger)');
      circle.setAttribute('stroke-width', '2.5');
    }}
    circle.dataset.nodeId = n.id;
    g.appendChild(circle);
  }});

  // Labels (only for important nodes)
  nodes.forEach(function(n) {{
    if (n.deps >= 3 || n.vuln || n.kev) {{
      var text = document.createElementNS('http://www.w3.org/2000/svg', 'text');
      text.setAttribute('x', n.x);
      text.setAttribute('y', n.y - n.r - 4);
      text.setAttribute('text-anchor', 'middle');
      text.setAttribute('class', 'heatmap-label');
      // Truncate long names
      var label = n.id.length > 20 ? n.id.substring(0, 18) + '\u2026' : n.id;
      text.textContent = label;
      g.appendChild(text);
    }}
  }});

  svg.appendChild(g);
}}

function setupHeatmapInteraction(svg, nodes, container, W, H) {{
  var tooltip = document.getElementById('heatmap-tooltip');
  var root = document.getElementById('heatmap-root');
  var dragging = null;

  // Tooltip
  svg.addEventListener('mouseover', function(e) {{
    var circle = e.target.closest('circle[data-node-id]');
    if (!circle) return;
    var id = circle.dataset.nodeId;
    var n = nodes.find(function(x) {{ return x.id === id; }});
    if (!n) return;

    // Highlight: dim all, brighten connected
    svg.querySelectorAll('circle').forEach(function(c) {{ c.setAttribute('fill-opacity', '0.2'); }});
    svg.querySelectorAll('line').forEach(function(l) {{ l.setAttribute('stroke-opacity', '0.05'); }});
    circle.setAttribute('fill-opacity', '1');
    svg.querySelectorAll('line').forEach(function(l) {{
      if (l.dataset.source === id || l.dataset.target === id) {{
        l.setAttribute('stroke-opacity', '0.6');
        l.setAttribute('stroke-width', '2');
        var otherId = l.dataset.source === id ? l.dataset.target : l.dataset.source;
        var otherCircle = svg.querySelector('circle[data-node-id=""' + otherId + '""]');
        if (otherCircle) otherCircle.setAttribute('fill-opacity', '0.7');
      }}
    }});

    tooltip.innerHTML = '<div class=""tt-name"">' + n.id + '</div>'
      + '<div class=""tt-row""><span>Health</span><span>' + n.score + '/100</span></div>'
      + '<div class=""tt-row""><span>Dependents</span><span>' + n.deps + '</span></div>'
      + '<div class=""tt-row""><span>Depth</span><span>' + n.depth + '</span></div>'
      + (n.vuln ? '<div class=""tt-row""><span>Vulnerable</span><span style=""color:var(--danger)"">Yes' + (n.kev ? ' (KEV)' : '') + '</span></div>' : '');
    tooltip.classList.add('visible');

    var rect = container.getBoundingClientRect();
    var cx = parseFloat(circle.getAttribute('cx'));
    var cy = parseFloat(circle.getAttribute('cy'));
    tooltip.style.left = (cx * _heatmapTransform.scale + _heatmapTransform.x + 15) + 'px';
    tooltip.style.top = (cy * _heatmapTransform.scale + _heatmapTransform.y - 10) + 'px';
  }});

  svg.addEventListener('mouseout', function(e) {{
    if (e.target.tagName === 'circle') {{
      svg.querySelectorAll('circle').forEach(function(c) {{ c.setAttribute('fill-opacity', '0.85'); }});
      svg.querySelectorAll('line').forEach(function(l) {{ l.setAttribute('stroke-opacity', '0.25'); l.setAttribute('stroke-width', '1'); }});
      tooltip.classList.remove('visible');
    }}
  }});

  // Click: navigate to packages section
  svg.addEventListener('click', function(e) {{
    var circle = e.target.closest('circle[data-node-id]');
    if (!circle || dragging) return;
    var id = circle.dataset.nodeId;
    showSection('packages');
    var pkgCard = document.getElementById('pkg-' + id) || document.getElementById('pkg-' + id.toLowerCase());
    if (pkgCard) {{
      pkgCard.scrollIntoView({{ behavior: 'smooth', block: 'center' }});
      pkgCard.classList.add('expanded');
    }}
  }});

  // Zoom
  container.addEventListener('wheel', function(e) {{
    e.preventDefault();
    var delta = e.deltaY > 0 ? 0.9 : 1.1;
    _heatmapTransform.scale *= delta;
    _heatmapTransform.scale = Math.max(0.3, Math.min(5, _heatmapTransform.scale));
    applyHeatmapTransform(root);
  }}, {{ passive: false }});

  // Drag nodes
  svg.addEventListener('mousedown', function(e) {{
    var circle = e.target.closest('circle[data-node-id]');
    if (!circle) return;
    dragging = circle;
    e.preventDefault();
  }});
  document.addEventListener('mousemove', function(e) {{
    if (!dragging) return;
    var rect = svg.getBoundingClientRect();
    var svgX = (e.clientX - rect.left - _heatmapTransform.x) / _heatmapTransform.scale;
    var svgY = (e.clientY - rect.top - _heatmapTransform.y) / _heatmapTransform.scale;
    var id = dragging.dataset.nodeId;
    dragging.setAttribute('cx', svgX);
    dragging.setAttribute('cy', svgY);
    // Move connected edges
    svg.querySelectorAll('line').forEach(function(l) {{
      if (l.dataset.source === id) {{ l.setAttribute('x1', svgX); l.setAttribute('y1', svgY); }}
      if (l.dataset.target === id) {{ l.setAttribute('x2', svgX); l.setAttribute('y2', svgY); }}
    }});
    // Move label
    var labels = svg.querySelectorAll('text.heatmap-label');
    labels.forEach(function(t) {{
      if (t.textContent.startsWith(id.substring(0, Math.min(18, id.length)))) {{
        t.setAttribute('x', svgX);
        var r = parseFloat(dragging.getAttribute('r'));
        t.setAttribute('y', svgY - r - 4);
      }}
    }});
  }});
  document.addEventListener('mouseup', function() {{
    dragging = null;
  }});
}}

function applyHeatmapTransform(root) {{
  if (!root) return;
  root.setAttribute('transform', 'translate(' + _heatmapTransform.x + ',' + _heatmapTransform.y + ') scale(' + _heatmapTransform.scale + ')');
}}

function resetHeatmapZoom() {{
  _heatmapTransform = {{ x: 0, y: 0, scale: 1 }};
  var root = document.getElementById('heatmap-root');
  applyHeatmapTransform(root);
}}

function toggleHeatmapLabels() {{
  _heatmapLabelsVisible = !_heatmapLabelsVisible;
  var labels = document.querySelectorAll('#heatmap-root text.heatmap-label');
  labels.forEach(function(t) {{ t.style.display = _heatmapLabelsVisible ? '' : 'none'; }});
}}
```

**Step 3: Run all tests**

Run: `dotnet test tests/DepSafe.Tests --no-restore`
Expected: All tests pass (JS is embedded in HTML, not tested by xUnit directly).

**Step 4: Commit**

```bash
git add src/DepSafe/Compliance/CraReportGenerator.Scripts.cs
git commit -m "feat: add force-directed layout and SVG rendering for risk heatmap"
```

---

### Task 6: Integration Tests

Write integration tests verifying the HTML output contains heatmap elements.

**Files:**
- Modify: `tests/DepSafe.Tests/CraReportGeneratorTests.cs`

**Context:**
- `CreateGenerator()` returns a new `CraReportGenerator` instance
- `CreateMinimalReport()` returns a minimal `CraReport`
- `SetDependencyTree()` accepts `IEnumerable<DependencyTree>`
- `SetHealthData()` accepts `IEnumerable<PackageHealth>`
- Call `gen.GenerateHtml(report)` to get the full HTML string
- Assert with `Assert.Contains()` and `Assert.DoesNotContain()`

**Step 1: Write 4 integration tests**

Add to `CraReportGeneratorTests.cs` before the `// --- Helper ---` comment:

```csharp
    // --- Risk Heatmap ---

    [Fact]
    public void GenerateHtml_WithDependencyTree_RendersHeatmapSection()
    {
        var gen = CreateGenerator();
        var report = CreateMinimalReport();
        gen.SetDependencyTree(new List<DependencyTree>
        {
            new()
            {
                ProjectPath = "test.csproj",
                ProjectType = ProjectType.DotNet,
                Roots = [
                    new DependencyTreeNode
                    {
                        PackageId = "PkgA",
                        Version = "1.0.0",
                        Depth = 0,
                        DependencyType = DependencyType.Direct,
                        Children = [
                            new DependencyTreeNode
                            {
                                PackageId = "PkgB",
                                Version = "2.0.0",
                                Depth = 1,
                                DependencyType = DependencyType.Transitive,
                            }
                        ]
                    }
                ]
            }
        });

        var html = gen.GenerateHtml(report);

        Assert.Contains("id=\"risk-heatmap\"", html);
        Assert.Contains("risk-heatmap-container", html);
    }

    [Fact]
    public void GenerateHtml_WithDependencyTree_EmbedsGraphJson()
    {
        var gen = CreateGenerator();
        var report = CreateMinimalReport();
        gen.SetDependencyTree(new List<DependencyTree>
        {
            new()
            {
                ProjectPath = "test.csproj",
                ProjectType = ProjectType.DotNet,
                Roots = [
                    new DependencyTreeNode
                    {
                        PackageId = "TestPkg",
                        Version = "1.0.0",
                        Depth = 0,
                        DependencyType = DependencyType.Direct,
                    }
                ]
            }
        });

        var html = gen.GenerateHtml(report);

        Assert.Contains("heatmap-graph-data", html);
        Assert.Contains("\"id\":\"TestPkg\"", html);
    }

    [Fact]
    public void GenerateHtml_NoDependencyTree_NoHeatmapSection()
    {
        var gen = CreateGenerator();
        var report = CreateMinimalReport();
        // Don't set any dependency trees

        var html = gen.GenerateHtml(report);

        Assert.DoesNotContain("id=\"risk-heatmap\"", html);
    }

    [Fact]
    public void GenerateHtml_WithDependencyTree_HeatmapNavVisible()
    {
        var gen = CreateGenerator();
        var report = CreateMinimalReport();
        gen.SetDependencyTree(new List<DependencyTree>
        {
            new()
            {
                ProjectPath = "test.csproj",
                ProjectType = ProjectType.DotNet,
                Roots = [
                    new DependencyTreeNode
                    {
                        PackageId = "NavPkg",
                        Version = "1.0.0",
                        Depth = 0,
                        DependencyType = DependencyType.Direct,
                    }
                ]
            }
        });

        var html = gen.GenerateHtml(report);

        Assert.Contains("data-section=\"risk-heatmap\"", html);
        Assert.Contains("Risk Heatmap", html);
    }
```

**Step 2: Run tests to verify they pass**

Run: `dotnet test tests/DepSafe.Tests --filter "FullyQualifiedName~CraReportGeneratorTests" --no-restore`
Expected: All new + existing tests pass.

**Step 3: Commit**

```bash
git add tests/DepSafe.Tests/CraReportGeneratorTests.cs
git commit -m "test: add integration tests for risk heatmap HTML rendering"
```

---

### Task 7: Final Verification

Run the full test suite, verify zero warnings, and inspect the generated report.

**Files:** None (verification only)

**Step 1: Run full test suite**

Run: `dotnet test tests/DepSafe.Tests --no-restore -v normal`
Expected: All tests pass, 0 warnings.

**Step 2: Build with warnings check**

Run: `dotnet build src/DepSafe -warnaserror --no-restore`
Expected: Build succeeds with 0 warnings.

**Step 3: Commit plan**

```bash
git add docs/plans/2026-02-12-risk-heatmap-plan.md
git commit -m "docs: add risk heatmap implementation plan"
```
