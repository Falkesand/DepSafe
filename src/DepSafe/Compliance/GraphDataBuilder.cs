using DepSafe.Models;

namespace DepSafe.Compliance;

/// <summary>
/// Flattens dependency trees into a node+edge graph for the risk heatmap visualization.
/// </summary>
public static class GraphDataBuilder
{
    private const int MaxNodesBeforeCap = 150;
    private const int CappedNodeCount = 80;
    private const int DefaultHealthScore = 50;

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
        var edgeSet = new HashSet<(string Source, string Target)>(new EdgeComparer());
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
                : DefaultHealthScore;

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
            var existing = nodeMap[node.PackageId];
            var shouldUpdate = node.HasVulnerabilities || node.HasKevVulnerability || node.Depth < existing.Depth;
            if (shouldUpdate)
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
