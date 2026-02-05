using DepSafe.Models;

namespace DepSafe.Compliance;

/// <summary>
/// Analyzes dependency attack surface per CRA Annex I Part I(10).
/// Measures transitive-to-direct ratio, depth, and identifies heavy packages.
/// </summary>
public static class AttackSurfaceAnalyzer
{
    private const int HeavyPackageThreshold = 20;

    /// <summary>
    /// Analyze attack surface from dependency trees.
    /// </summary>
    public static AttackSurfaceResult Analyze(
        IReadOnlyList<PackageHealth> directPackages,
        IReadOnlyList<PackageHealth> transitivePackages,
        IReadOnlyList<DependencyTree> dependencyTrees)
    {
        var directCount = directPackages.Count;
        var transitiveCount = transitivePackages.Count;
        var maxDepth = dependencyTrees.Count > 0
            ? dependencyTrees.Max(t => t.MaxDepth)
            : 0;

        // Find "heavy" packages (direct packages with many transitive deps)
        var heavyPackages = new List<(string PackageId, int TransitiveCount)>();
        foreach (var tree in dependencyTrees)
        {
            foreach (var root in tree.Roots)
            {
                var childCount = CountDescendants(root);
                if (childCount > HeavyPackageThreshold)
                {
                    heavyPackages.Add((root.PackageId, childCount));
                }
            }
        }

        heavyPackages.Sort((a, b) => b.TransitiveCount.CompareTo(a.TransitiveCount));

        return new AttackSurfaceResult
        {
            DirectCount = directCount,
            TransitiveCount = transitiveCount,
            MaxDepth = maxDepth,
            HeavyPackages = heavyPackages
        };
    }

    private static int CountDescendants(DependencyTreeNode node)
    {
        var count = 0;
        foreach (var child in node.Children)
        {
            count += 1 + CountDescendants(child);
        }
        return count;
    }
}
