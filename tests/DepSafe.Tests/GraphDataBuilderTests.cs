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
        // A->B, C->B — B has 2 reverse deps
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

    [Fact]
    public void Build_MultipleOccurrences_UsesMinimumDepth()
    {
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
                                PackageId = "B", Version = "1.0.0", Depth = 1,
                                DependencyType = DependencyType.Transitive,
                                Children = [
                                    new DependencyTreeNode
                                    {
                                        PackageId = "C", Version = "1.0.0", Depth = 2,
                                        DependencyType = DependencyType.Transitive,
                                    }
                                ]
                            }
                        ]
                    },
                    new DependencyTreeNode
                    {
                        PackageId = "C", Version = "1.0.0", Depth = 0,
                        DependencyType = DependencyType.Direct,
                    }
                ]
            }
        };
        var health = new Dictionary<string, PackageHealth>(StringComparer.OrdinalIgnoreCase);

        var (nodes, _) = GraphDataBuilder.Build(trees, health);

        Assert.Equal(0, nodes.First(n => n.Id == "C").Depth);
    }

    [Fact]
    public void Build_DeduplicatesEdges()
    {
        var trees = new List<DependencyTree>
        {
            new()
            {
                ProjectPath = "a.csproj",
                ProjectType = ProjectType.DotNet,
                Roots = [
                    new DependencyTreeNode
                    {
                        PackageId = "A", Version = "1.0.0", Depth = 0,
                        DependencyType = DependencyType.Direct,
                        Children = [
                            new DependencyTreeNode { PackageId = "B", Version = "1.0.0", Depth = 1, DependencyType = DependencyType.Transitive }
                        ]
                    }
                ]
            },
            new()
            {
                ProjectPath = "b.csproj",
                ProjectType = ProjectType.DotNet,
                Roots = [
                    new DependencyTreeNode
                    {
                        PackageId = "A", Version = "1.0.0", Depth = 0,
                        DependencyType = DependencyType.Direct,
                        Children = [
                            new DependencyTreeNode { PackageId = "B", Version = "1.0.0", Depth = 1, DependencyType = DependencyType.Transitive }
                        ]
                    }
                ]
            },
        };
        var health = new Dictionary<string, PackageHealth>(StringComparer.OrdinalIgnoreCase);

        var (_, edges) = GraphDataBuilder.Build(trees, health);

        Assert.Single(edges);
    }

    [Fact]
    public void Build_MergesVulnerabilityFlags()
    {
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
                        HasVulnerabilities = false,
                        Children = [
                            new DependencyTreeNode
                            {
                                PackageId = "B", Version = "1.0.0", Depth = 1,
                                DependencyType = DependencyType.Transitive,
                                HasVulnerabilities = false,
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
                                PackageId = "B", Version = "1.0.0", Depth = 1,
                                DependencyType = DependencyType.Transitive,
                                HasVulnerabilities = true,
                                HasKevVulnerability = true,
                            }
                        ]
                    }
                ]
            }
        };
        var health = new Dictionary<string, PackageHealth>(StringComparer.OrdinalIgnoreCase);

        var (nodes, _) = GraphDataBuilder.Build(trees, health);

        var b = nodes.First(n => n.Id == "B");
        Assert.True(b.HasVulnerabilities);
        Assert.True(b.HasKevVulnerability);
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
