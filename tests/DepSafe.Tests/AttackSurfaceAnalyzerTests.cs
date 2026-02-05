using DepSafe.Compliance;
using DepSafe.Models;

namespace DepSafe.Tests;

public class AttackSurfaceAnalyzerTests
{
    [Fact]
    public void Analyze_EmptyInputs_ReturnsZeros()
    {
        var result = AttackSurfaceAnalyzer.Analyze([], [], []);

        Assert.Equal(0, result.DirectCount);
        Assert.Equal(0, result.TransitiveCount);
        Assert.Equal(0, result.MaxDepth);
        Assert.Empty(result.HeavyPackages);
    }

    [Fact]
    public void Analyze_DirectOnly_RatioIsZero()
    {
        var direct = new List<PackageHealth>
        {
            MakePackage("A"),
            MakePackage("B"),
        };

        var result = AttackSurfaceAnalyzer.Analyze(direct, [], []);

        Assert.Equal(2, result.DirectCount);
        Assert.Equal(0, result.TransitiveCount);
        Assert.Equal(0.0, result.TransitiveToDirectRatio);
    }

    [Fact]
    public void Analyze_CalculatesRatio()
    {
        var direct = new List<PackageHealth> { MakePackage("A") };
        var transitive = Enumerable.Range(0, 5).Select(i => MakePackage($"T{i}")).ToList();

        var result = AttackSurfaceAnalyzer.Analyze(direct, transitive, []);

        Assert.Equal(1, result.DirectCount);
        Assert.Equal(5, result.TransitiveCount);
        Assert.Equal(5.0, result.TransitiveToDirectRatio);
    }

    [Fact]
    public void Analyze_UsesMaxDepthFromTrees()
    {
        var tree1 = new DependencyTree
        {
            ProjectPath = "/test",
            ProjectType = ProjectType.DotNet,
            Roots = [],
            MaxDepth = 3
        };
        var tree2 = new DependencyTree
        {
            ProjectPath = "/test2",
            ProjectType = ProjectType.Npm,
            Roots = [],
            MaxDepth = 7
        };

        var result = AttackSurfaceAnalyzer.Analyze([], [], [tree1, tree2]);

        Assert.Equal(7, result.MaxDepth);
    }

    [Fact]
    public void Analyze_DetectsHeavyPackages()
    {
        // Create a root node with >20 descendants
        var children = Enumerable.Range(0, 25)
            .Select(i => new DependencyTreeNode
            {
                PackageId = $"Child{i}",
                Version = "1.0.0",
                Depth = 1,
                DependencyType = DependencyType.Transitive
            }).ToList();

        var root = new DependencyTreeNode
        {
            PackageId = "HeavyRoot",
            Version = "1.0.0",
            Depth = 0,
            DependencyType = DependencyType.Direct,
            Children = children
        };

        var tree = new DependencyTree
        {
            ProjectPath = "/test",
            ProjectType = ProjectType.DotNet,
            Roots = [root],
            MaxDepth = 1
        };

        var result = AttackSurfaceAnalyzer.Analyze([], [], [tree]);

        Assert.Single(result.HeavyPackages);
        Assert.Equal("HeavyRoot", result.HeavyPackages[0].PackageId);
        Assert.Equal(25, result.HeavyPackages[0].TransitiveCount);
    }

    [Fact]
    public void Analyze_DoesNotFlagLightPackages()
    {
        var children = Enumerable.Range(0, 5)
            .Select(i => new DependencyTreeNode
            {
                PackageId = $"Child{i}",
                Version = "1.0.0",
                Depth = 1,
                DependencyType = DependencyType.Transitive
            }).ToList();

        var root = new DependencyTreeNode
        {
            PackageId = "LightRoot",
            Version = "1.0.0",
            Depth = 0,
            DependencyType = DependencyType.Direct,
            Children = children
        };

        var tree = new DependencyTree
        {
            ProjectPath = "/test",
            ProjectType = ProjectType.DotNet,
            Roots = [root],
            MaxDepth = 1
        };

        var result = AttackSurfaceAnalyzer.Analyze([], [], [tree]);

        Assert.Empty(result.HeavyPackages);
    }

    [Fact]
    public void AttackSurfaceResult_ZeroDirectCount_RatioIsZero()
    {
        var result = new AttackSurfaceResult
        {
            DirectCount = 0,
            TransitiveCount = 10,
            MaxDepth = 3,
            HeavyPackages = []
        };

        Assert.Equal(0, result.TransitiveToDirectRatio);
    }

    private static PackageHealth MakePackage(string id) => new()
    {
        PackageId = id,
        Version = "1.0.0",
        Score = 80,
        Status = HealthStatus.Healthy,
        Metrics = new PackageMetrics()
    };
}
