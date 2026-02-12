using DepSafe.Compliance;
using DepSafe.Models;
using DepSafe.Scoring;

namespace DepSafe.Tests;

public class RemediationPrioritizerTests
{
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

    private static DependencyTree CreateTree(params DependencyTreeNode[] roots) => new()
    {
        ProjectPath = "/test",
        ProjectType = ProjectType.DotNet,
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

    private static VulnerabilityInfo CreateVuln(
        string severity = "HIGH",
        string vulnerableRange = "< 2.0.0",
        string? patchedVersion = "2.0.0",
        List<string>? cves = null,
        DateTime? publishedAt = null,
        double? epssProbability = null) => new()
    {
        Id = "GHSA-test",
        Severity = severity,
        Summary = "Test vuln",
        PackageId = "TestPkg",
        VulnerableVersionRange = vulnerableRange,
        PatchedVersion = patchedVersion,
        Cves = cves ?? ["CVE-2024-0001"],
        PublishedAt = publishedAt ?? new DateTime(2024, 1, 1, 0, 0, 0, DateTimeKind.Utc),
        EpssProbability = epssProbability,
    };

    private static readonly List<CraComplianceItem> EmptyCompliance = [];

    private static Dictionary<string, List<string>> CreateVersions(string packageId, params string[] versions)
        => new(StringComparer.OrdinalIgnoreCase)
        {
            [packageId] = versions.ToList()
        };

    private static readonly Dictionary<string, List<string>> EmptyVersions = new();

    [Fact]
    public void PrioritizeUpdates_NoPackages_ReturnsEmpty()
    {
        var result = RemediationPrioritizer.PrioritizeUpdates(
            Array.Empty<PackageHealth>(),
            new Dictionary<string, List<VulnerabilityInfo>>(),
            50,
            EmptyCompliance);

        Assert.Empty(result);
    }

    [Fact]
    public void PrioritizeUpdates_NoVulns_ReturnsEmpty()
    {
        var packages = new[] { CreatePackage() };
        var vulns = new Dictionary<string, List<VulnerabilityInfo>>();

        var result = RemediationPrioritizer.PrioritizeUpdates(packages, vulns, 50, EmptyCompliance);

        Assert.Empty(result);
    }

    [Fact]
    public void PrioritizeUpdates_VulnNotAffecting_ReturnsEmpty()
    {
        var packages = new[] { CreatePackage(version: "3.0.0") };
        var vulns = new Dictionary<string, List<VulnerabilityInfo>>
        {
            ["TestPkg"] = [CreateVuln(vulnerableRange: "< 2.0.0", patchedVersion: "2.0.0")],
        };

        var result = RemediationPrioritizer.PrioritizeUpdates(packages, vulns, 50, EmptyCompliance);

        Assert.Empty(result);
    }

    [Fact]
    public void PrioritizeUpdates_AffectedVuln_ReturnsItem()
    {
        var packages = new[] { CreatePackage() };
        var vulns = new Dictionary<string, List<VulnerabilityInfo>>
        {
            ["TestPkg"] = [CreateVuln()],
        };

        var result = RemediationPrioritizer.PrioritizeUpdates(packages, vulns, 50, EmptyCompliance);

        Assert.Single(result);
        Assert.Equal("TestPkg", result[0].PackageId);
        Assert.Equal("1.0.0", result[0].CurrentVersion);
        Assert.Equal("2.0.0", result[0].RecommendedVersion);
    }

    [Fact]
    public void PrioritizeUpdates_KevVuln_HasHighestPriority()
    {
        var packages = new[]
        {
            CreatePackage("PkgKev", hasKev: true),
            CreatePackage("PkgNormal", "1.0.0"),
        };
        var vulns = new Dictionary<string, List<VulnerabilityInfo>>
        {
            ["PkgKev"] = [CreateVuln(severity: "LOW")],
            ["PkgNormal"] = [CreateVuln(severity: "CRITICAL")],
        };

        var result = RemediationPrioritizer.PrioritizeUpdates(packages, vulns, 50, EmptyCompliance);

        Assert.Equal(2, result.Count);
        // KEV package should be first despite lower severity
        Assert.Equal("PkgKev", result[0].PackageId);
    }

    [Fact]
    public void PrioritizeUpdates_HighEpss_AddsToPriority()
    {
        var packages = new[]
        {
            CreatePackage("PkgHighEpss", maxEpss: 0.7),
            CreatePackage("PkgLowEpss", "1.0.0"),
        };
        var vulns = new Dictionary<string, List<VulnerabilityInfo>>
        {
            ["PkgHighEpss"] = [CreateVuln(severity: "LOW", epssProbability: 0.7)],
            ["PkgLowEpss"] = [CreateVuln(severity: "LOW", epssProbability: 0.1)],
        };

        var result = RemediationPrioritizer.PrioritizeUpdates(packages, vulns, 50, EmptyCompliance);

        Assert.Equal(2, result.Count);
        // High EPSS package gets +5000 priority
        Assert.Equal("PkgHighEpss", result[0].PackageId);
    }

    [Fact]
    public void PrioritizeUpdates_CriticalSeverity_Adds500()
    {
        var packages = new[]
        {
            CreatePackage("PkgCrit"),
            CreatePackage("PkgLow", "1.0.0"),
        };
        var vulns = new Dictionary<string, List<VulnerabilityInfo>>
        {
            ["PkgCrit"] = [CreateVuln(severity: "CRITICAL")],
            ["PkgLow"] = [CreateVuln(severity: "LOW")],
        };

        var result = RemediationPrioritizer.PrioritizeUpdates(packages, vulns, 50, EmptyCompliance);

        Assert.Equal(2, result.Count);
        Assert.Equal("PkgCrit", result[0].PackageId);
        Assert.True(result[0].PriorityScore > result[1].PriorityScore);
    }

    [Fact]
    public void PrioritizeUpdates_SortedByPriorityDescending()
    {
        var packages = new[]
        {
            CreatePackage("PkgLow"),
            CreatePackage("PkgHigh", "1.0.0"),
            CreatePackage("PkgMed", "1.0.0"),
        };
        var vulns = new Dictionary<string, List<VulnerabilityInfo>>
        {
            ["PkgLow"] = [CreateVuln(severity: "LOW")],
            ["PkgHigh"] = [CreateVuln(severity: "CRITICAL")],
            ["PkgMed"] = [CreateVuln(severity: "MODERATE")],
        };

        var result = RemediationPrioritizer.PrioritizeUpdates(packages, vulns, 50, EmptyCompliance);

        Assert.Equal(3, result.Count);
        Assert.True(result[0].PriorityScore >= result[1].PriorityScore);
        Assert.True(result[1].PriorityScore >= result[2].PriorityScore);
    }

    [Fact]
    public void PrioritizeUpdates_MaxItems20_Truncates()
    {
        var packages = new List<PackageHealth>();
        var vulns = new Dictionary<string, List<VulnerabilityInfo>>();

        for (int i = 0; i < 25; i++)
        {
            var name = $"Pkg{i:D2}";
            packages.Add(CreatePackage(name));
            vulns[name] = [CreateVuln(cves: [$"CVE-2024-{i:D4}"])];
        }

        var result = RemediationPrioritizer.PrioritizeUpdates(packages, vulns, 50, EmptyCompliance);

        Assert.Equal(20, result.Count);
    }

    [Fact]
    public void PrioritizeUpdates_PatchBump_EffortIsPatch()
    {
        var packages = new[] { CreatePackage(version: "1.0.0") };
        var vulns = new Dictionary<string, List<VulnerabilityInfo>>
        {
            ["TestPkg"] = [CreateVuln(patchedVersion: "1.0.1")],
        };

        var result = RemediationPrioritizer.PrioritizeUpdates(packages, vulns, 50, EmptyCompliance);

        Assert.Single(result);
        Assert.Equal(UpgradeEffort.Patch, result[0].Effort);
    }

    [Fact]
    public void PrioritizeUpdates_MinorBump_EffortIsMinor()
    {
        var packages = new[] { CreatePackage(version: "1.0.0") };
        var vulns = new Dictionary<string, List<VulnerabilityInfo>>
        {
            ["TestPkg"] = [CreateVuln(patchedVersion: "1.1.0")],
        };

        var result = RemediationPrioritizer.PrioritizeUpdates(packages, vulns, 50, EmptyCompliance);

        Assert.Single(result);
        Assert.Equal(UpgradeEffort.Minor, result[0].Effort);
    }

    [Fact]
    public void PrioritizeUpdates_MajorBump_EffortIsMajor()
    {
        var packages = new[] { CreatePackage(version: "1.0.0") };
        var vulns = new Dictionary<string, List<VulnerabilityInfo>>
        {
            ["TestPkg"] = [CreateVuln(patchedVersion: "2.0.0")],
        };

        var result = RemediationPrioritizer.PrioritizeUpdates(packages, vulns, 50, EmptyCompliance);

        Assert.Single(result);
        Assert.Equal(UpgradeEffort.Major, result[0].Effort);
    }

    [Fact]
    public void PrioritizeUpdates_UnparseableVersion_EffortIsMajor()
    {
        var packages = new[] { CreatePackage(version: "not-a-version") };
        var vulns = new Dictionary<string, List<VulnerabilityInfo>>
        {
            ["TestPkg"] =
            [
                new VulnerabilityInfo
                {
                    Id = "GHSA-test",
                    Severity = "HIGH",
                    Summary = "Test",
                    PackageId = "TestPkg",
                    VulnerableVersionRange = "", // Empty range → IsAffected returns true
                    PatchedVersion = "also-not-a-version",
                    Cves = ["CVE-2024-0001"],
                },
            ],
        };

        var result = RemediationPrioritizer.PrioritizeUpdates(packages, vulns, 50, EmptyCompliance);

        Assert.Single(result);
        Assert.Equal(UpgradeEffort.Major, result[0].Effort);
    }

    [Fact]
    public void PrioritizeUpdates_UsesHighestPatchedVersion()
    {
        var packages = new[] { CreatePackage(version: "1.0.0") };
        var vulns = new Dictionary<string, List<VulnerabilityInfo>>
        {
            ["TestPkg"] =
            [
                CreateVuln(patchedVersion: "1.1.0", cves: ["CVE-2024-0001"]),
                CreateVuln(patchedVersion: "1.5.0", cves: ["CVE-2024-0002"]),
            ],
        };

        var result = RemediationPrioritizer.PrioritizeUpdates(packages, vulns, 50, EmptyCompliance);

        Assert.Single(result);
        Assert.Equal("1.5.0", result[0].RecommendedVersion);
    }

    [Fact]
    public void PrioritizeUpdates_FallsBackToLatestVersion()
    {
        var packages = new[] { CreatePackage(version: "1.0.0", latestVersion: "3.0.0") };
        var vulns = new Dictionary<string, List<VulnerabilityInfo>>
        {
            ["TestPkg"] = [CreateVuln(patchedVersion: null)], // No patched version
        };

        var result = RemediationPrioritizer.PrioritizeUpdates(packages, vulns, 50, EmptyCompliance);

        Assert.Single(result);
        Assert.Equal("3.0.0", result[0].RecommendedVersion);
    }

    [Fact]
    public void PrioritizeUpdates_PatchFixAvailable_SinglePatchTier()
    {
        var packages = new[] { CreatePackage(version: "1.0.0") };
        var vulns = new Dictionary<string, List<VulnerabilityInfo>>
        {
            ["TestPkg"] = [CreateVuln(vulnerableRange: ">=1.0.0, <1.0.3", patchedVersion: "1.0.3")],
        };
        // Only patch-level versions available — no minor/major candidates
        var versions = CreateVersions("TestPkg", "1.0.0", "1.0.1", "1.0.2", "1.0.3");

        var result = RemediationPrioritizer.PrioritizeUpdates(packages, vulns, 50, EmptyCompliance, versions);

        Assert.Single(result);
        Assert.Single(result[0].UpgradeTiers);
        Assert.Equal("1.0.3", result[0].UpgradeTiers[0].TargetVersion);
        Assert.Equal(UpgradeEffort.Patch, result[0].UpgradeTiers[0].Effort);
        Assert.True(result[0].UpgradeTiers[0].IsRecommended);
    }

    [Fact]
    public void PrioritizeUpdates_OnlyMajorFix_SingleMajorTier()
    {
        var packages = new[] { CreatePackage(version: "1.0.0") };
        var vulns = new Dictionary<string, List<VulnerabilityInfo>>
        {
            ["TestPkg"] = [CreateVuln(vulnerableRange: ">=0, <2.0.0", patchedVersion: "2.0.0")],
        };
        var versions = CreateVersions("TestPkg", "1.0.0", "1.0.1", "1.1.0", "2.0.0", "2.1.0");

        var result = RemediationPrioritizer.PrioritizeUpdates(packages, vulns, 50, EmptyCompliance, versions);

        Assert.Single(result);
        Assert.Single(result[0].UpgradeTiers);
        Assert.Equal("2.0.0", result[0].UpgradeTiers[0].TargetVersion);
        Assert.Equal(UpgradeEffort.Major, result[0].UpgradeTiers[0].Effort);
        Assert.True(result[0].UpgradeTiers[0].IsRecommended);
    }

    [Fact]
    public void PrioritizeUpdates_PatchAndMajorFixes_TwoTiers()
    {
        var packages = new[] { CreatePackage(version: "1.0.0") };
        var vulns = new Dictionary<string, List<VulnerabilityInfo>>
        {
            ["TestPkg"] =
            [
                CreateVuln(vulnerableRange: ">=1.0.0, <1.0.3", patchedVersion: "1.0.3", cves: ["CVE-2024-0001"]),
                CreateVuln(vulnerableRange: ">=0, <2.0.0", patchedVersion: "2.0.0", cves: ["CVE-2024-0002"]),
            ],
        };
        // No minor-level candidates — only patch and major tiers
        var versions = CreateVersions("TestPkg", "1.0.0", "1.0.3", "2.0.0");

        var result = RemediationPrioritizer.PrioritizeUpdates(packages, vulns, 50, EmptyCompliance, versions);

        Assert.Single(result);
        Assert.Equal(2, result[0].UpgradeTiers.Count);

        // First tier: patch fixes 1 of 2 CVEs
        Assert.Equal("1.0.3", result[0].UpgradeTiers[0].TargetVersion);
        Assert.Equal(UpgradeEffort.Patch, result[0].UpgradeTiers[0].Effort);
        Assert.Equal(1, result[0].UpgradeTiers[0].CvesFixed);
        Assert.Equal(2, result[0].UpgradeTiers[0].TotalCves);
        Assert.True(result[0].UpgradeTiers[0].IsRecommended);

        // Second tier: major fixes all
        Assert.Equal("2.0.0", result[0].UpgradeTiers[1].TargetVersion);
        Assert.Equal(UpgradeEffort.Major, result[0].UpgradeTiers[1].Effort);
        Assert.Equal(2, result[0].UpgradeTiers[1].CvesFixed);
        Assert.Equal(2, result[0].UpgradeTiers[1].TotalCves);
        Assert.False(result[0].UpgradeTiers[1].IsRecommended);
    }

    [Fact]
    public void PrioritizeUpdates_SameVersionForPatchAndMinor_Deduplicates()
    {
        var packages = new[] { CreatePackage(version: "1.0.0") };
        var vulns = new Dictionary<string, List<VulnerabilityInfo>>
        {
            ["TestPkg"] = [CreateVuln(vulnerableRange: ">=1.0.0, <1.0.3", patchedVersion: "1.0.3")],
        };
        var versions = CreateVersions("TestPkg", "1.0.0", "1.0.3");

        var result = RemediationPrioritizer.PrioritizeUpdates(packages, vulns, 50, EmptyCompliance, versions);

        Assert.Single(result);
        Assert.Single(result[0].UpgradeTiers);
        Assert.Equal("1.0.3", result[0].UpgradeTiers[0].TargetVersion);
    }

    [Fact]
    public void PrioritizeUpdates_NoVersionData_FallsBackToExistingBehavior()
    {
        var packages = new[] { CreatePackage(version: "1.0.0") };
        var vulns = new Dictionary<string, List<VulnerabilityInfo>>
        {
            ["TestPkg"] = [CreateVuln(patchedVersion: "2.0.0")],
        };

        var result = RemediationPrioritizer.PrioritizeUpdates(packages, vulns, 50, EmptyCompliance, EmptyVersions);

        Assert.Single(result);
        Assert.Equal("2.0.0", result[0].RecommendedVersion);
        Assert.Empty(result[0].UpgradeTiers);
    }

    [Fact]
    public void PrioritizeUpdates_PrereleaseVersions_Excluded()
    {
        var packages = new[] { CreatePackage(version: "1.0.0") };
        var vulns = new Dictionary<string, List<VulnerabilityInfo>>
        {
            ["TestPkg"] = [CreateVuln(vulnerableRange: ">=1.0.0, <1.0.3", patchedVersion: "1.0.3")],
        };
        var versions = CreateVersions("TestPkg", "1.0.0", "1.0.3-beta", "1.0.3", "2.0.0");

        var result = RemediationPrioritizer.PrioritizeUpdates(packages, vulns, 50, EmptyCompliance, versions);

        Assert.Single(result);
        Assert.True(result[0].UpgradeTiers.Count >= 1);
        Assert.DoesNotContain(result[0].UpgradeTiers, t => t.TargetVersion.Contains("-beta"));
    }

    [Fact]
    public void PrioritizeUpdates_ThreeTiers_PatchMinorMajor()
    {
        var packages = new[] { CreatePackage(version: "1.0.0") };
        var vulns = new Dictionary<string, List<VulnerabilityInfo>>
        {
            ["TestPkg"] = [CreateVuln(vulnerableRange: ">=1.0.0, <1.0.5", patchedVersion: "1.0.5")],
        };
        var versions = CreateVersions("TestPkg", "1.0.0", "1.0.5", "1.2.0", "2.0.0");

        var result = RemediationPrioritizer.PrioritizeUpdates(packages, vulns, 50, EmptyCompliance, versions);

        Assert.Single(result);
        Assert.Equal(3, result[0].UpgradeTiers.Count);
        Assert.Equal(UpgradeEffort.Patch, result[0].UpgradeTiers[0].Effort);
        Assert.Equal(UpgradeEffort.Minor, result[0].UpgradeTiers[1].Effort);
        Assert.Equal(UpgradeEffort.Major, result[0].UpgradeTiers[2].Effort);
        Assert.True(result[0].UpgradeTiers[0].IsRecommended);
        Assert.False(result[0].UpgradeTiers[1].IsRecommended);
        Assert.False(result[0].UpgradeTiers[2].IsRecommended);
    }

    [Fact]
    public void PrioritizeUpdates_PartialFix_ShowsCveFractions()
    {
        var packages = new[] { CreatePackage(version: "1.0.0") };
        var vulns = new Dictionary<string, List<VulnerabilityInfo>>
        {
            ["TestPkg"] =
            [
                CreateVuln(vulnerableRange: ">=1.0.0, <1.0.3", patchedVersion: "1.0.3", cves: ["CVE-2024-0001"]),
                CreateVuln(vulnerableRange: ">=0, <2.0.0", patchedVersion: "2.0.0", cves: ["CVE-2024-0002"]),
            ],
        };
        var versions = CreateVersions("TestPkg", "1.0.0", "1.0.3", "2.0.0");

        var result = RemediationPrioritizer.PrioritizeUpdates(packages, vulns, 50, EmptyCompliance, versions);

        Assert.Single(result);
        var patchTier = result[0].UpgradeTiers.First(t => t.Effort == UpgradeEffort.Patch);
        Assert.Equal(1, patchTier.CvesFixed);
        Assert.Equal(2, patchTier.TotalCves);

        var majorTier = result[0].UpgradeTiers.First(t => t.Effort == UpgradeEffort.Major);
        Assert.Equal(2, majorTier.CvesFixed);
        Assert.Equal(2, majorTier.TotalCves);
    }

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
                Owner = "test",
                Name = "archived-pkg",
                FullName = "test/archived-pkg",
                Stars = 100,
                OpenIssues = 0,
                Forks = 10,
                LastCommitDate = DateTime.UtcNow.AddYears(-3),
                LastPushDate = DateTime.UtcNow.AddYears(-3),
                IsArchived = true,
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
                Owner = "test",
                Name = "healthy-pkg",
                FullName = "test/healthy-pkg",
                Stars = 100,
                OpenIssues = 5,
                Forks = 10,
                LastCommitDate = DateTime.UtcNow.AddDays(-30),
                LastPushDate = DateTime.UtcNow.AddDays(-30),
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

    [Fact]
    public void UpgradeTiers_WithMultipleTiers_DataShape()
    {
        var item = new RemediationRoadmapItem
        {
            PackageId = "TestPkg",
            CurrentVersion = "1.0.0",
            RecommendedVersion = "1.0.3",
            CveCount = 2,
            CveIds = ["CVE-2024-0001", "CVE-2024-0002"],
            ScoreLift = 5,
            Effort = UpgradeEffort.Patch,
            PriorityScore = 100,
            UpgradeTiers =
            [
                new UpgradeTier("1.0.3", UpgradeEffort.Patch, 1, 2, true),
                new UpgradeTier("2.0.0", UpgradeEffort.Major, 2, 2, false),
            ],
        };

        Assert.Equal(2, item.UpgradeTiers.Count);
        Assert.True(item.UpgradeTiers[0].IsRecommended);
        Assert.False(item.UpgradeTiers[1].IsRecommended);
        Assert.Equal("1/2", $"{item.UpgradeTiers[0].CvesFixed}/{item.UpgradeTiers[0].TotalCves}");
        Assert.Equal("2/2", $"{item.UpgradeTiers[1].CvesFixed}/{item.UpgradeTiers[1].TotalCves}");
    }
}
