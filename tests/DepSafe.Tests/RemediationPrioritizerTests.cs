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
        double? maxEpss = null) => new()
    {
        PackageId = id,
        Version = version,
        Score = 60,
        Status = HealthStatus.Watch,
        Metrics = new PackageMetrics { TotalDownloads = 1000 },
        LatestVersion = latestVersion,
        HasKevVulnerability = hasKev,
        MaxEpssProbability = maxEpss,
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
}
