using DepSafe.Compliance;
using DepSafe.DataSources;
using DepSafe.Models;

namespace DepSafe.Tests;

public class ReportingObligationAnalyzerTests
{
    private static PackageHealth CreatePackage(string id = "TestPkg", string version = "1.0.0") => new()
    {
        PackageId = id,
        Version = version,
        Score = 80,
        Status = HealthStatus.Healthy,
        Metrics = new PackageMetrics { TotalDownloads = 1000 },
    };

    private static VulnerabilityInfo CreateVuln(
        string id = "GHSA-1",
        string severity = "HIGH",
        string vulnerableRange = "< 2.0.0",
        string? patchedVersion = "2.0.0",
        List<string>? cves = null,
        DateTime? publishedAt = null,
        double? epssProbability = null)
    {
        return new VulnerabilityInfo
        {
            Id = id,
            Severity = severity,
            Summary = "Test vulnerability",
            PackageId = "TestPkg",
            VulnerableVersionRange = vulnerableRange,
            PatchedVersion = patchedVersion,
            Cves = cves ?? ["CVE-2024-0001"],
            PublishedAt = publishedAt ?? new DateTime(2024, 1, 15, 0, 0, 0, DateTimeKind.Utc),
            EpssProbability = epssProbability,
        };
    }

    private static readonly HashSet<string> EmptyKev = new(StringComparer.OrdinalIgnoreCase);
    private static readonly Dictionary<string, EpssScore> EmptyEpss = new(StringComparer.OrdinalIgnoreCase);

    [Fact]
    public void Analyze_NoPackages_ReturnsEmpty()
    {
        var result = ReportingObligationAnalyzer.Analyze(
            Array.Empty<PackageHealth>(),
            new Dictionary<string, List<VulnerabilityInfo>>(),
            EmptyKev,
            EmptyEpss);

        Assert.Empty(result);
    }

    [Fact]
    public void Analyze_NoVulnerabilities_ReturnsEmpty()
    {
        var packages = new[] { CreatePackage() };
        var vulns = new Dictionary<string, List<VulnerabilityInfo>>();

        var result = ReportingObligationAnalyzer.Analyze(packages, vulns, EmptyKev, EmptyEpss);

        Assert.Empty(result);
    }

    [Fact]
    public void Analyze_VulnNotAffectingVersion_ReturnsEmpty()
    {
        var packages = new[] { CreatePackage(version: "3.0.0") }; // Above patched version
        var vulns = new Dictionary<string, List<VulnerabilityInfo>>
        {
            ["TestPkg"] = [CreateVuln(vulnerableRange: "< 2.0.0", patchedVersion: "2.0.0")],
        };
        var kev = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "CVE-2024-0001" };

        var result = ReportingObligationAnalyzer.Analyze(packages, vulns, kev, EmptyEpss);

        Assert.Empty(result);
    }

    [Fact]
    public void Analyze_KevVulnerability_ReturnsObligation()
    {
        var packages = new[] { CreatePackage() };
        var vulns = new Dictionary<string, List<VulnerabilityInfo>>
        {
            ["TestPkg"] = [CreateVuln()],
        };
        var kev = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "CVE-2024-0001" };

        var result = ReportingObligationAnalyzer.Analyze(packages, vulns, kev, EmptyEpss);

        Assert.Single(result);
        Assert.Equal("TestPkg", result[0].PackageId);
        Assert.True(result[0].IsKevVulnerability);
    }

    [Fact]
    public void Analyze_HighEpss_ReturnsObligation()
    {
        var packages = new[] { CreatePackage() };
        var vulns = new Dictionary<string, List<VulnerabilityInfo>>
        {
            ["TestPkg"] = [CreateVuln()],
        };
        var epss = new Dictionary<string, EpssScore>(StringComparer.OrdinalIgnoreCase)
        {
            ["CVE-2024-0001"] = new EpssScore { Cve = "CVE-2024-0001", Probability = 0.75, Percentile = 0.95 },
        };

        var result = ReportingObligationAnalyzer.Analyze(packages, vulns, EmptyKev, epss);

        Assert.Single(result);
        Assert.Equal(0.75, result[0].EpssProbability);
    }

    [Fact]
    public void Analyze_LowEpssNotInKev_ReturnsEmpty()
    {
        var packages = new[] { CreatePackage() };
        var vulns = new Dictionary<string, List<VulnerabilityInfo>>
        {
            ["TestPkg"] = [CreateVuln()],
        };
        var epss = new Dictionary<string, EpssScore>(StringComparer.OrdinalIgnoreCase)
        {
            ["CVE-2024-0001"] = new EpssScore { Cve = "CVE-2024-0001", Probability = 0.1, Percentile = 0.3 },
        };

        var result = ReportingObligationAnalyzer.Analyze(packages, vulns, EmptyKev, epss);

        Assert.Empty(result);
    }

    [Fact]
    public void Analyze_BothKevAndHighEpss_TriggerIsBoth()
    {
        var packages = new[] { CreatePackage() };
        var vulns = new Dictionary<string, List<VulnerabilityInfo>>
        {
            ["TestPkg"] = [CreateVuln()],
        };
        var kev = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "CVE-2024-0001" };
        var epss = new Dictionary<string, EpssScore>(StringComparer.OrdinalIgnoreCase)
        {
            ["CVE-2024-0001"] = new EpssScore { Cve = "CVE-2024-0001", Probability = 0.8, Percentile = 0.99 },
        };

        var result = ReportingObligationAnalyzer.Analyze(packages, vulns, kev, epss);

        Assert.Single(result);
        Assert.Equal(ReportingTrigger.Both, result[0].Trigger);
    }

    [Fact]
    public void Analyze_KevOnly_TriggerIsKevExploitation()
    {
        var packages = new[] { CreatePackage() };
        var vulns = new Dictionary<string, List<VulnerabilityInfo>>
        {
            ["TestPkg"] = [CreateVuln()],
        };
        var kev = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "CVE-2024-0001" };

        var result = ReportingObligationAnalyzer.Analyze(packages, vulns, kev, EmptyEpss);

        Assert.Equal(ReportingTrigger.KevExploitation, result[0].Trigger);
    }

    [Fact]
    public void Analyze_EpssOnly_TriggerIsHighEpss()
    {
        var packages = new[] { CreatePackage() };
        var vulns = new Dictionary<string, List<VulnerabilityInfo>>
        {
            ["TestPkg"] = [CreateVuln()],
        };
        var epss = new Dictionary<string, EpssScore>(StringComparer.OrdinalIgnoreCase)
        {
            ["CVE-2024-0001"] = new EpssScore { Cve = "CVE-2024-0001", Probability = 0.6, Percentile = 0.9 },
        };

        var result = ReportingObligationAnalyzer.Analyze(packages, vulns, EmptyKev, epss);

        Assert.Equal(ReportingTrigger.HighEpss, result[0].Trigger);
    }

    [Fact]
    public void Analyze_MultipleVulns_PicksHighestSeverity()
    {
        var packages = new[] { CreatePackage() };
        var vulns = new Dictionary<string, List<VulnerabilityInfo>>
        {
            ["TestPkg"] =
            [
                CreateVuln(id: "GHSA-1", severity: "LOW", cves: ["CVE-2024-0001"]),
                CreateVuln(id: "GHSA-2", severity: "CRITICAL", cves: ["CVE-2024-0002"]),
            ],
        };
        var kev = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "CVE-2024-0001", "CVE-2024-0002" };

        var result = ReportingObligationAnalyzer.Analyze(packages, vulns, kev, EmptyEpss);

        Assert.Single(result);
        Assert.Equal("CRITICAL", result[0].Severity);
    }

    [Fact]
    public void Analyze_MultipleCves_AggregatesIntoSingleObligation()
    {
        var packages = new[] { CreatePackage() };
        var vulns = new Dictionary<string, List<VulnerabilityInfo>>
        {
            ["TestPkg"] =
            [
                CreateVuln(id: "GHSA-1", cves: ["CVE-2024-0001"]),
                CreateVuln(id: "GHSA-2", cves: ["CVE-2024-0002"]),
            ],
        };
        var kev = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "CVE-2024-0001", "CVE-2024-0002" };

        var result = ReportingObligationAnalyzer.Analyze(packages, vulns, kev, EmptyEpss);

        Assert.Single(result); // Single obligation for the package
        Assert.Equal(2, result[0].CveIds.Count);
    }

    [Fact]
    public void Analyze_SortsBySeverity_CriticalFirst()
    {
        var packages = new[]
        {
            CreatePackage("PkgLow", "1.0.0"),
            CreatePackage("PkgCrit", "1.0.0"),
        };
        var vulns = new Dictionary<string, List<VulnerabilityInfo>>
        {
            ["PkgLow"] = [CreateVuln(severity: "LOW", cves: ["CVE-2024-0001"])],
            ["PkgCrit"] = [CreateVuln(severity: "CRITICAL", cves: ["CVE-2024-0002"])],
        };
        var kev = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "CVE-2024-0001", "CVE-2024-0002" };

        var result = ReportingObligationAnalyzer.Analyze(packages, vulns, kev, EmptyEpss);

        Assert.Equal(2, result.Count);
        Assert.Equal("CRITICAL", result[0].Severity);
        Assert.Equal("LOW", result[1].Severity);
    }

    [Fact]
    public void Analyze_EarliestPublished_UsedAsDiscoveryDate()
    {
        var earlyDate = new DateTime(2023, 6, 1, 0, 0, 0, DateTimeKind.Utc);
        var laterDate = new DateTime(2024, 3, 15, 0, 0, 0, DateTimeKind.Utc);

        var packages = new[] { CreatePackage() };
        var vulns = new Dictionary<string, List<VulnerabilityInfo>>
        {
            ["TestPkg"] =
            [
                CreateVuln(id: "GHSA-1", cves: ["CVE-2024-0001"], publishedAt: laterDate),
                CreateVuln(id: "GHSA-2", cves: ["CVE-2024-0002"], publishedAt: earlyDate),
            ],
        };
        var kev = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "CVE-2024-0001", "CVE-2024-0002" };

        var result = ReportingObligationAnalyzer.Analyze(packages, vulns, kev, EmptyEpss);

        Assert.Single(result);
        Assert.Equal(earlyDate, result[0].DiscoveryDate);
    }
}
