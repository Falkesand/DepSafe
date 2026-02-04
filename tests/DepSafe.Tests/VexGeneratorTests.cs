using DepSafe.Compliance;
using DepSafe.Models;

namespace DepSafe.Tests;

public class VexGeneratorTests
{
    private readonly VexGenerator _generator = new();

    [Fact]
    public void Generate_NoVulnerabilities_CreatesEmptyStatements()
    {
        // Arrange
        var packages = new List<PackageHealth>
        {
            CreatePackageHealth("SafePackage", "1.0.0")
        };
        var vulnerabilities = new Dictionary<string, List<VulnerabilityInfo>>();

        // Act
        var vex = _generator.Generate(packages, vulnerabilities);

        // Assert
        Assert.Empty(vex.Statements);
        Assert.Equal("DepSafe", vex.Tooling);
    }

    [Fact]
    public void Generate_WithVulnerabilities_CreatesStatements()
    {
        // Arrange
        var packages = new List<PackageHealth>
        {
            CreatePackageHealth("VulnerablePackage", "1.0.0")
        };

        var vulnerabilities = new Dictionary<string, List<VulnerabilityInfo>>
        {
            ["VulnerablePackage"] =
            [
                new VulnerabilityInfo
                {
                    Id = "GHSA-test-1234",
                    Severity = "HIGH",
                    Summary = "Test vulnerability",
                    PackageId = "VulnerablePackage",
                    VulnerableVersionRange = "< 2.0.0",
                    PatchedVersion = "2.0.0",
                    Cves = ["CVE-2024-1234"]
                }
            ]
        };

        // Act
        var vex = _generator.Generate(packages, vulnerabilities);

        // Assert
        Assert.Single(vex.Statements);
        var statement = vex.Statements[0];
        Assert.Equal("GHSA-test-1234", statement.Vulnerability.Name);
        Assert.Contains("CVE-2024-1234", statement.Vulnerability.Aliases!);
    }

    [Fact]
    public void Generate_AffectedVersion_StatusIsAffected()
    {
        // Arrange
        var packages = new List<PackageHealth>
        {
            CreatePackageHealth("VulnerablePackage", "1.0.0") // Affected version
        };

        var vulnerabilities = new Dictionary<string, List<VulnerabilityInfo>>
        {
            ["VulnerablePackage"] =
            [
                new VulnerabilityInfo
                {
                    Id = "GHSA-test-1234",
                    Severity = "HIGH",
                    Summary = "Test vulnerability",
                    PackageId = "VulnerablePackage",
                    VulnerableVersionRange = "< 2.0.0",
                    PatchedVersion = "2.0.0"
                }
            ]
        };

        // Act
        var vex = _generator.Generate(packages, vulnerabilities);

        // Assert
        Assert.Single(vex.Statements);
        Assert.Equal(VexStatus.Affected, vex.Statements[0].Status);
        Assert.NotNull(vex.Statements[0].ActionStatement);
    }

    [Fact]
    public void Generate_PatchedVersion_StatusIsFixed()
    {
        // Arrange
        var packages = new List<PackageHealth>
        {
            CreatePackageHealth("VulnerablePackage", "2.0.0") // Patched version
        };

        var vulnerabilities = new Dictionary<string, List<VulnerabilityInfo>>
        {
            ["VulnerablePackage"] =
            [
                new VulnerabilityInfo
                {
                    Id = "GHSA-test-1234",
                    Severity = "HIGH",
                    Summary = "Test vulnerability",
                    PackageId = "VulnerablePackage",
                    VulnerableVersionRange = "< 2.0.0",
                    PatchedVersion = "2.0.0"
                }
            ]
        };

        // Act
        var vex = _generator.Generate(packages, vulnerabilities);

        // Assert
        Assert.Single(vex.Statements);
        Assert.Equal(VexStatus.Fixed, vex.Statements[0].Status);
    }

    [Fact]
    public void Generate_IncludesProductPurl()
    {
        // Arrange
        var packages = new List<PackageHealth>
        {
            CreatePackageHealth("TestPackage", "1.2.3")
        };

        var vulnerabilities = new Dictionary<string, List<VulnerabilityInfo>>
        {
            ["TestPackage"] =
            [
                new VulnerabilityInfo
                {
                    Id = "GHSA-test",
                    Severity = "MODERATE",
                    Summary = "Test",
                    PackageId = "TestPackage",
                    VulnerableVersionRange = "< 2.0.0"
                }
            ]
        };

        // Act
        var vex = _generator.Generate(packages, vulnerabilities);

        // Assert
        var product = vex.Statements[0].Products[0];
        Assert.Equal("pkg:nuget/TestPackage@1.2.3", product.Identifiers.Purl);
    }

    [Fact]
    public void Generate_MultipleVulnerabilities_CreatesMultipleStatements()
    {
        // Arrange
        var packages = new List<PackageHealth>
        {
            CreatePackageHealth("Package1", "1.0.0"),
            CreatePackageHealth("Package2", "1.0.0")
        };

        var vulnerabilities = new Dictionary<string, List<VulnerabilityInfo>>
        {
            ["Package1"] =
            [
                new VulnerabilityInfo
                {
                    Id = "GHSA-1",
                    Severity = "HIGH",
                    Summary = "Vuln 1",
                    PackageId = "Package1",
                    VulnerableVersionRange = "< 2.0.0"
                },
                new VulnerabilityInfo
                {
                    Id = "GHSA-2",
                    Severity = "CRITICAL",
                    Summary = "Vuln 2",
                    PackageId = "Package1",
                    VulnerableVersionRange = "< 3.0.0"
                }
            ],
            ["Package2"] =
            [
                new VulnerabilityInfo
                {
                    Id = "GHSA-3",
                    Severity = "LOW",
                    Summary = "Vuln 3",
                    PackageId = "Package2",
                    VulnerableVersionRange = "< 1.5.0"
                }
            ]
        };

        // Act
        var vex = _generator.Generate(packages, vulnerabilities);

        // Assert
        Assert.Equal(3, vex.Statements.Count);
    }

    private static PackageHealth CreatePackageHealth(string packageId, string version)
    {
        return new PackageHealth
        {
            PackageId = packageId,
            Version = version,
            Score = 50,
            Status = HealthStatus.Warning,
            Metrics = new PackageMetrics
            {
                DaysSinceLastRelease = 30,
                ReleasesPerYear = 2,
                DownloadTrend = 0,
                TotalDownloads = 10000
            }
        };
    }
}
