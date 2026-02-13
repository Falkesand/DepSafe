using DepSafe.Compliance;
using DepSafe.Models;

namespace DepSafe.Tests;

public class SbomGeneratorTests
{
    private readonly SbomGenerator _generator = new();

    [Fact]
    public void Generate_CreatesValidSpdxDocument()
    {
        // Arrange
        var packages = CreateTestPackages();

        // Act
        var sbom = _generator.Generate("TestProject", "1.0.0", packages);

        // Assert
        Assert.Equal("SPDX-3.0", sbom.SpdxVersion);
        Assert.Equal("CC0-1.0", sbom.DataLicense);
        Assert.StartsWith("SPDXRef-DOCUMENT", sbom.SpdxId);
        Assert.Contains("TestProject", sbom.Name);
        Assert.NotNull(sbom.CreationInfo);
        Assert.NotEmpty(sbom.CreationInfo.Creators);
    }

    [Fact]
    public void Generate_IncludesAllPackages()
    {
        // Arrange
        var packages = CreateTestPackages();

        // Act
        var sbom = _generator.Generate("TestProject", "1.0.0", packages);

        // Assert
        // Should have root package + all dependency packages
        Assert.Equal(packages.Count + 1, sbom.Packages.Count);
    }

    [Fact]
    public void Generate_CreatesPackageUrls()
    {
        // Arrange
        var packages = new List<PackageHealth>
        {
            CreatePackageHealth("Newtonsoft.Json", "13.0.3", "MIT")
        };

        // Act
        var sbom = _generator.Generate("TestProject", "1.0.0", packages);

        // Assert
        var pkg = sbom.Packages.FirstOrDefault(p => p.Name == "Newtonsoft.Json");
        Assert.NotNull(pkg);
        Assert.Contains("nuget.org", pkg.DownloadLocation);
        Assert.NotNull(pkg.ExternalRefs);
        Assert.Contains(pkg.ExternalRefs, r => r.ReferenceType == "purl" &&
            r.ReferenceLocator == "pkg:nuget/Newtonsoft.Json@13.0.3");
    }

    [Fact]
    public void Generate_MapsLicensesToSpdx()
    {
        // Arrange
        var packages = new List<PackageHealth>
        {
            CreatePackageHealth("Package1", "1.0.0", "MIT"),
            CreatePackageHealth("Package2", "1.0.0", "Apache-2.0"),
            CreatePackageHealth("Package3", "1.0.0", null)
        };

        // Act
        var sbom = _generator.Generate("TestProject", "1.0.0", packages);

        // Assert
        var mitPkg = sbom.Packages.FirstOrDefault(p => p.Name == "Package1");
        var apachePkg = sbom.Packages.FirstOrDefault(p => p.Name == "Package2");
        var noLicensePkg = sbom.Packages.FirstOrDefault(p => p.Name == "Package3");

        Assert.Equal("MIT", mitPkg?.LicenseConcluded);
        Assert.Equal("Apache-2.0", apachePkg?.LicenseConcluded);
        Assert.Equal("NOASSERTION", noLicensePkg?.LicenseConcluded);
    }

    [Fact]
    public void Generate_CreatesRelationships()
    {
        // Arrange
        var packages = CreateTestPackages();

        // Act
        var sbom = _generator.Generate("TestProject", "1.0.0", packages);

        // Assert
        // Should have DESCRIBES relationships from document to packages
        // and DEPENDS_ON relationships from root to dependencies
        Assert.NotEmpty(sbom.Relationships);
        Assert.Contains(sbom.Relationships, r => r.RelationshipType == "DESCRIBES");
        Assert.Contains(sbom.Relationships, r => r.RelationshipType == "DEPENDS_ON");
    }

    [Fact]
    public void GenerateCycloneDx_CreatesValidDocument()
    {
        // Arrange
        var packages = CreateTestPackages();

        // Act
        var bom = _generator.GenerateCycloneDx("TestProject", "1.0.0", packages);

        // Assert
        Assert.Equal("CycloneDX", bom.BomFormat);
        Assert.Equal("1.5", bom.SpecVersion);
        Assert.StartsWith("urn:uuid:", bom.SerialNumber);
        Assert.NotNull(bom.Metadata);
        Assert.NotNull(bom.Components);
        Assert.Equal(packages.Count, bom.Components.Count);
    }

    [Fact]
    public void GenerateCycloneDx_IncludesPurls()
    {
        // Arrange
        var packages = new List<PackageHealth>
        {
            CreatePackageHealth("Serilog", "3.1.1", "Apache-2.0")
        };

        // Act
        var bom = _generator.GenerateCycloneDx("TestProject", "1.0.0", packages);

        // Assert
        var component = bom.Components.FirstOrDefault(c => c.Name == "Serilog");
        Assert.NotNull(component);
        Assert.Equal("pkg:nuget/Serilog@3.1.1", component.Purl);
        Assert.Equal("library", component.Type);
    }

    [Fact]
    public void Generate_UsesProjectVersion()
    {
        var packages = new List<PackageHealth>
        {
            CreatePackageHealth("Newtonsoft.Json", "13.0.1", null)
        };

        var result = _generator.Generate("TestProject", "2.5.0", packages);

        var rootPackage = result.Packages.First(p => p.Name == "TestProject");
        Assert.Equal("2.5.0", rootPackage.VersionInfo);
    }

    [Fact]
    public void GenerateCycloneDx_UsesProjectVersion()
    {
        var packages = new List<PackageHealth>
        {
            CreatePackageHealth("Newtonsoft.Json", "13.0.1", null)
        };

        var result = _generator.GenerateCycloneDx("TestProject", "3.0.0-beta", packages);

        Assert.NotNull(result.Metadata);
        Assert.NotNull(result.Metadata.Component);
        Assert.Equal("3.0.0-beta", result.Metadata.Component.Version);
    }

    private static List<PackageHealth> CreateTestPackages()
    {
        return
        [
            CreatePackageHealth("Newtonsoft.Json", "13.0.3", "MIT"),
            CreatePackageHealth("Serilog", "3.1.1", "Apache-2.0"),
            CreatePackageHealth("AutoMapper", "12.0.1", "MIT")
        ];
    }

    private static PackageHealth CreatePackageHealth(string packageId, string version, string? license)
    {
        return new PackageHealth
        {
            PackageId = packageId,
            Version = version,
            Score = 85,
            Status = HealthStatus.Healthy,
            License = license,
            Metrics = new PackageMetrics
            {
                DaysSinceLastRelease = 30,
                ReleasesPerYear = 4,
                DownloadTrend = 0.1,
                TotalDownloads = 100000
            }
        };
    }
}
