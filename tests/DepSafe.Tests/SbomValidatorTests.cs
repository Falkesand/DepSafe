using DepSafe.Compliance;
using DepSafe.Models;

namespace DepSafe.Tests;

public class SbomValidatorTests
{
    [Fact]
    public void Validate_CompletePackages_ReturnsHighCompleteness()
    {
        var sbom = CreateSbom(new[]
        {
            CreatePackage("PackageA", supplier: "Vendor A", license: "MIT", hasPurl: true, hasChecksum: true),
            CreatePackage("PackageB", supplier: "Vendor B", license: "Apache-2.0", hasPurl: true, hasChecksum: true),
        });

        var result = SbomValidator.Validate(sbom);

        Assert.Equal(2, result.TotalPackages);
        Assert.Equal(2, result.WithSupplier);
        Assert.Equal(2, result.WithLicense);
        Assert.Equal(2, result.WithPurl);
        Assert.Equal(2, result.WithChecksum);
        Assert.True(result.HasTimestamp);
        Assert.True(result.HasCreator);
        Assert.Equal(100, result.CompletenessPercent);
    }

    [Fact]
    public void Validate_MissingSupplier_CountsCorrectly()
    {
        var sbom = CreateSbom(new[]
        {
            CreatePackage("PackageA", supplier: null, license: "MIT", hasPurl: true, hasChecksum: true),
            CreatePackage("PackageB", supplier: "Vendor B", license: "MIT", hasPurl: true, hasChecksum: true),
        });

        var result = SbomValidator.Validate(sbom);

        Assert.Equal(1, result.WithSupplier);
    }

    [Fact]
    public void Validate_NoassertionLicense_NotCounted()
    {
        var sbom = CreateSbom(new[]
        {
            CreatePackage("PackageA", supplier: "Vendor", license: "NOASSERTION", hasPurl: true, hasChecksum: true),
        });

        var result = SbomValidator.Validate(sbom);

        Assert.Equal(0, result.WithLicense);
    }

    [Fact]
    public void Validate_NoassertionSupplier_NotCounted()
    {
        var sbom = CreateSbom(new[]
        {
            CreatePackage("PackageA", supplier: "NOASSERTION", license: "MIT", hasPurl: true, hasChecksum: true),
        });

        var result = SbomValidator.Validate(sbom);

        Assert.Equal(0, result.WithSupplier);
    }

    [Fact]
    public void Validate_MissingTimestamp_FlagsIt()
    {
        var sbom = new SbomDocument
        {
            SpdxId = "SPDXRef-DOCUMENT",
            Name = "Test",
            DocumentNamespace = "https://example.com",
            CreationInfo = new SbomCreationInfo
            {
                Created = "",
                Creators = ["Tool: DepSafe"]
            },
            Packages = [],
            Relationships = []
        };

        var result = SbomValidator.Validate(sbom);

        Assert.False(result.HasTimestamp);
    }

    [Fact]
    public void Validate_MissingCreator_FlagsIt()
    {
        var sbom = new SbomDocument
        {
            SpdxId = "SPDXRef-DOCUMENT",
            Name = "Test",
            DocumentNamespace = "https://example.com",
            CreationInfo = new SbomCreationInfo
            {
                Created = "2025-01-01T00:00:00Z",
                Creators = []
            },
            Packages = [],
            Relationships = []
        };

        var result = SbomValidator.Validate(sbom);

        Assert.False(result.HasCreator);
    }

    [Fact]
    public void Validate_EmptyPackages_ReturnsDocumentLevelOnly()
    {
        var sbom = CreateSbom([]);

        var result = SbomValidator.Validate(sbom);

        Assert.Equal(0, result.TotalPackages);
        Assert.True(result.HasTimestamp);
        Assert.True(result.HasCreator);
    }

    [Fact]
    public void Validate_PackageWithPurlRef_DetectedByLocator()
    {
        var pkg = new SbomPackage
        {
            SpdxId = "SPDXRef-Package-Test",
            Name = "Test",
            VersionInfo = "1.0.0",
            DownloadLocation = "https://example.com",
            ExternalRefs =
            [
                new SbomExternalRef
                {
                    ReferenceCategory = "PACKAGE-MANAGER",
                    ReferenceType = "purl",
                    ReferenceLocator = "pkg:nuget/Test@1.0.0"
                }
            ]
        };

        var sbom = CreateSbom([pkg]);
        var result = SbomValidator.Validate(sbom);

        Assert.Equal(1, result.WithPurl);
    }

    private static SbomDocument CreateSbom(SbomPackage[] packages)
    {
        return new SbomDocument
        {
            SpdxId = "SPDXRef-DOCUMENT",
            Name = "Test SBOM",
            DocumentNamespace = "https://example.com/test",
            CreationInfo = new SbomCreationInfo
            {
                Created = "2025-01-01T00:00:00Z",
                Creators = ["Tool: DepSafe"]
            },
            Packages = packages.ToList(),
            Relationships = []
        };
    }

    private static SbomPackage CreatePackage(
        string name,
        string? supplier = null,
        string? license = null,
        bool hasPurl = false,
        bool hasChecksum = false)
    {
        var externalRefs = new List<SbomExternalRef>();
        if (hasPurl)
        {
            externalRefs.Add(new SbomExternalRef
            {
                ReferenceCategory = "PACKAGE-MANAGER",
                ReferenceType = "purl",
                ReferenceLocator = $"pkg:nuget/{name}@1.0.0"
            });
        }

        var checksums = hasChecksum
            ? new List<SbomChecksum>
            {
                new() { Algorithm = "SHA256", ChecksumValue = "abc123" }
            }
            : null;

        return new SbomPackage
        {
            SpdxId = $"SPDXRef-Package-{name}",
            Name = name,
            VersionInfo = "1.0.0",
            Supplier = supplier,
            DownloadLocation = $"https://nuget.org/packages/{name}",
            LicenseConcluded = license,
            ExternalRefs = externalRefs.Count > 0 ? externalRefs : null,
            Checksums = checksums
        };
    }
}
