using System.Collections.Frozen;
using DepSafe.Models;

namespace DepSafe.Compliance;

/// <summary>
/// Generates SBOM documents in SPDX 3.0 format.
/// </summary>
public sealed class SbomGenerator
{
    private static readonly FrozenDictionary<string, string> SpdxLicenseMap = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
    {
        ["MIT"] = "MIT",
        ["APACHE-2.0"] = "Apache-2.0",
        ["APACHE 2.0"] = "Apache-2.0",
        ["APACHE LICENSE 2.0"] = "Apache-2.0",
        ["BSD-3-CLAUSE"] = "BSD-3-Clause",
        ["BSD 3-CLAUSE"] = "BSD-3-Clause",
        ["BSD-2-CLAUSE"] = "BSD-2-Clause",
        ["BSD 2-CLAUSE"] = "BSD-2-Clause",
        ["GPL-3.0"] = "GPL-3.0-only",
        ["GPL 3.0"] = "GPL-3.0-only",
        ["GPLV3"] = "GPL-3.0-only",
        ["GPL-2.0"] = "GPL-2.0-only",
        ["GPL 2.0"] = "GPL-2.0-only",
        ["GPLV2"] = "GPL-2.0-only",
        ["LGPL-3.0"] = "LGPL-3.0-only",
        ["LGPLV3"] = "LGPL-3.0-only",
        ["LGPL-2.1"] = "LGPL-2.1-only",
        ["LGPLV2.1"] = "LGPL-2.1-only",
        ["MPL-2.0"] = "MPL-2.0",
        ["MOZILLA PUBLIC LICENSE 2.0"] = "MPL-2.0",
        ["ISC"] = "ISC",
        ["UNLICENSE"] = "Unlicense",
        ["CC0-1.0"] = "CC0-1.0"
    }.ToFrozenDictionary(StringComparer.OrdinalIgnoreCase);

    private readonly string _toolName;
    private readonly string _toolVersion;

    public SbomGenerator(string? toolName = null, string? toolVersion = null)
    {
        _toolName = toolName ?? "DepSafe";
        var asmVersion = typeof(SbomGenerator).Assembly.GetName().Version;
        _toolVersion = toolVersion ?? (asmVersion is not null ? $"{asmVersion.Major}.{asmVersion.Minor}.{asmVersion.Build}" : "1.0.0");
    }

    /// <summary>
    /// Generate SPDX 3.0 SBOM from analyzed packages.
    /// </summary>
    public SbomDocument Generate(string projectName, string projectVersion, IEnumerable<PackageHealth> packages)
    {
        var packageList = packages.ToList();
        var docId = $"SPDXRef-DOCUMENT-{Guid.NewGuid():N}";
        var timestamp = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ");

        var sbomPackages = packageList.Select((pkg, index) => new SbomPackage
        {
            SpdxId = $"SPDXRef-Package-{SanitizeId(pkg.PackageId)}",
            Name = pkg.PackageId,
            VersionInfo = pkg.Version,
            Supplier = FormatSupplier(pkg.Authors),
            DownloadLocation = GetDownloadLocation(pkg),
            FilesAnalyzed = false,
            LicenseConcluded = MapLicenseToSpdx(pkg.License),
            LicenseDeclared = MapLicenseToSpdx(pkg.License),
            CopyrightText = "NOASSERTION",
            ExternalRefs =
            [
                new SbomExternalRef
                {
                    ReferenceCategory = "PACKAGE-MANAGER",
                    ReferenceType = "purl",
                    ReferenceLocator = GetPurl(pkg)
                }
            ],
            Checksums = ParseIntegrity(pkg.ContentIntegrity),
            Ecosystem = pkg.Ecosystem
        }).ToList();

        var relationships = sbomPackages.Select(pkg => new SbomRelationship
        {
            SpdxElementId = docId,
            RelatedSpdxElement = pkg.SpdxId,
            RelationshipType = "DESCRIBES"
        }).ToList();

        // Add dependency relationships between root and packages
        var rootPackage = new SbomPackage
        {
            SpdxId = $"SPDXRef-RootPackage-{SanitizeId(projectName)}",
            Name = projectName,
            VersionInfo = projectVersion,
            Supplier = "NOASSERTION",
            DownloadLocation = "NOASSERTION",
            FilesAnalyzed = false,
            LicenseConcluded = "NOASSERTION",
            LicenseDeclared = "NOASSERTION",
            CopyrightText = "NOASSERTION"
        };

        sbomPackages.Insert(0, rootPackage);

        foreach (var pkg in sbomPackages.Skip(1))
        {
            relationships.Add(new SbomRelationship
            {
                SpdxElementId = rootPackage.SpdxId,
                RelatedSpdxElement = pkg.SpdxId,
                RelationshipType = "DEPENDS_ON"
            });
        }

        return new SbomDocument
        {
            SpdxId = docId,
            Name = $"SBOM for {projectName}",
            DocumentNamespace = $"https://nuget-health.dev/sbom/{Guid.NewGuid()}",
            CreationInfo = new SbomCreationInfo
            {
                Created = timestamp,
                Creators = [$"Tool: {_toolName}-{_toolVersion}"]
            },
            Packages = sbomPackages,
            Relationships = relationships
        };
    }

    /// <summary>
    /// Generate CycloneDX format SBOM.
    /// </summary>
    public CycloneDxBom GenerateCycloneDx(string projectName, string projectVersion, IEnumerable<PackageHealth> packages)
    {
        var packageList = packages.ToList();
        var timestamp = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ");

        return new CycloneDxBom
        {
            BomFormat = "CycloneDX",
            SpecVersion = "1.5",
            SerialNumber = $"urn:uuid:{Guid.NewGuid()}",
            Version = 1,
            Metadata = new CycloneDxMetadata
            {
                Timestamp = timestamp,
                Tools =
                [
                    new CycloneDxTool
                    {
                        Vendor = "DepSafe",
                        Name = _toolName,
                        Version = _toolVersion
                    }
                ],
                Component = new CycloneDxComponent
                {
                    Type = "application",
                    Name = projectName,
                    Version = projectVersion,
                    BomRef = $"pkg:generic/{SanitizeId(projectName)}"
                }
            },
            Components = packageList.Select(pkg => new CycloneDxComponent
            {
                Type = "library",
                BomRef = GetPurl(pkg),
                Name = pkg.PackageId,
                Version = pkg.Version,
                Purl = GetPurl(pkg),
                Licenses = string.IsNullOrEmpty(pkg.License) ? null :
                [
                    new CycloneDxLicense
                    {
                        Id = MapLicenseToSpdx(pkg.License)
                    }
                ],
                ExternalReferences =
                [
                    new CycloneDxExternalRef
                    {
                        Type = "distribution",
                        Url = GetDownloadLocation(pkg)
                    }
                ]
            }).ToList()
        };
    }

    private static List<SbomChecksum>? ParseIntegrity(string? integrity)
    {
        if (string.IsNullOrEmpty(integrity)) return null;

        // Format: "sha512-base64data==" or "sha256-base64data=="
        var dashIndex = integrity.IndexOf('-');
        if (dashIndex < 0) return null;

        var algorithm = integrity[..dashIndex].ToUpperInvariant();
        var hash = integrity[(dashIndex + 1)..];
        return [new SbomChecksum { Algorithm = algorithm, ChecksumValue = hash }];
    }

    private static string SanitizeId(string input)
    {
        foreach (var c in input)
        {
            if (!char.IsLetterOrDigit(c) && c != '-' && c != '.')
            {
                var sb = new System.Text.StringBuilder(input.Length);
                foreach (var ch in input)
                {
                    if (char.IsLetterOrDigit(ch) || ch == '-' || ch == '.')
                        sb.Append(ch);
                }
                return sb.ToString();
            }
        }
        return input;
    }

    private static string GetDownloadLocation(PackageHealth pkg)
    {
        return pkg.Ecosystem == PackageEcosystem.Npm
            ? $"https://www.npmjs.com/package/{Uri.EscapeDataString(pkg.PackageId)}/v/{pkg.Version}"
            : $"https://www.nuget.org/packages/{pkg.PackageId}/{pkg.Version}";
    }

    private static string GetPurl(PackageHealth pkg)
    {
        return pkg.Ecosystem == PackageEcosystem.Npm
            ? $"pkg:npm/{Uri.EscapeDataString(pkg.PackageId)}@{pkg.Version}"
            : $"pkg:nuget/{pkg.PackageId}@{pkg.Version}";
    }

    private static string FormatSupplier(IReadOnlyList<string> authors)
    {
        if (authors.Count == 0) return "NOASSERTION";
        var joined = string.Join(", ", authors);
        if (string.IsNullOrWhiteSpace(joined)) return "NOASSERTION";
        return $"Organization: {joined}";
    }

    private static string MapLicenseToSpdx(string? license)
    {
        if (string.IsNullOrEmpty(license)) return "NOASSERTION";

        if (SpdxLicenseMap.TryGetValue(license, out var spdx))
            return spdx;

        return license.Contains("http") ? "NOASSERTION" : license;
    }
}
