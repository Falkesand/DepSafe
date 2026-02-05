using System.Text.Json.Serialization;

namespace DepSafe.Models;

/// <summary>
/// SPDX 3.0 compatible SBOM document.
/// </summary>
public sealed class SbomDocument
{
    [JsonPropertyName("spdxVersion")]
    public string SpdxVersion { get; init; } = "SPDX-3.0";

    [JsonPropertyName("dataLicense")]
    public string DataLicense { get; init; } = "CC0-1.0";

    [JsonPropertyName("SPDXID")]
    public required string SpdxId { get; init; }

    [JsonPropertyName("name")]
    public required string Name { get; init; }

    [JsonPropertyName("documentNamespace")]
    public required string DocumentNamespace { get; init; }

    [JsonPropertyName("creationInfo")]
    public required SbomCreationInfo CreationInfo { get; init; }

    [JsonPropertyName("packages")]
    public required List<SbomPackage> Packages { get; init; }

    [JsonPropertyName("relationships")]
    public required List<SbomRelationship> Relationships { get; init; }
}

public sealed class SbomCreationInfo
{
    [JsonPropertyName("created")]
    public required string Created { get; init; }

    [JsonPropertyName("creators")]
    public required List<string> Creators { get; init; }

    [JsonPropertyName("licenseListVersion")]
    public string LicenseListVersion { get; init; } = "3.21";
}

public sealed class SbomPackage
{
    [JsonPropertyName("SPDXID")]
    public required string SpdxId { get; init; }

    [JsonPropertyName("name")]
    public required string Name { get; init; }

    [JsonPropertyName("versionInfo")]
    public required string VersionInfo { get; init; }

    [JsonPropertyName("supplier")]
    public string? Supplier { get; init; }

    [JsonPropertyName("downloadLocation")]
    public required string DownloadLocation { get; init; }

    [JsonPropertyName("filesAnalyzed")]
    public bool FilesAnalyzed { get; init; } = false;

    [JsonPropertyName("licenseConcluded")]
    public string? LicenseConcluded { get; init; }

    [JsonPropertyName("licenseDeclared")]
    public string? LicenseDeclared { get; init; }

    [JsonPropertyName("copyrightText")]
    public string CopyrightText { get; init; } = "NOASSERTION";

    [JsonPropertyName("externalRefs")]
    public List<SbomExternalRef>? ExternalRefs { get; init; }

    [JsonPropertyName("checksums")]
    public List<SbomChecksum>? Checksums { get; init; }

    /// <summary>Package ecosystem for internal use (not serialized to SBOM).</summary>
    [JsonIgnore]
    public PackageEcosystem Ecosystem { get; init; } = PackageEcosystem.NuGet;
}

public sealed class SbomExternalRef
{
    [JsonPropertyName("referenceCategory")]
    public required string ReferenceCategory { get; init; }

    [JsonPropertyName("referenceType")]
    public required string ReferenceType { get; init; }

    [JsonPropertyName("referenceLocator")]
    public required string ReferenceLocator { get; init; }
}

public sealed class SbomChecksum
{
    [JsonPropertyName("algorithm")]
    public required string Algorithm { get; init; }

    [JsonPropertyName("checksumValue")]
    public required string ChecksumValue { get; init; }
}

public sealed class SbomRelationship
{
    [JsonPropertyName("spdxElementId")]
    public required string SpdxElementId { get; init; }

    [JsonPropertyName("relatedSpdxElement")]
    public required string RelatedSpdxElement { get; init; }

    [JsonPropertyName("relationshipType")]
    public required string RelationshipType { get; init; }
}
