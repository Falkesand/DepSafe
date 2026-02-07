using System.Text.Json.Serialization;

namespace DepSafe.Models;

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
    public List<SbomChecksum>? Checksums { get; set; }

    /// <summary>Package ecosystem for internal use (not serialized to SBOM).</summary>
    [JsonIgnore]
    public PackageEcosystem Ecosystem { get; init; } = PackageEcosystem.NuGet;
}
