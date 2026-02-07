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
