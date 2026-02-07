using System.Text.Json.Serialization;

namespace DepSafe.Models;

public sealed class SbomCreationInfo
{
    [JsonPropertyName("created")]
    public required string Created { get; init; }

    [JsonPropertyName("creators")]
    public required List<string> Creators { get; init; }

    [JsonPropertyName("licenseListVersion")]
    public string LicenseListVersion { get; init; } = "3.21";
}
