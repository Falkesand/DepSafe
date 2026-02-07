using System.Text.Json.Serialization;

namespace DepSafe.Models;

public sealed class SbomChecksum
{
    [JsonPropertyName("algorithm")]
    public required string Algorithm { get; init; }

    [JsonPropertyName("checksumValue")]
    public required string ChecksumValue { get; init; }
}
