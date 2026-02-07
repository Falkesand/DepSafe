using System.Text.Json.Serialization;

namespace DepSafe.Models;

public sealed class SbomExternalRef
{
    [JsonPropertyName("referenceCategory")]
    public required string ReferenceCategory { get; init; }

    [JsonPropertyName("referenceType")]
    public required string ReferenceType { get; init; }

    [JsonPropertyName("referenceLocator")]
    public required string ReferenceLocator { get; init; }
}
