using System.Text.Json.Serialization;

namespace DepSafe.Models;

public sealed class VexIdentifiers
{
    [JsonPropertyName("purl")]
    public required string Purl { get; init; }
}
