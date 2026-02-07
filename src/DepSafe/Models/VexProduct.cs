using System.Text.Json.Serialization;

namespace DepSafe.Models;

public sealed class VexProduct
{
    [JsonPropertyName("@id")]
    public required string Id { get; init; }

    [JsonPropertyName("identifiers")]
    public required VexIdentifiers Identifiers { get; init; }
}
