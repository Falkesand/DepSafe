using System.Text.Json.Serialization;

namespace DepSafe.Models;

/// <summary>
/// The subject (artifact) within a Sigil signature envelope.
/// </summary>
public sealed class SignatureSubject
{
    [JsonPropertyName("name")]
    public required string Name { get; init; }

    [JsonPropertyName("digests")]
    public required Dictionary<string, string> Digests { get; init; }

    [JsonPropertyName("mediaType")]
    public string? MediaType { get; init; }

    [JsonPropertyName("metadata")]
    public Dictionary<string, string>? Metadata { get; init; }
}
