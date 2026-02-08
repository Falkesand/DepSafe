using System.Text.Json.Serialization;

namespace DepSafe.Models;

/// <summary>
/// A single cryptographic signature within a Sigil signature envelope.
/// </summary>
public sealed class SignatureEntry
{
    [JsonPropertyName("keyId")]
    public required string KeyId { get; init; }

    [JsonPropertyName("algorithm")]
    public required string Algorithm { get; init; }

    [JsonPropertyName("publicKey")]
    public string? PublicKey { get; init; }

    [JsonPropertyName("value")]
    public required string Value { get; init; }

    [JsonPropertyName("timestamp")]
    public DateTime? Timestamp { get; init; }

    [JsonPropertyName("label")]
    public string? Label { get; init; }
}
