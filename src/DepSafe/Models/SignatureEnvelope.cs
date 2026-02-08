using System.Text.Json.Serialization;

namespace DepSafe.Models;

/// <summary>
/// Parsed Sigil .sig.json detached signature envelope.
/// Contains the subject (artifact being signed) and one or more signatures.
/// </summary>
public sealed class SignatureEnvelope
{
    [JsonPropertyName("subject")]
    public required SignatureSubject Subject { get; init; }

    [JsonPropertyName("signatures")]
    public required List<SignatureEntry> Signatures { get; init; }
}
