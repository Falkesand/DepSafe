using System.Text.Json.Serialization;

namespace DepSafe.Models;

/// <summary>
/// VEX (Vulnerability Exploitability eXchange) document following OpenVEX format.
/// </summary>
public sealed class VexDocument
{
    [JsonPropertyName("@context")]
    public string Context { get; init; } = "https://openvex.dev/ns/v0.2.0";

    [JsonPropertyName("@id")]
    public required string Id { get; init; }

    [JsonPropertyName("author")]
    public required string Author { get; init; }

    [JsonPropertyName("timestamp")]
    public required string Timestamp { get; init; }

    [JsonPropertyName("version")]
    public int Version { get; init; } = 1;

    [JsonPropertyName("tooling")]
    public string Tooling { get; init; } = "DepSafe";

    [JsonPropertyName("statements")]
    public required List<VexStatement> Statements { get; init; }
}
