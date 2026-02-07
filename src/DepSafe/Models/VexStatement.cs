using System.Text.Json.Serialization;

namespace DepSafe.Models;

public sealed class VexStatement
{
    [JsonPropertyName("vulnerability")]
    public required VexVulnerability Vulnerability { get; init; }

    [JsonPropertyName("products")]
    public required List<VexProduct> Products { get; init; }

    [JsonPropertyName("status")]
    public required string Status { get; init; }

    [JsonPropertyName("justification")]
    public string? Justification { get; init; }

    [JsonPropertyName("action_statement")]
    public string? ActionStatement { get; init; }

    [JsonPropertyName("impact_statement")]
    public string? ImpactStatement { get; init; }

    /// <summary>Version that fixes the vulnerability (if known).</summary>
    [JsonPropertyName("patched_version")]
    public string? PatchedVersion { get; init; }
}
