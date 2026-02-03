using System.Text.Json.Serialization;

namespace NuGetHealthAnalyzer.Models;

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
    public string Tooling { get; init; } = "NuGetHealthAnalyzer";

    [JsonPropertyName("statements")]
    public required List<VexStatement> Statements { get; init; }
}

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
}

public sealed class VexVulnerability
{
    [JsonPropertyName("@id")]
    public required string Id { get; init; }

    [JsonPropertyName("name")]
    public required string Name { get; init; }

    [JsonPropertyName("description")]
    public string? Description { get; init; }

    [JsonPropertyName("aliases")]
    public List<string>? Aliases { get; init; }
}

public sealed class VexProduct
{
    [JsonPropertyName("@id")]
    public required string Id { get; init; }

    [JsonPropertyName("identifiers")]
    public required VexIdentifiers Identifiers { get; init; }
}

public sealed class VexIdentifiers
{
    [JsonPropertyName("purl")]
    public required string Purl { get; init; }
}

/// <summary>
/// VEX status values per the OpenVEX specification.
/// </summary>
public static class VexStatus
{
    public const string NotAffected = "not_affected";
    public const string Affected = "affected";
    public const string Fixed = "fixed";
    public const string UnderInvestigation = "under_investigation";
}

/// <summary>
/// VEX justification values per the OpenVEX specification.
/// </summary>
public static class VexJustification
{
    public const string ComponentNotPresent = "component_not_present";
    public const string VulnerableCodeNotPresent = "vulnerable_code_not_present";
    public const string VulnerableCodeNotInExecutePath = "vulnerable_code_not_in_execute_path";
    public const string VulnerableCodeCannotBeControlledByAdversary = "vulnerable_code_cannot_be_controlled_by_adversary";
    public const string InlineMitigationsAlreadyExist = "inline_mitigations_already_exist";
}
