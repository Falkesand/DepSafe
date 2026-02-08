using System.Text.Json.Serialization;

namespace DepSafe.DataSources;

public sealed partial class OsvApiClient
{
    // OSV API request/response models
    internal sealed class OsvBatchRequest
    {
        [JsonPropertyName("queries")]
        public required List<OsvQuery> Queries { get; init; }
    }

    internal sealed class OsvQuery
    {
        [JsonPropertyName("package")]
        public required OsvPackage Package { get; init; }

        [JsonPropertyName("version")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string? Version { get; init; }
    }

    internal sealed class OsvPackage
    {
        [JsonPropertyName("name")]
        public required string Name { get; init; }

        [JsonPropertyName("ecosystem")]
        public required string Ecosystem { get; init; }
    }

    internal sealed class OsvBatchResponse
    {
        [JsonPropertyName("results")]
        public List<OsvQueryResult>? Results { get; init; }
    }

    internal sealed class OsvQueryResult
    {
        [JsonPropertyName("vulns")]
        public List<OsvVulnerability>? Vulns { get; init; }
    }

    internal sealed class OsvVulnerability
    {
        [JsonPropertyName("id")]
        public string? Id { get; init; }

        [JsonPropertyName("summary")]
        public string? Summary { get; init; }

        [JsonPropertyName("details")]
        public string? Details { get; init; }

        [JsonPropertyName("published")]
        public string? Published { get; init; }

        [JsonPropertyName("modified")]
        public string? Modified { get; init; }

        [JsonPropertyName("severity")]
        public List<OsvSeverity>? Severity { get; init; }

        [JsonPropertyName("affected")]
        public List<OsvAffected>? Affected { get; init; }

        [JsonPropertyName("references")]
        public List<OsvReference>? References { get; init; }

        [JsonPropertyName("database_specific")]
        public OsvDatabaseSpecific? DatabaseSpecific { get; init; }
    }

    internal sealed class OsvSeverity
    {
        [JsonPropertyName("type")]
        public string? Type { get; init; }

        [JsonPropertyName("score")]
        public string? Score { get; init; }
    }

    internal sealed class OsvAffected
    {
        [JsonPropertyName("package")]
        public OsvPackage? Package { get; init; }

        [JsonPropertyName("ranges")]
        public List<OsvRange>? Ranges { get; init; }

        [JsonPropertyName("versions")]
        public List<string>? Versions { get; init; }
    }

    internal sealed class OsvRange
    {
        [JsonPropertyName("type")]
        public string? Type { get; init; }

        [JsonPropertyName("events")]
        public List<OsvEvent>? Events { get; init; }
    }

    internal sealed class OsvEvent
    {
        [JsonPropertyName("introduced")]
        public string? Introduced { get; init; }

        [JsonPropertyName("fixed")]
        public string? Fixed { get; init; }
    }

    internal sealed class OsvReference
    {
        [JsonPropertyName("type")]
        public string? Type { get; init; }

        [JsonPropertyName("url")]
        public string? Url { get; init; }
    }

    internal sealed class OsvDatabaseSpecific
    {
        [JsonPropertyName("severity")]
        public string? Severity { get; init; }

        [JsonPropertyName("cwe_ids")]
        public List<string>? CweIds { get; init; }
    }
}
