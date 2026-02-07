using System.Text.Json.Serialization;

namespace DepSafe.Models;

public sealed class SbomRelationship
{
    [JsonPropertyName("spdxElementId")]
    public required string SpdxElementId { get; init; }

    [JsonPropertyName("relatedSpdxElement")]
    public required string RelatedSpdxElement { get; init; }

    [JsonPropertyName("relationshipType")]
    public required string RelationshipType { get; init; }
}
