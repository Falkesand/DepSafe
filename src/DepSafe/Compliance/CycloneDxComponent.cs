namespace DepSafe.Compliance;

public sealed class CycloneDxComponent
{
    public required string Type { get; init; }
    public string? BomRef { get; init; }
    public required string Name { get; init; }
    public string? Version { get; init; }
    public string? Purl { get; init; }
    public List<CycloneDxLicense>? Licenses { get; init; }
    public List<CycloneDxExternalRef>? ExternalReferences { get; init; }
}
