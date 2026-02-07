namespace DepSafe.Compliance;

public sealed class CycloneDxMetadata
{
    public required string Timestamp { get; init; }
    public List<CycloneDxTool>? Tools { get; init; }
    public CycloneDxComponent? Component { get; init; }
}
