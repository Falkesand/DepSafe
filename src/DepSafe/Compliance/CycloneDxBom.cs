namespace DepSafe.Compliance;

public sealed class CycloneDxBom
{
    public string BomFormat { get; init; } = "CycloneDX";
    public string SpecVersion { get; init; } = "1.5";
    public required string SerialNumber { get; init; }
    public int Version { get; init; } = 1;
    public required CycloneDxMetadata Metadata { get; init; }
    public required List<CycloneDxComponent> Components { get; init; }
}
