namespace DepSafe.Compliance;

/// <summary>
/// Manifest for an evidence pack containing all CRA compliance artifacts.
/// </summary>
public sealed class EvidencePackManifest
{
    public required DateTime GeneratedAt { get; init; }
    public required string ToolVersion { get; init; }
    public required string ProjectPath { get; init; }
    public required List<EvidenceArtifact> Artifacts { get; init; }
    public bool Signed { get; init; }
}
