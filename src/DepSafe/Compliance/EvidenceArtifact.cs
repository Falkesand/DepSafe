namespace DepSafe.Compliance;

/// <summary>
/// A single artifact in an evidence pack with integrity checksum.
/// </summary>
public sealed class EvidenceArtifact
{
    public required string Type { get; init; }
    public required string File { get; init; }
    public required string Sha256 { get; init; }
}
