namespace DepSafe.Compliance;

/// <summary>
/// A crypto compliance issue.
/// </summary>
public sealed class CryptoIssue
{
    public required string PackageId { get; init; }
    public required string Version { get; init; }
    public required string Issue { get; init; }
    public required string Severity { get; init; }
}
