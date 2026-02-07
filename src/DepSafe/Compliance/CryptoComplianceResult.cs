namespace DepSafe.Compliance;

/// <summary>
/// Result of crypto compliance check.
/// </summary>
public sealed class CryptoComplianceResult
{
    public required List<CryptoIssue> Issues { get; init; }
    public required List<string> CryptoPackagesFound { get; init; }
    public required bool IsCompliant { get; init; }
}
