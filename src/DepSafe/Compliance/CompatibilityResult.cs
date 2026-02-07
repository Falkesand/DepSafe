namespace DepSafe.Compliance;

/// <summary>
/// Result of a license compatibility check.
/// </summary>
public sealed class CompatibilityResult
{
    public required bool IsCompatible { get; init; }
    public required string Severity { get; init; } // "Error", "Warning", "Info"
    public required string Message { get; init; }
    public string? Recommendation { get; init; }
}
