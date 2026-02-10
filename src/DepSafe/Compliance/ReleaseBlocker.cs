namespace DepSafe.Compliance;

/// <summary>
/// A blocking issue that prevents release readiness.
/// </summary>
public sealed class ReleaseBlocker
{
    public required string Requirement { get; init; }
    public required string Reason { get; init; }
}
