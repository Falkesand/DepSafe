namespace DepSafe.Compliance;

/// <summary>
/// Result of release readiness evaluation: go/no-go classification.
/// </summary>
public sealed class ReleaseReadinessResult
{
    public bool IsReady => BlockingItems.Count == 0;
    public required IReadOnlyList<ReleaseBlocker> BlockingItems { get; init; }
    public required IReadOnlyList<string> AdvisoryItems { get; init; }
}
