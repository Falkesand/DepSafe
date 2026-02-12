namespace DepSafe.Models;

public sealed record TrendSummary(
    List<TrendMetric> Metrics,
    int SnapshotCount,
    DateTime? FirstSnapshot,
    DateTime? LastSnapshot,
    TrendDirection OverallDirection);
