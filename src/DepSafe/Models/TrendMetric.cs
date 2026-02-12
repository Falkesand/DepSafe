namespace DepSafe.Models;

public sealed record TrendMetric(
    string Name,
    int CurrentValue,
    int? PreviousValue,
    int? Delta,
    TrendDirection Direction,
    bool HigherIsBetter);
