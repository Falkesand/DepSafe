namespace DepSafe.Models;

public sealed class ProjectSummary
{
    public int TotalPackages { get; init; }
    public int HealthyCount { get; init; }
    public int WatchCount { get; init; }
    public int WarningCount { get; init; }
    public int CriticalCount { get; init; }
    public int VulnerableCount { get; init; }
}
