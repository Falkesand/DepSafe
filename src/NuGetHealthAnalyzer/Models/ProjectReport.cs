namespace NuGetHealthAnalyzer.Models;

/// <summary>
/// Health report for an entire project or solution.
/// </summary>
public sealed class ProjectReport
{
    public required string ProjectPath { get; init; }
    public required DateTime GeneratedAt { get; init; }
    public required int OverallScore { get; init; }
    public required HealthStatus OverallStatus { get; init; }
    public required List<PackageHealth> Packages { get; init; }
    public required ProjectSummary Summary { get; init; }
}

public sealed class ProjectSummary
{
    public int TotalPackages { get; init; }
    public int HealthyCount { get; init; }
    public int WatchCount { get; init; }
    public int WarningCount { get; init; }
    public int CriticalCount { get; init; }
    public int VulnerableCount { get; init; }
}
