namespace NuGetHealthAnalyzer.Models;

/// <summary>
/// Health assessment for a single NuGet package.
/// </summary>
public sealed class PackageHealth
{
    public required string PackageId { get; init; }
    public required string Version { get; init; }
    public required int Score { get; init; }
    public required HealthStatus Status { get; init; }
    public required PackageMetrics Metrics { get; init; }
    public string? RepositoryUrl { get; init; }
    public string? License { get; init; }
    public List<string> Vulnerabilities { get; init; } = [];
    public List<string> Recommendations { get; init; } = [];
}

public enum HealthStatus
{
    Healthy,   // 80-100
    Watch,     // 60-79
    Warning,   // 40-59
    Critical   // 0-39
}

/// <summary>
/// Raw metrics used to calculate health score.
/// </summary>
public sealed class PackageMetrics
{
    /// <summary>Days since last release.</summary>
    public int DaysSinceLastRelease { get; init; }

    /// <summary>Average releases per year over the past 3 years.</summary>
    public double ReleasesPerYear { get; init; }

    /// <summary>Download trend: positive = growing, negative = declining.</summary>
    public double DownloadTrend { get; init; }

    /// <summary>Total downloads.</summary>
    public long TotalDownloads { get; init; }

    /// <summary>Days since last repository commit (if available).</summary>
    public int? DaysSinceLastCommit { get; init; }

    /// <summary>Open issues count (if available).</summary>
    public int? OpenIssues { get; init; }

    /// <summary>Repository stars (if available).</summary>
    public int? Stars { get; init; }

    /// <summary>Number of known vulnerabilities.</summary>
    public int VulnerabilityCount { get; init; }
}

/// <summary>
/// Package reference from a project file.
/// </summary>
public sealed class PackageReference
{
    public required string PackageId { get; init; }
    public required string Version { get; init; }
    public string? SourceFile { get; init; }
}
