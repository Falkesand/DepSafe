namespace DepSafe.Models;

/// <summary>
/// Raw metrics used to calculate health score.
/// </summary>
public sealed class PackageMetrics
{
    /// <summary>Days since last release. Null if release date unknown.</summary>
    public int? DaysSinceLastRelease { get; init; }

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
