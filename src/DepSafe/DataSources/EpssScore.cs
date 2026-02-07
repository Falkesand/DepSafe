namespace DepSafe.DataSources;

/// <summary>
/// EPSS score for a single CVE.
/// </summary>
public sealed class EpssScore
{
    /// <summary>CVE identifier (e.g., CVE-2021-44228).</summary>
    public required string Cve { get; init; }

    /// <summary>Probability of exploitation in the next 30 days (0.0-1.0).</summary>
    public required double Probability { get; init; }

    /// <summary>Percentile ranking relative to all scored CVEs (0.0-1.0).</summary>
    public required double Percentile { get; init; }
}
