namespace DepSafe.Scoring;

/// <summary>
/// Configurable weights for health score calculation.
/// </summary>
public sealed class ScoreWeights
{
    /// <summary>Weight for freshness (days since release). Default: 25%</summary>
    public double Freshness { get; init; } = 0.25;

    /// <summary>Weight for release cadence (releases per year). Default: 15%</summary>
    public double ReleaseCadence { get; init; } = 0.15;

    /// <summary>Weight for download trend. Default: 20%</summary>
    public double DownloadTrend { get; init; } = 0.20;

    /// <summary>Weight for repository activity. Default: 25%</summary>
    public double RepositoryActivity { get; init; } = 0.25;

    /// <summary>Weight for known vulnerabilities. Default: 15%</summary>
    public double Vulnerabilities { get; init; } = 0.15;

    /// <summary>
    /// Default weights as defined in the plan.
    /// </summary>
    public static ScoreWeights Default => new();

    /// <summary>
    /// Validates that weights sum to 1.0.
    /// </summary>
    public bool IsValid()
    {
        var sum = Freshness + ReleaseCadence + DownloadTrend + RepositoryActivity + Vulnerabilities;
        return Math.Abs(sum - 1.0) < 0.001;
    }
}
