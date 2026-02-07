namespace DepSafe.Compliance;

/// <summary>
/// Complete license analysis report.
/// </summary>
public sealed class LicenseReport
{
    public string? ProjectLicense { get; init; }
    public int TotalPackages { get; init; }
    public required List<CompatibilityResult> CompatibilityResults { get; init; }
    public required Dictionary<string, int> LicenseDistribution { get; init; }
    public required Dictionary<LicenseCategory, int> CategoryDistribution { get; init; }
    public required List<string> UnknownLicenses { get; init; }
    public required string OverallStatus { get; init; }
    public int ErrorCount { get; init; }
    public int WarningCount { get; init; }
}
