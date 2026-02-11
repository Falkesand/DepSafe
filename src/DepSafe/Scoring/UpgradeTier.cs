namespace DepSafe.Scoring;

/// <summary>
/// One possible upgrade path for a vulnerable package within a specific semver tier.
/// </summary>
public sealed record UpgradeTier(
    string TargetVersion,
    UpgradeEffort Effort,
    int CvesFixed,
    int TotalCves,
    bool IsRecommended);
