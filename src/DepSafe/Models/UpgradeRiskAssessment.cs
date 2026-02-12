namespace DepSafe.Models;

public sealed record UpgradeRiskAssessment(
    int RiskScore,
    UpgradeRiskLevel RiskLevel,
    int BreakingChangeSignals,
    int DeprecationSignals,
    List<string> RiskFactors,
    int ReleasesBetween,
    TimeSpan TimeBetween);
