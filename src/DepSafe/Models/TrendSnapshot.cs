namespace DepSafe.Models;

public sealed record TrendSnapshot(
    DateTime CapturedAt,
    string ProjectPath,
    int HealthScore,
    int CraReadinessScore,
    int VulnerabilityCount,
    int CriticalPackageCount,
    int ReportableVulnerabilityCount,
    int? MaxUnpatchedVulnerabilityDays,
    int? SbomCompletenessPercentage,
    int? MaxDependencyDepth,
    bool HasUnmaintainedPackages,
    int PackageCount,
    int TransitivePackageCount);
