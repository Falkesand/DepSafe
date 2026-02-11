using DepSafe.Models;

namespace DepSafe.Compliance;

public sealed class CraReport
{
    public required DateTime GeneratedAt { get; init; }
    public TimeSpan? GenerationDuration { get; init; }
    public required string ProjectPath { get; init; }
    public required int HealthScore { get; init; }
    public required HealthStatus HealthStatus { get; init; }
    public required List<CraComplianceItem> ComplianceItems { get; init; }
    public required CraComplianceStatus OverallComplianceStatus { get; init; }
    public required SbomDocument Sbom { get; init; }
    public required VexDocument Vex { get; init; }
    public required int PackageCount { get; init; }
    public required int TransitivePackageCount { get; init; }
    public required int VulnerabilityCount { get; init; }
    public required int CriticalPackageCount { get; init; }
    public int VersionConflictCount { get; init; }
    public List<DependencyIssue> DependencyIssues { get; init; } = [];
    public int CraReadinessScore { get; init; }

    // Structured CI/CD policy fields (v1.5)
    /// <summary>Days since the oldest unpatched vulnerability was published.</summary>
    public int? MaxUnpatchedVulnerabilityDays { get; init; }
    /// <summary>SBOM completeness percentage (0-100).</summary>
    public int? SbomCompletenessPercentage { get; init; }
    /// <summary>Maximum dependency tree depth.</summary>
    public int? MaxDependencyDepth { get; init; }
    /// <summary>Whether any dependency is unmaintained (no activity 2+ years).</summary>
    public bool HasUnmaintainedPackages { get; init; }
    /// <summary>Count of vulnerabilities triggering CRA Art. 14 reporting obligations.</summary>
    public int ReportableVulnerabilityCount { get; init; }

    // Structured policy fields (v1.6)
    /// <summary>Package IDs that are deprecated.</summary>
    public List<string> DeprecatedPackages { get; init; } = [];
    /// <summary>Lowest health score among all packages.</summary>
    public int? MinPackageHealthScore { get; init; }
    /// <summary>Package ID with the lowest health score.</summary>
    public string? MinHealthScorePackage { get; init; }

}
