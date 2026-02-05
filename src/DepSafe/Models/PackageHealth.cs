namespace DepSafe.Models;

/// <summary>
/// Health assessment for a single NuGet package.
/// </summary>
public sealed class PackageHealth
{
    public required string PackageId { get; init; }
    public required string Version { get; init; }

    /// <summary>General health score (0-100) based on freshness, popularity, activity.</summary>
    public required int Score { get; init; }

    /// <summary>General health status derived from Score.</summary>
    public required HealthStatus Status { get; init; }

    /// <summary>CRA compliance score (0-100) based on vulnerabilities, license, identifiability.</summary>
    public int CraScore { get; set; }

    /// <summary>CRA compliance status derived from CraScore.</summary>
    public CraComplianceStatus CraStatus { get; set; }

    public required PackageMetrics Metrics { get; init; }
    public string? RepositoryUrl { get; init; }
    public string? License { get; init; }
    public List<string> Vulnerabilities { get; init; } = [];

    /// <summary>Latest available version of the package.</summary>
    public string? LatestVersion { get; init; }

    /// <summary>Peer dependencies (npm only) - packages that must be installed alongside.</summary>
    public Dictionary<string, string> PeerDependencies { get; init; } = [];

    /// <summary>True if this package has a vulnerability in the CISA KEV catalog (actively exploited).</summary>
    public bool HasKevVulnerability { get; set; }

    /// <summary>CVE IDs from CISA KEV catalog affecting this package.</summary>
    public List<string> KevCves { get; set; } = [];

    public List<string> Recommendations { get; init; } = [];
    public List<PackageDependency> Dependencies { get; init; } = [];

    /// <summary>Type of dependency relationship.</summary>
    public DependencyType DependencyType { get; init; } = DependencyType.Direct;

    /// <summary>Package ecosystem (NuGet or npm).</summary>
    public PackageEcosystem Ecosystem { get; init; } = PackageEcosystem.NuGet;
}

/// <summary>
/// CRA compliance status for a package.
/// </summary>
public enum CraComplianceStatus
{
    /// <summary>Fully compliant - no vulnerabilities, license identified.</summary>
    Compliant,
    /// <summary>Minor issues - license unclear or minor vulnerability.</summary>
    Review,
    /// <summary>Action required - vulnerabilities present.</summary>
    ActionRequired,
    /// <summary>Non-compliant - critical vulnerabilities or missing required info.</summary>
    NonCompliant
}

/// <summary>
/// Type of package dependency relationship.
/// </summary>
public enum DependencyType
{
    /// <summary>Directly referenced in project file.</summary>
    Direct,
    /// <summary>Transitive dependency (dependency of a direct package, resolved by NuGet).</summary>
    Transitive,
    /// <summary>Sub-dependency (dependency of another package in the report).</summary>
    SubDependency
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

/// <summary>
/// Package reference from a project file.
/// </summary>
public sealed class PackageReference
{
    public required string PackageId { get; init; }
    public required string Version { get; init; }
    public string? SourceFile { get; init; }
    public bool IsTransitive { get; init; }
    public string? ResolvedVersion { get; init; }
    public string? RequestedVersion { get; init; }
}

/// <summary>
/// Parsed output from dotnet list package --format json
/// </summary>
public sealed class DotnetPackageListOutput
{
    public int Version { get; set; }
    public string? Parameters { get; set; }
    public List<DotnetProjectPackages> Projects { get; set; } = [];
}

public sealed class DotnetProjectPackages
{
    public required string Path { get; set; }
    public List<DotnetFrameworkPackages> Frameworks { get; set; } = [];
}

public sealed class DotnetFrameworkPackages
{
    public required string Framework { get; set; }
    public List<DotnetPackageInfo> TopLevelPackages { get; set; } = [];
    public List<DotnetPackageInfo> TransitivePackages { get; set; } = [];
}

public sealed class DotnetPackageInfo
{
    public required string Id { get; set; }
    public string? RequestedVersion { get; set; }
    public required string ResolvedVersion { get; set; }
}
