namespace DepSafe.Models;

/// <summary>
/// Health assessment for a single NuGet package.
/// </summary>
public sealed class PackageHealth
{
    private static readonly IReadOnlyDictionary<string, string> s_emptyPeerDeps =
        new Dictionary<string, string>();

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
    public IReadOnlyList<string> Vulnerabilities { get; init; } = [];

    /// <summary>Latest available version of the package.</summary>
    public string? LatestVersion { get; init; }

    /// <summary>Peer dependencies (npm only) - packages that must be installed alongside.</summary>
    public IReadOnlyDictionary<string, string> PeerDependencies { get; init; } = s_emptyPeerDeps;

    /// <summary>True if this package has a vulnerability in the CISA KEV catalog (actively exploited).</summary>
    public bool HasKevVulnerability { get; set; }

    /// <summary>CVE IDs from CISA KEV catalog affecting this package.</summary>
    public List<string> KevCves { get; set; } = [];

    /// <summary>Highest EPSS probability across all vulnerabilities (0.0-1.0).</summary>
    public double? MaxEpssProbability { get; set; }

    /// <summary>Highest EPSS percentile across all vulnerabilities (0.0-1.0).</summary>
    public double? MaxEpssPercentile { get; set; }

    /// <summary>Days since the oldest unpatched vulnerability was published.</summary>
    public int? OldestUnpatchedVulnDays { get; set; }

    /// <summary>Number of vulnerabilities where a patch is available but not applied.</summary>
    public int PatchAvailableNotAppliedCount { get; set; }

    /// <summary>Package content integrity hash for SBOM checksum field (e.g., sha512-...).</summary>
    public string? ContentIntegrity { get; set; }

    /// <summary>Package authors/publishers for SBOM supplier field.</summary>
    public IReadOnlyList<string> Authors { get; init; } = [];

    public List<string> Recommendations { get; init; } = [];
    public IReadOnlyList<PackageDependency> Dependencies { get; init; } = [];

    /// <summary>Type of dependency relationship.</summary>
    public DependencyType DependencyType { get; init; } = DependencyType.Direct;

    /// <summary>Package ecosystem (NuGet or npm).</summary>
    public PackageEcosystem Ecosystem { get; init; } = PackageEcosystem.NuGet;
}
