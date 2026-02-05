namespace DepSafe.Models;

/// <summary>
/// Information retrieved from npm registry API about a package.
/// </summary>
public sealed class NpmPackageInfo
{
    public required string Name { get; init; }
    public required string LatestVersion { get; init; }
    public required List<NpmVersionInfo> Versions { get; init; }
    public required long WeeklyDownloads { get; init; }
    public string? RepositoryUrl { get; init; }
    public string? License { get; init; }
    public string? Description { get; init; }
    public string? Homepage { get; init; }
    public List<string> Keywords { get; init; } = [];
    public bool IsDeprecated { get; init; }
    public string? DeprecationMessage { get; init; }
    public string? Author { get; init; }
    public Dictionary<string, string> Dependencies { get; init; } = [];
    public Dictionary<string, string> DevDependencies { get; init; } = [];
    public Dictionary<string, string> PeerDependencies { get; init; } = [];
}

/// <summary>
/// Version-specific information for an npm package.
/// </summary>
public sealed class NpmVersionInfo
{
    public required string Version { get; init; }
    public required DateTime PublishedDate { get; init; }
    public bool IsDeprecated { get; init; }
}

/// <summary>
/// Dependency information from package-lock.json.
/// </summary>
public sealed class NpmLockDependency
{
    public required string Name { get; init; }
    public required string Version { get; init; }
    public required string ResolvedUrl { get; init; }
    public bool IsDev { get; init; }
    public bool IsOptional { get; init; }
    public string? Integrity { get; init; }
    public Dictionary<string, string> Dependencies { get; init; } = [];
}

/// <summary>
/// Parsed package.json content.
/// </summary>
public sealed class PackageJson
{
    public string? Name { get; init; }
    public string? Version { get; init; }
    public Dictionary<string, string> Dependencies { get; init; } = [];
    public Dictionary<string, string> DevDependencies { get; init; } = [];
    public Dictionary<string, string> PeerDependencies { get; init; } = [];
    public string? License { get; init; }
    public string? Repository { get; init; }
}
