namespace NuGetHealthAnalyzer.Models;

/// <summary>
/// Information retrieved from NuGet API about a package.
/// </summary>
public sealed class NuGetPackageInfo
{
    public required string PackageId { get; init; }
    public required string LatestVersion { get; init; }
    public required List<VersionInfo> Versions { get; init; }
    public required long TotalDownloads { get; init; }
    public string? ProjectUrl { get; init; }
    public string? RepositoryUrl { get; init; }
    public string? License { get; init; }
    public string? LicenseUrl { get; init; }
    public string? Description { get; init; }
    public List<string> Authors { get; init; } = [];
    public List<string> Tags { get; init; } = [];
    public bool IsDeprecated { get; init; }
    public string? DeprecationReason { get; init; }
}

public sealed class VersionInfo
{
    public required string Version { get; init; }
    public required DateTime PublishedDate { get; init; }
    public required long Downloads { get; init; }
    public bool IsPrerelease { get; init; }
    public bool IsListed { get; init; } = true;
}
