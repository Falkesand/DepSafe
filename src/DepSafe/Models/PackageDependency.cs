namespace DepSafe.Models;

/// <summary>
/// A package dependency.
/// </summary>
public sealed class PackageDependency
{
    public required string PackageId { get; init; }
    public string? VersionRange { get; init; }
    public string? TargetFramework { get; init; }
}
