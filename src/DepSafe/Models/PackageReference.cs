namespace DepSafe.Models;

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
