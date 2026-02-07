namespace DepSafe.Models;

/// <summary>
/// Version-specific information for an npm package.
/// </summary>
public sealed class NpmVersionInfo
{
    public required string Version { get; init; }
    public required DateTime PublishedDate { get; init; }
    public bool IsDeprecated { get; init; }
}
