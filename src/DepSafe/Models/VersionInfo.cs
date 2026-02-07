namespace DepSafe.Models;

public sealed class VersionInfo
{
    public required string Version { get; init; }
    public required DateTime PublishedDate { get; init; }
    public required long Downloads { get; init; }
    public bool IsPrerelease { get; init; }
    public bool IsListed { get; init; } = true;
}
