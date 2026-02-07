namespace DepSafe.Models;

public sealed class DotnetPackageInfo
{
    public required string Id { get; set; }
    public string? RequestedVersion { get; set; }
    public required string ResolvedVersion { get; set; }
}
