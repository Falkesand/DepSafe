namespace DepSafe.Models;

public sealed class DotnetFrameworkPackages
{
    public required string Framework { get; set; }
    public List<DotnetPackageInfo> TopLevelPackages { get; set; } = [];
    public List<DotnetPackageInfo> TransitivePackages { get; set; } = [];
}
