namespace DepSafe.Models;

/// <summary>
/// Parsed output from dotnet list package --format json
/// </summary>
public sealed class DotnetPackageListOutput
{
    public int Version { get; set; }
    public string? Parameters { get; set; }
    public List<DotnetProjectPackages> Projects { get; set; } = [];
}
