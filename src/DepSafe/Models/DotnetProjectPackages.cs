namespace DepSafe.Models;

public sealed class DotnetProjectPackages
{
    public required string Path { get; set; }
    public List<DotnetFrameworkPackages> Frameworks { get; set; } = [];
}
