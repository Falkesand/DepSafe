namespace DepSafe.Models;

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
