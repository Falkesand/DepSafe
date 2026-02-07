namespace DepSafe.Models;

/// <summary>
/// Dependency information from package-lock.json.
/// </summary>
public sealed class NpmLockDependency
{
    public required string Name { get; init; }
    public required string Version { get; init; }
    public required string ResolvedUrl { get; init; }
    public bool IsDev { get; init; }
    public bool IsOptional { get; init; }
    public string? Integrity { get; init; }
    public Dictionary<string, string> Dependencies { get; init; } = [];
}
