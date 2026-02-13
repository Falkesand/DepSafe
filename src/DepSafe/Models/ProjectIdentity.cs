namespace DepSafe.Models;

/// <summary>
/// Identifies a project by name and version, extracted from project metadata.
/// </summary>
public sealed record ProjectIdentity(string Name, string Version);
