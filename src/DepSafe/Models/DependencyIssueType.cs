namespace DepSafe.Models;

/// <summary>
/// Type of dependency issue detected.
/// </summary>
public enum DependencyIssueType
{
    /// <summary>Same package appears with multiple different versions.</summary>
    VersionConflict,
    /// <summary>Peer dependency version requirement not satisfied.</summary>
    PeerDependencyMismatch
}
