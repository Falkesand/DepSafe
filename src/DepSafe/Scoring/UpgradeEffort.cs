namespace DepSafe.Scoring;

/// <summary>
/// Effort level for upgrading a package.
/// </summary>
public enum UpgradeEffort
{
    /// <summary>Patch version bump (e.g., 1.0.0 -> 1.0.1). Low risk.</summary>
    Patch,
    /// <summary>Minor version bump (e.g., 1.0.0 -> 1.1.0). May have new features.</summary>
    Minor,
    /// <summary>Major version bump (e.g., 1.0.0 -> 2.0.0). May have breaking changes.</summary>
    Major
}
