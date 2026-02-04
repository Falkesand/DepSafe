namespace DepSafe.Models;

/// <summary>
/// Configuration for CRA compliance scanning.
/// Loaded from .cra-config.json in project root.
/// </summary>
public sealed class CraConfig
{
    /// <summary>
    /// Override license detection for specific packages.
    /// Key: Package name (case-insensitive)
    /// Value: SPDX license identifier (e.g., "Apache-2.0", "MIT")
    /// </summary>
    /// <example>
    /// {
    ///   "licenseOverrides": {
    ///     "SixLabors.ImageSharp": "Apache-2.0",
    ///     "SomePackage": "MIT"
    ///   }
    /// }
    /// </example>
    public Dictionary<string, string> LicenseOverrides { get; set; } = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Packages to exclude from CRA analysis.
    /// Useful for internal/private packages.
    /// </summary>
    public List<string> ExcludePackages { get; set; } = [];

    /// <summary>
    /// Additional notes or justifications for compliance decisions.
    /// Key: Package name
    /// Value: Note explaining the decision
    /// </summary>
    public Dictionary<string, string> ComplianceNotes { get; set; } = new(StringComparer.OrdinalIgnoreCase);
}
