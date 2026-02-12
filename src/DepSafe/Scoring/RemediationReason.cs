namespace DepSafe.Scoring;

/// <summary>
/// Categorizes why a package appears in the remediation roadmap.
/// </summary>
public enum RemediationReason
{
    /// <summary>Package has known CVEs affecting the installed version.</summary>
    Vulnerability,
    /// <summary>Package is marked deprecated by the registry.</summary>
    Deprecated,
    /// <summary>Package has no activity for 2+ years or is archived.</summary>
    Unmaintained,
    /// <summary>Package has too few maintainers (bus factor risk).</summary>
    LowBusFactor,
}
