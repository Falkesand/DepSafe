namespace DepSafe.Models;

/// <summary>
/// CRA compliance status for a package.
/// </summary>
public enum CraComplianceStatus
{
    /// <summary>Fully compliant - no vulnerabilities, license identified.</summary>
    Compliant,
    /// <summary>Minor issues - license unclear or minor vulnerability.</summary>
    Review,
    /// <summary>Action required - vulnerabilities present.</summary>
    ActionRequired,
    /// <summary>Non-compliant - critical vulnerabilities or missing required info.</summary>
    NonCompliant
}
