namespace DepSafe.Scoring;

/// <summary>
/// ROI tier for a remediation item.
/// </summary>
public enum RemediationTier
{
    /// <summary>High return on investment — fixes that reduce the most risk per effort.</summary>
    HighROI,
    /// <summary>Low return on investment — diminishing returns.</summary>
    LowROI
}
