namespace DepSafe.Models;

/// <summary>
/// Trigger reason for a CRA Art. 14 reporting obligation.
/// </summary>
public enum ReportingTrigger
{
    /// <summary>Vulnerability is in CISA KEV catalog (actively exploited).</summary>
    KevExploitation,

    /// <summary>EPSS probability >= 0.5 (high likelihood of exploitation).</summary>
    HighEpss,

    /// <summary>Both KEV and high EPSS.</summary>
    Both
}
