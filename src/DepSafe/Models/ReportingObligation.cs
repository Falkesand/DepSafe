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

/// <summary>
/// A vulnerability that triggers CRA Art. 14 incident reporting obligations.
/// Art. 14 requires manufacturers to notify CSIRT within 24 hours of becoming aware
/// of an actively exploited vulnerability, with full details within 72 hours.
/// </summary>
public sealed class ReportingObligation
{
    /// <summary>Package containing the reportable vulnerability.</summary>
    public required string PackageId { get; init; }

    /// <summary>Installed version of the affected package.</summary>
    public required string Version { get; init; }

    /// <summary>CVE identifiers triggering the obligation.</summary>
    public required List<string> CveIds { get; init; }

    /// <summary>Highest severity among the triggering CVEs (Critical/High/Medium/Low).</summary>
    public required string Severity { get; init; }

    /// <summary>What triggered the reporting obligation.</summary>
    public required ReportingTrigger Trigger { get; init; }

    /// <summary>Date the vulnerability was first discovered/published.</summary>
    public required DateTime DiscoveryDate { get; init; }

    /// <summary>EPSS probability of the highest-scoring CVE (0.0-1.0).</summary>
    public double? EpssProbability { get; init; }

    /// <summary>Whether any CVE is in the CISA KEV catalog.</summary>
    public bool IsKevVulnerability { get; init; }

    /// <summary>CRA Art. 14(2)(a) — Early warning within 24 hours of discovery.</summary>
    public DateTime EarlyWarningDeadline => DiscoveryDate.AddHours(24);

    /// <summary>CRA Art. 14(2)(b) — Full notification within 72 hours of discovery.</summary>
    public DateTime FullNotificationDeadline => DiscoveryDate.AddHours(72);

    /// <summary>CRA Art. 14(2)(c) — Final report within 14 days of discovery.</summary>
    public DateTime FinalReportDeadline => DiscoveryDate.AddDays(14);
}
