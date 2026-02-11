using DepSafe.Models;

namespace DepSafe.Compliance;

/// <summary>
/// Evaluates release readiness by classifying compliance items and policy violations
/// into Blocking (prevents release) and Advisory (requires attention) categories.
/// </summary>
public static class ReleaseReadinessEvaluator
{
    /// <summary>
    /// Evaluate release readiness based on CRA compliance report and policy violations.
    /// Blocking = NonCompliant compliance items + policy violations.
    /// Advisory = ActionRequired + Review compliance items.
    /// </summary>
    public static ReleaseReadinessResult Evaluate(CraReport report, List<string> policyViolations, AuditSimulationResult? auditResult = null)
    {
        var blockers = new List<ReleaseBlocker>();
        var advisories = new List<string>();

        foreach (var item in report.ComplianceItems)
        {
            switch (item.Status)
            {
                case CraComplianceStatus.NonCompliant:
                    blockers.Add(new ReleaseBlocker
                    {
                        Requirement = item.Requirement,
                        Reason = item.Description,
                    });
                    break;
                case CraComplianceStatus.ActionRequired:
                case CraComplianceStatus.Review:
                    advisories.Add($"{item.Requirement}: {item.Description}");
                    break;
            }
        }

        foreach (var violation in policyViolations)
        {
            blockers.Add(new ReleaseBlocker
            {
                Requirement = "Policy Violation",
                Reason = violation,
            });
        }

        if (auditResult is not null)
        {
            foreach (var finding in auditResult.Findings.Where(f => f.Severity is AuditSeverity.Critical or AuditSeverity.High))
            {
                blockers.Add(new ReleaseBlocker
                {
                    Requirement = $"Audit: {finding.ArticleReference}",
                    Reason = finding.Finding,
                });
            }

            foreach (var finding in auditResult.Findings.Where(f => f.Severity is AuditSeverity.Medium or AuditSeverity.Low))
            {
                advisories.Add($"Audit: {finding.ArticleReference} \u2014 {finding.Finding}");
            }
        }

        return new ReleaseReadinessResult
        {
            BlockingItems = blockers,
            AdvisoryItems = advisories,
        };
    }
}
