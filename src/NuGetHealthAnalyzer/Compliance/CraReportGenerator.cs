using System.Text;
using System.Text.Json;
using NuGetHealthAnalyzer.Models;

namespace NuGetHealthAnalyzer.Compliance;

/// <summary>
/// Generates comprehensive CRA compliance reports combining SBOM, VEX, and health data.
/// </summary>
public sealed class CraReportGenerator
{
    private readonly SbomGenerator _sbomGenerator;
    private readonly VexGenerator _vexGenerator;

    public CraReportGenerator(SbomGenerator? sbomGenerator = null, VexGenerator? vexGenerator = null)
    {
        _sbomGenerator = sbomGenerator ?? new SbomGenerator();
        _vexGenerator = vexGenerator ?? new VexGenerator();
    }

    /// <summary>
    /// Generate complete CRA compliance report.
    /// </summary>
    public CraReport Generate(
        ProjectReport healthReport,
        IReadOnlyDictionary<string, List<VulnerabilityInfo>> vulnerabilities)
    {
        var sbom = _sbomGenerator.Generate(healthReport.ProjectPath, healthReport.Packages);
        var vex = _vexGenerator.Generate(healthReport.Packages, vulnerabilities);

        var complianceItems = new List<CraComplianceItem>();

        // CRA Article 10 - SBOM
        complianceItems.Add(new CraComplianceItem
        {
            Requirement = "CRA Article 10 - Software Bill of Materials",
            Description = "Machine-readable inventory of software components",
            Status = sbom.Packages.Count > 0 ? CraComplianceStatus.Compliant : CraComplianceStatus.NonCompliant,
            Evidence = $"SBOM generated with {sbom.Packages.Count} components in SPDX 3.0 format",
            Recommendation = null
        });

        // Vulnerability documentation
        var vulnCount = vulnerabilities.Values.Sum(v => v.Count);
        complianceItems.Add(new CraComplianceItem
        {
            Requirement = "CRA Article 11 - Vulnerability Handling",
            Description = "Documentation of known vulnerabilities and their status",
            Status = vulnCount == 0 ? CraComplianceStatus.Compliant :
                vex.Statements.Any(s => s.Status == VexStatus.Affected) ?
                    CraComplianceStatus.ActionRequired : CraComplianceStatus.Compliant,
            Evidence = $"VEX document generated with {vex.Statements.Count} statements. {vulnCount} vulnerabilities documented.",
            Recommendation = vulnCount > 0
                ? "Review affected vulnerabilities and apply available patches"
                : null
        });

        // Update mechanism (health scoring)
        var outdatedPackages = healthReport.Packages.Count(p =>
            p.Metrics.DaysSinceLastRelease > 730);
        complianceItems.Add(new CraComplianceItem
        {
            Requirement = "CRA Article 10(6) - Security Updates",
            Description = "Mechanism to ensure timely security updates",
            Status = outdatedPackages == 0 ? CraComplianceStatus.Compliant :
                outdatedPackages > healthReport.Packages.Count / 2 ?
                    CraComplianceStatus.NonCompliant : CraComplianceStatus.ActionRequired,
            Evidence = $"{outdatedPackages} of {healthReport.Packages.Count} packages have not been updated in 2+ years",
            Recommendation = outdatedPackages > 0
                ? "Review and update stale dependencies or find maintained alternatives"
                : null
        });

        // License compliance
        var noLicensePackages = healthReport.Packages.Count(p =>
            string.IsNullOrEmpty(p.License) || p.License == "NOASSERTION");
        complianceItems.Add(new CraComplianceItem
        {
            Requirement = "CRA Article 10(9) - License Information",
            Description = "License information for all components",
            Status = noLicensePackages == 0 ? CraComplianceStatus.Compliant :
                noLicensePackages > healthReport.Packages.Count / 4 ?
                    CraComplianceStatus.ActionRequired : CraComplianceStatus.Compliant,
            Evidence = $"{healthReport.Packages.Count - noLicensePackages} of {healthReport.Packages.Count} packages have license information",
            Recommendation = noLicensePackages > 0
                ? "Investigate and document licenses for packages without license information"
                : null
        });

        return new CraReport
        {
            GeneratedAt = DateTime.UtcNow,
            ProjectPath = healthReport.ProjectPath,
            HealthScore = healthReport.OverallScore,
            HealthStatus = healthReport.OverallStatus,
            ComplianceItems = complianceItems,
            OverallComplianceStatus = DetermineOverallStatus(complianceItems),
            Sbom = sbom,
            Vex = vex,
            PackageCount = healthReport.Packages.Count,
            VulnerabilityCount = vulnCount,
            CriticalPackageCount = healthReport.Summary.CriticalCount
        };
    }

    private static CraComplianceStatus DetermineOverallStatus(List<CraComplianceItem> items)
    {
        if (items.Any(i => i.Status == CraComplianceStatus.NonCompliant))
            return CraComplianceStatus.NonCompliant;
        if (items.Any(i => i.Status == CraComplianceStatus.ActionRequired))
            return CraComplianceStatus.ActionRequired;
        return CraComplianceStatus.Compliant;
    }

    /// <summary>
    /// Generate HTML report.
    /// </summary>
    public string GenerateHtml(CraReport report)
    {
        var sb = new StringBuilder();

        sb.AppendLine("<!DOCTYPE html>");
        sb.AppendLine("<html lang=\"en\">");
        sb.AppendLine("<head>");
        sb.AppendLine("  <meta charset=\"UTF-8\">");
        sb.AppendLine("  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">");
        sb.AppendLine("  <title>CRA Compliance Report</title>");
        sb.AppendLine("  <style>");
        sb.AppendLine("    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 40px; background: #f5f5f5; }");
        sb.AppendLine("    .container { max-width: 1200px; margin: 0 auto; background: white; padding: 40px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }");
        sb.AppendLine("    h1 { color: #333; border-bottom: 2px solid #007acc; padding-bottom: 10px; }");
        sb.AppendLine("    h2 { color: #555; margin-top: 30px; }");
        sb.AppendLine("    .status { display: inline-block; padding: 4px 12px; border-radius: 4px; font-weight: bold; }");
        sb.AppendLine("    .status.compliant { background: #d4edda; color: #155724; }");
        sb.AppendLine("    .status.action-required { background: #fff3cd; color: #856404; }");
        sb.AppendLine("    .status.non-compliant { background: #f8d7da; color: #721c24; }");
        sb.AppendLine("    .metric { display: inline-block; margin-right: 30px; margin-bottom: 20px; }");
        sb.AppendLine("    .metric-value { font-size: 36px; font-weight: bold; color: #007acc; }");
        sb.AppendLine("    .metric-label { font-size: 14px; color: #666; }");
        sb.AppendLine("    table { width: 100%; border-collapse: collapse; margin-top: 20px; }");
        sb.AppendLine("    th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }");
        sb.AppendLine("    th { background: #f8f9fa; font-weight: 600; }");
        sb.AppendLine("    .recommendation { background: #fff3cd; padding: 10px; border-radius: 4px; margin-top: 10px; }");
        sb.AppendLine("    .footer { margin-top: 40px; padding-top: 20px; border-top: 1px solid #ddd; color: #666; font-size: 14px; }");
        sb.AppendLine("  </style>");
        sb.AppendLine("</head>");
        sb.AppendLine("<body>");
        sb.AppendLine("  <div class=\"container\">");

        // Header
        sb.AppendLine("    <h1>EU Cyber Resilience Act Compliance Report</h1>");
        sb.AppendLine($"    <p><strong>Project:</strong> {EscapeHtml(report.ProjectPath)}</p>");
        sb.AppendLine($"    <p><strong>Generated:</strong> {report.GeneratedAt:yyyy-MM-dd HH:mm:ss} UTC</p>");

        // Overall status
        var statusClass = report.OverallComplianceStatus switch
        {
            CraComplianceStatus.Compliant => "compliant",
            CraComplianceStatus.ActionRequired => "action-required",
            _ => "non-compliant"
        };
        sb.AppendLine($"    <p><strong>Overall Status:</strong> <span class=\"status {statusClass}\">{report.OverallComplianceStatus}</span></p>");

        // Key metrics
        sb.AppendLine("    <h2>Key Metrics</h2>");
        sb.AppendLine("    <div>");
        sb.AppendLine($"      <div class=\"metric\"><div class=\"metric-value\">{report.HealthScore}</div><div class=\"metric-label\">Health Score</div></div>");
        sb.AppendLine($"      <div class=\"metric\"><div class=\"metric-value\">{report.PackageCount}</div><div class=\"metric-label\">Packages</div></div>");
        sb.AppendLine($"      <div class=\"metric\"><div class=\"metric-value\">{report.VulnerabilityCount}</div><div class=\"metric-label\">Vulnerabilities</div></div>");
        sb.AppendLine($"      <div class=\"metric\"><div class=\"metric-value\">{report.CriticalPackageCount}</div><div class=\"metric-label\">Critical Packages</div></div>");
        sb.AppendLine("    </div>");

        // Compliance checklist
        sb.AppendLine("    <h2>Compliance Checklist</h2>");
        sb.AppendLine("    <table>");
        sb.AppendLine("      <tr><th>Requirement</th><th>Status</th><th>Evidence</th></tr>");

        foreach (var item in report.ComplianceItems)
        {
            var itemStatusClass = item.Status switch
            {
                CraComplianceStatus.Compliant => "compliant",
                CraComplianceStatus.ActionRequired => "action-required",
                _ => "non-compliant"
            };
            sb.AppendLine($"      <tr>");
            sb.AppendLine($"        <td><strong>{EscapeHtml(item.Requirement)}</strong><br><small>{EscapeHtml(item.Description)}</small></td>");
            sb.AppendLine($"        <td><span class=\"status {itemStatusClass}\">{item.Status}</span></td>");
            sb.AppendLine($"        <td>{EscapeHtml(item.Evidence ?? "")}");
            if (!string.IsNullOrEmpty(item.Recommendation))
            {
                sb.AppendLine($"<div class=\"recommendation\"><strong>Recommendation:</strong> {EscapeHtml(item.Recommendation)}</div>");
            }
            sb.AppendLine($"        </td>");
            sb.AppendLine($"      </tr>");
        }

        sb.AppendLine("    </table>");

        // Footer
        sb.AppendLine("    <div class=\"footer\">");
        sb.AppendLine("      <p>Generated by NuGetHealthAnalyzer</p>");
        sb.AppendLine("      <p><small>This report assists with EU Cyber Resilience Act compliance. Consult legal counsel for authoritative compliance guidance.</small></p>");
        sb.AppendLine("    </div>");

        sb.AppendLine("  </div>");
        sb.AppendLine("</body>");
        sb.AppendLine("</html>");

        return sb.ToString();
    }

    /// <summary>
    /// Generate JSON report.
    /// </summary>
    public string GenerateJson(CraReport report)
    {
        return JsonSerializer.Serialize(report, new JsonSerializerOptions
        {
            WriteIndented = true,
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase
        });
    }

    private static string EscapeHtml(string input)
    {
        return input
            .Replace("&", "&amp;")
            .Replace("<", "&lt;")
            .Replace(">", "&gt;")
            .Replace("\"", "&quot;")
            .Replace("'", "&#39;");
    }
}

public sealed class CraReport
{
    public required DateTime GeneratedAt { get; init; }
    public required string ProjectPath { get; init; }
    public required int HealthScore { get; init; }
    public required HealthStatus HealthStatus { get; init; }
    public required List<CraComplianceItem> ComplianceItems { get; init; }
    public required CraComplianceStatus OverallComplianceStatus { get; init; }
    public required SbomDocument Sbom { get; init; }
    public required VexDocument Vex { get; init; }
    public required int PackageCount { get; init; }
    public required int VulnerabilityCount { get; init; }
    public required int CriticalPackageCount { get; init; }
}

public sealed class CraComplianceItem
{
    public required string Requirement { get; init; }
    public required string Description { get; init; }
    public required CraComplianceStatus Status { get; init; }
    public string? Evidence { get; init; }
    public string? Recommendation { get; init; }
}

public enum CraComplianceStatus
{
    Compliant,
    ActionRequired,
    NonCompliant
}
