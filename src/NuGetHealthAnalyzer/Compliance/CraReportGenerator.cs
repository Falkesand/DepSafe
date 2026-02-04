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
            p.Metrics.DaysSinceLastRelease.HasValue && p.Metrics.DaysSinceLastRelease > 730);
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
    /// Generate interactive HTML report with drill-down capabilities.
    /// </summary>
    public string GenerateHtml(CraReport report)
    {
        var sb = new StringBuilder();
        var packages = report.Sbom.Packages.Skip(1).ToList(); // Skip root package

        sb.AppendLine("<!DOCTYPE html>");
        sb.AppendLine("<html lang=\"en\">");
        sb.AppendLine("<head>");
        sb.AppendLine("  <meta charset=\"UTF-8\">");
        sb.AppendLine("  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">");
        sb.AppendLine($"  <title>CRA Compliance Report - {EscapeHtml(Path.GetFileName(report.ProjectPath))}</title>");
        sb.Append(GetHtmlStyles());
        sb.AppendLine("</head>");
        sb.AppendLine("<body>");

        // Sidebar Navigation
        sb.AppendLine("<nav class=\"sidebar\">");
        sb.AppendLine("  <div class=\"sidebar-header\">");
        sb.AppendLine("    <h2>NuGet Health</h2>");
        sb.AppendLine("  </div>");
        sb.AppendLine("  <ul class=\"nav-links\">");
        sb.AppendLine("    <li><a href=\"#\" onclick=\"showSection('overview')\" class=\"active\" data-section=\"overview\">Overview</a></li>");
        sb.AppendLine("    <li><a href=\"#\" onclick=\"showSection('packages')\" data-section=\"packages\">Packages</a></li>");
        sb.AppendLine("    <li><a href=\"#\" onclick=\"showSection('licenses')\" data-section=\"licenses\">Licenses</a></li>");
        sb.AppendLine("    <li><a href=\"#\" onclick=\"showSection('sbom')\" data-section=\"sbom\">SBOM</a></li>");
        sb.AppendLine("    <li><a href=\"#\" onclick=\"showSection('vulnerabilities')\" data-section=\"vulnerabilities\">Vulnerabilities</a></li>");
        sb.AppendLine("    <li><a href=\"#\" onclick=\"showSection('compliance')\" data-section=\"compliance\">Compliance</a></li>");
        sb.AppendLine("  </ul>");
        sb.AppendLine("</nav>");

        // Main Content
        sb.AppendLine("<main class=\"main-content\">");

        // Header
        sb.AppendLine("<header class=\"header\">");
        sb.AppendLine($"  <h1>{EscapeHtml(Path.GetFileName(report.ProjectPath))}</h1>");
        sb.AppendLine($"  <p class=\"subtitle\">Generated {report.GeneratedAt:MMMM dd, yyyy 'at' HH:mm} UTC</p>");
        sb.AppendLine("</header>");

        // Overview Section
        sb.AppendLine("<section id=\"overview\" class=\"section active\">");
        GenerateOverviewSection(sb, report);
        sb.AppendLine("</section>");

        // Packages Section
        sb.AppendLine("<section id=\"packages\" class=\"section\">");
        GeneratePackagesSection(sb, report);
        sb.AppendLine("</section>");

        // Licenses Section
        sb.AppendLine("<section id=\"licenses\" class=\"section\">");
        GenerateLicensesSection(sb, report);
        sb.AppendLine("</section>");

        // SBOM Section
        sb.AppendLine("<section id=\"sbom\" class=\"section\">");
        GenerateSbomSection(sb, report, packages);
        sb.AppendLine("</section>");

        // Vulnerabilities Section
        sb.AppendLine("<section id=\"vulnerabilities\" class=\"section\">");
        GenerateVulnerabilitiesSection(sb, report);
        sb.AppendLine("</section>");

        // Compliance Section
        sb.AppendLine("<section id=\"compliance\" class=\"section\">");
        GenerateComplianceSection(sb, report);
        sb.AppendLine("</section>");

        sb.AppendLine("</main>");

        // JavaScript
        sb.Append(GetHtmlScripts(report));

        sb.AppendLine("</body>");
        sb.AppendLine("</html>");

        return sb.ToString();
    }

    private void GenerateOverviewSection(StringBuilder sb, CraReport report)
    {
        // SBOM completeness warning
        if (_hasIncompleteTransitive || _hasUnresolvedVersions)
        {
            sb.AppendLine("<div class=\"sbom-warning\">");
            sb.AppendLine("  <h4>⚠️ SBOM Completeness Warning</h4>");
            sb.AppendLine("  <p>This report may be incomplete for full CRA compliance:</p>");
            sb.AppendLine("  <ul>");
            if (_hasIncompleteTransitive)
            {
                sb.AppendLine("    <li><strong>Transitive dependencies not fully resolved</strong> - Deep dependency tree may be incomplete</li>");
            }
            if (_hasUnresolvedVersions)
            {
                sb.AppendLine("    <li><strong>Unresolved MSBuild variables</strong> - Some package versions could not be determined</li>");
            }
            sb.AppendLine("  </ul>");
            sb.AppendLine("  <p><strong>To fix:</strong> Run <code>dotnet restore</code> in your project directory before generating the report.</p>");
            sb.AppendLine("</div>");
        }

        var statusClass = report.OverallComplianceStatus switch
        {
            CraComplianceStatus.Compliant => "healthy",
            CraComplianceStatus.ActionRequired => "warning",
            _ => "critical"
        };

        sb.AppendLine("<div class=\"overview-grid\">");

        // Health Score Card
        sb.AppendLine("  <div class=\"card score-card\">");
        sb.AppendLine("    <h3>Health Score</h3>");
        sb.AppendLine($"    <div class=\"score-gauge {GetScoreClass(report.HealthScore)}\">");
        sb.AppendLine($"      <svg viewBox=\"0 0 100 50\">");
        sb.AppendLine($"        <path class=\"gauge-bg\" d=\"M 10 50 A 40 40 0 0 1 90 50\" />");
        var angle = 180 * (report.HealthScore / 100.0);
        sb.AppendLine($"        <path class=\"gauge-fill\" d=\"M 10 50 A 40 40 0 0 1 90 50\" style=\"stroke-dasharray: {angle * 1.26}, 226\" />");
        sb.AppendLine($"      </svg>");
        sb.AppendLine($"      <div class=\"score-value\">{report.HealthScore}</div>");
        sb.AppendLine("    </div>");
        sb.AppendLine($"    <div class=\"score-label {GetScoreClass(report.HealthScore)}\">{report.HealthStatus}</div>");
        sb.AppendLine("  </div>");

        // Compliance Status Card
        sb.AppendLine($"  <div class=\"card status-card {statusClass}\">");
        sb.AppendLine("    <h3>CRA Compliance</h3>");
        sb.AppendLine($"    <div class=\"big-status\">{report.OverallComplianceStatus}</div>");
        var compliantCount = report.ComplianceItems.Count(i => i.Status == CraComplianceStatus.Compliant);
        sb.AppendLine($"    <div class=\"status-detail\">{compliantCount}/{report.ComplianceItems.Count} requirements met</div>");
        sb.AppendLine("  </div>");

        // Summary Cards
        sb.AppendLine("  <div class=\"card metric-card\">");
        sb.AppendLine($"    <div class=\"metric-value\">{report.PackageCount}</div>");
        sb.AppendLine("    <div class=\"metric-label\">Total Packages</div>");
        sb.AppendLine("  </div>");

        sb.AppendLine("  <div class=\"card metric-card\">");
        sb.AppendLine($"    <div class=\"metric-value {(report.VulnerabilityCount > 0 ? "critical" : "")}\">{report.VulnerabilityCount}</div>");
        sb.AppendLine("    <div class=\"metric-label\">Vulnerabilities</div>");
        sb.AppendLine("  </div>");

        sb.AppendLine("  <div class=\"card metric-card\">");
        sb.AppendLine($"    <div class=\"metric-value {(report.CriticalPackageCount > 0 ? "critical" : "")}\">{report.CriticalPackageCount}</div>");
        sb.AppendLine("    <div class=\"metric-label\">Critical Packages</div>");
        sb.AppendLine("  </div>");

        sb.AppendLine("</div>");

        // Quick Actions
        if (report.ComplianceItems.Any(i => i.Status != CraComplianceStatus.Compliant))
        {
            sb.AppendLine("<div class=\"card recommendations-card\">");
            sb.AppendLine("  <h3>Recommended Actions</h3>");
            sb.AppendLine("  <ul class=\"action-list\">");
            foreach (var item in report.ComplianceItems.Where(i => !string.IsNullOrEmpty(i.Recommendation)))
            {
                sb.AppendLine($"    <li><strong>{EscapeHtml(item.Requirement)}:</strong> {EscapeHtml(item.Recommendation!)}</li>");
            }
            sb.AppendLine("  </ul>");
            sb.AppendLine("</div>");
        }
    }

    private void GeneratePackagesSection(StringBuilder sb, CraReport report)
    {
        sb.AppendLine("<div class=\"section-header\">");
        sb.AppendLine("  <h2>Package Health</h2>");
        sb.AppendLine("  <input type=\"text\" id=\"package-search\" class=\"search-input\" placeholder=\"Search packages...\" onkeyup=\"filterPackages()\">");
        sb.AppendLine("</div>");

        sb.AppendLine("<div class=\"filter-bar\">");
        sb.AppendLine("  <button class=\"filter-btn active\" onclick=\"filterByStatus('all')\">All</button>");
        sb.AppendLine("  <button class=\"filter-btn healthy\" onclick=\"filterByStatus('healthy')\">Healthy</button>");
        sb.AppendLine("  <button class=\"filter-btn watch\" onclick=\"filterByStatus('watch')\">Watch</button>");
        sb.AppendLine("  <button class=\"filter-btn warning\" onclick=\"filterByStatus('warning')\">Warning</button>");
        sb.AppendLine("  <button class=\"filter-btn critical\" onclick=\"filterByStatus('critical')\">Critical</button>");
        sb.AppendLine("</div>");

        // Check for unresolved MSBuild variables
        var unresolvedVersions = report.Sbom.Packages
            .Where(p => p.VersionInfo?.Contains("$(") == true)
            .Select(p => p.VersionInfo)
            .Distinct()
            .ToList();

        if (unresolvedVersions.Count > 0)
        {
            sb.AppendLine("<div class=\"msb-warning\">");
            sb.AppendLine("  <h4>&#9888; Unresolved MSBuild Variables</h4>");
            sb.AppendLine("  <p>Some package versions contain MSBuild variables that couldn't be resolved:</p>");
            sb.AppendLine("  <p style=\"margin-top: 8px;\">");
            foreach (var v in unresolvedVersions.Take(5))
            {
                sb.AppendLine($"    <code>{EscapeHtml(v)}</code> ");
            }
            if (unresolvedVersions.Count > 5)
                sb.AppendLine($"    <em>and {unresolvedVersions.Count - 5} more...</em>");
            sb.AppendLine("  </p>");
            sb.AppendLine("  <p style=\"margin-top: 10px;\"><strong>To resolve:</strong> Run <code>dotnet restore</code> first, or check your <code>Directory.Build.props</code> / <code>Directory.Packages.props</code> files.</p>");
            sb.AppendLine("</div>");
        }

        sb.AppendLine("<div id=\"packages-list\" class=\"packages-list\">");

        // Build set of all package IDs in the report for internal linking
        var allPackageIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var pkg in report.Sbom.Packages.Skip(1))
            allPackageIds.Add(pkg.Name);
        if (_transitiveDataCache != null)
            foreach (var t in _transitiveDataCache)
                allPackageIds.Add(t.PackageId);

        foreach (var pkg in report.Sbom.Packages.Skip(1))
        {
            var pkgName = pkg.Name;
            var version = pkg.VersionInfo;
            var score = 70; // Default score
            var status = "watch";

            // Find matching health data
            var healthData = _healthDataCache?.FirstOrDefault(h => h.PackageId == pkgName);
            if (healthData != null)
            {
                score = healthData.Score;
                status = healthData.Status.ToString().ToLowerInvariant();
            }

            sb.AppendLine($"  <div class=\"package-card\" id=\"pkg-{EscapeHtml(pkgName)}\" data-status=\"{status}\" data-name=\"{EscapeHtml(pkgName.ToLowerInvariant())}\">");
            sb.AppendLine("    <div class=\"package-header\" onclick=\"togglePackage(this)\">");
            sb.AppendLine($"      <div class=\"package-info\">");
            sb.AppendLine($"        <span class=\"package-name\">{EscapeHtml(pkgName)}</span>");
            sb.AppendLine($"        <span class=\"package-version\">{FormatVersion(version, pkgName)}</span>");
            sb.AppendLine($"        <span class=\"dep-type-badge direct\" title=\"Direct dependency - referenced in your project file\">direct</span>");
            sb.AppendLine($"      </div>");
            sb.AppendLine($"      <div class=\"package-score {GetScoreClass(score)}\">{score}</div>");
            sb.AppendLine($"      <span class=\"expand-icon\">+</span>");
            sb.AppendLine("    </div>");
            sb.AppendLine("    <div class=\"package-details\">");

            if (healthData != null)
            {
                sb.AppendLine("      <div class=\"detail-grid\">");
                sb.AppendLine($"        <div class=\"detail-item\"><span class=\"label\">License</span><span class=\"value\">{FormatLicense(healthData.License)}</span></div>");
                sb.AppendLine($"        <div class=\"detail-item\"><span class=\"label\">Last Release</span><span class=\"value\">{FormatDaysSinceRelease(healthData.Metrics.DaysSinceLastRelease)}</span></div>");
                sb.AppendLine($"        <div class=\"detail-item\"><span class=\"label\">Releases/Year</span><span class=\"value\">{healthData.Metrics.ReleasesPerYear:F1}</span></div>");
                sb.AppendLine($"        <div class=\"detail-item\"><span class=\"label\">Downloads</span><span class=\"value\">{FormatNumber(healthData.Metrics.TotalDownloads)}</span></div>");
                if (healthData.Metrics.Stars.HasValue)
                    sb.AppendLine($"        <div class=\"detail-item\"><span class=\"label\">GitHub Stars</span><span class=\"value\">{FormatNumber(healthData.Metrics.Stars.Value)}</span></div>");
                if (healthData.Metrics.DaysSinceLastCommit.HasValue)
                    sb.AppendLine($"        <div class=\"detail-item\"><span class=\"label\">Last Commit</span><span class=\"value\">{healthData.Metrics.DaysSinceLastCommit} days ago</span></div>");
                sb.AppendLine("      </div>");

                if (healthData.Recommendations.Count > 0)
                {
                    sb.AppendLine("      <div class=\"recommendations\">");
                    sb.AppendLine("        <h4>Recommendations</h4>");
                    sb.AppendLine("        <ul>");
                    foreach (var rec in healthData.Recommendations)
                        sb.AppendLine($"          <li>{EscapeHtml(rec)}</li>");
                    sb.AppendLine("        </ul>");
                    sb.AppendLine("      </div>");
                }

                if (healthData.Vulnerabilities.Count > 0)
                {
                    sb.AppendLine("      <div class=\"vulnerabilities-badge\">");
                    sb.AppendLine($"        <span class=\"vuln-count\">{healthData.Vulnerabilities.Count} vulnerabilities</span>");
                    sb.AppendLine("      </div>");
                }

                // Dependencies (what this package uses)
                if (healthData.Dependencies.Count > 0)
                {
                    sb.AppendLine("      <div class=\"package-dependencies\">");
                    sb.AppendLine($"        <h4>Dependencies ({healthData.Dependencies.Count})</h4>");
                    sb.AppendLine("        <div class=\"dep-list\">");
                    foreach (var dep in healthData.Dependencies.Take(10))
                    {
                        if (allPackageIds.Contains(dep.PackageId))
                        {
                            // Internal link - navigate to the package on this page
                            sb.AppendLine($"          <a href=\"#pkg-{EscapeHtml(dep.PackageId)}\" class=\"dep-item dep-internal\" title=\"{EscapeHtml(dep.VersionRange ?? "any")} - Click to jump to package\" onclick=\"navigateToPackage('{EscapeJs(dep.PackageId)}'); return false;\">{EscapeHtml(dep.PackageId)}</a>");
                        }
                        else
                        {
                            // External link - go to NuGet.org
                            sb.AppendLine($"          <a href=\"https://www.nuget.org/packages/{EscapeHtml(dep.PackageId)}\" target=\"_blank\" class=\"dep-item dep-external\" title=\"{EscapeHtml(dep.VersionRange ?? "any")} - External dependency (NuGet.org)\">{EscapeHtml(dep.PackageId)}</a>");
                        }
                    }
                    if (healthData.Dependencies.Count > 10)
                    {
                        sb.AppendLine($"          <span class=\"dep-more\">+{healthData.Dependencies.Count - 10} more</span>");
                    }
                    sb.AppendLine("        </div>");
                    sb.AppendLine("      </div>");
                }
            }

            sb.AppendLine($"      <div class=\"package-links\">");
            sb.AppendLine($"        <a href=\"https://www.nuget.org/packages/{EscapeHtml(pkgName)}/{EscapeHtml(version)}\" target=\"_blank\">NuGet</a>");
            if (!string.IsNullOrEmpty(healthData?.RepositoryUrl))
                sb.AppendLine($"        <a href=\"{EscapeHtml(healthData.RepositoryUrl)}\" target=\"_blank\">Repository</a>");
            sb.AppendLine($"      </div>");
            sb.AppendLine("    </div>");
            sb.AppendLine("  </div>");
        }

        sb.AppendLine("</div>");

        // Transitive Dependencies Section
        if (_transitiveDataCache?.Count > 0)
        {
            sb.AppendLine("<div class=\"transitive-section\">");
            sb.AppendLine("  <div class=\"transitive-header\" onclick=\"toggleTransitive()\">");
            sb.AppendLine($"    <h3>Transitive Dependencies ({_transitiveDataCache.Count})</h3>");
            sb.AppendLine("    <span class=\"transitive-toggle\" id=\"transitive-toggle\">Show</span>");
            sb.AppendLine("  </div>");
            sb.AppendLine("  <div id=\"transitive-list\" class=\"packages-list transitive-list\" style=\"display: none;\">");

            foreach (var healthData in _transitiveDataCache.OrderBy(h => h.Score))
            {
                var pkgName = healthData.PackageId;
                var version = healthData.Version;
                var score = healthData.Score;
                var status = healthData.Status.ToString().ToLowerInvariant();

                var depTypeBadge = healthData.DependencyType switch
                {
                    DependencyType.SubDependency => "<span class=\"dep-type-badge sub-dep\" title=\"Sub-dependency - a dependency of another package\">sub-dependency</span>",
                    _ => "<span class=\"dep-type-badge transitive\" title=\"Transitive dependency - pulled in by NuGet dependency resolution\">transitive</span>"
                };

                sb.AppendLine($"  <div class=\"package-card transitive\" id=\"pkg-{EscapeHtml(pkgName)}\" data-status=\"{status}\" data-name=\"{EscapeHtml(pkgName.ToLowerInvariant())}\">");
                sb.AppendLine("    <div class=\"package-header\" onclick=\"togglePackage(this)\">");
                sb.AppendLine($"      <div class=\"package-info\">");
                sb.AppendLine($"        <span class=\"package-name\">{EscapeHtml(pkgName)}</span>");
                sb.AppendLine($"        <span class=\"package-version\">{FormatVersion(version, pkgName)}</span>");
                sb.AppendLine($"        {depTypeBadge}");
                sb.AppendLine($"      </div>");
                sb.AppendLine($"      <div class=\"package-score {GetScoreClass(score)}\">{score}</div>");
                sb.AppendLine($"      <span class=\"expand-icon\">+</span>");
                sb.AppendLine("    </div>");
                sb.AppendLine("    <div class=\"package-details\">");

                sb.AppendLine("      <div class=\"detail-grid\">");
                sb.AppendLine($"        <div class=\"detail-item\"><span class=\"label\">License</span><span class=\"value\">{FormatLicense(healthData.License)}</span></div>");
                sb.AppendLine($"        <div class=\"detail-item\"><span class=\"label\">Last Release</span><span class=\"value\">{FormatDaysSinceRelease(healthData.Metrics.DaysSinceLastRelease)}</span></div>");
                sb.AppendLine($"        <div class=\"detail-item\"><span class=\"label\">Releases/Year</span><span class=\"value\">{healthData.Metrics.ReleasesPerYear:F1}</span></div>");
                sb.AppendLine($"        <div class=\"detail-item\"><span class=\"label\">Downloads</span><span class=\"value\">{FormatNumber(healthData.Metrics.TotalDownloads)}</span></div>");
                if (healthData.Metrics.Stars.HasValue)
                    sb.AppendLine($"        <div class=\"detail-item\"><span class=\"label\">GitHub Stars</span><span class=\"value\">{FormatNumber(healthData.Metrics.Stars.Value)}</span></div>");
                if (healthData.Metrics.DaysSinceLastCommit.HasValue)
                    sb.AppendLine($"        <div class=\"detail-item\"><span class=\"label\">Last Commit</span><span class=\"value\">{healthData.Metrics.DaysSinceLastCommit} days ago</span></div>");
                sb.AppendLine("      </div>");

                if (healthData.Recommendations.Count > 0)
                {
                    sb.AppendLine("      <div class=\"recommendations\">");
                    sb.AppendLine("        <h4>Recommendations</h4>");
                    sb.AppendLine("        <ul>");
                    foreach (var rec in healthData.Recommendations)
                        sb.AppendLine($"          <li>{EscapeHtml(rec)}</li>");
                    sb.AppendLine("        </ul>");
                    sb.AppendLine("      </div>");
                }

                if (healthData.Vulnerabilities.Count > 0)
                {
                    sb.AppendLine("      <div class=\"vulnerabilities-badge\">");
                    sb.AppendLine($"        <span class=\"vuln-count\">{healthData.Vulnerabilities.Count} vulnerabilities</span>");
                    sb.AppendLine("      </div>");
                }

                sb.AppendLine($"      <div class=\"package-links\">");
                sb.AppendLine($"        <a href=\"https://www.nuget.org/packages/{EscapeHtml(pkgName)}/{EscapeHtml(version)}\" target=\"_blank\">NuGet</a>");
                if (!string.IsNullOrEmpty(healthData.RepositoryUrl))
                    sb.AppendLine($"        <a href=\"{EscapeHtml(healthData.RepositoryUrl)}\" target=\"_blank\">Repository</a>");
                sb.AppendLine($"      </div>");
                sb.AppendLine("    </div>");
                sb.AppendLine("  </div>");
            }

            sb.AppendLine("  </div>");
            sb.AppendLine("</div>");
        }
    }

    private void GenerateSbomSection(StringBuilder sb, CraReport report, List<SbomPackage> packages)
    {
        sb.AppendLine("<div class=\"section-header\">");
        sb.AppendLine("  <h2>Software Bill of Materials (SBOM)</h2>");
        sb.AppendLine("  <div class=\"sbom-meta\">");
        sb.AppendLine($"    <span class=\"meta-item\">Format: SPDX {report.Sbom.SpdxVersion}</span>");
        sb.AppendLine($"    <span class=\"meta-item\">Components: {packages.Count}</span>");
        sb.AppendLine("  </div>");
        sb.AppendLine("</div>");

        sb.AppendLine("<div class=\"card\">");
        sb.AppendLine("  <input type=\"text\" id=\"sbom-search\" class=\"search-input\" placeholder=\"Search components...\" onkeyup=\"filterSbom()\">");
        sb.AppendLine("  <table class=\"sbom-table\" id=\"sbom-table\">");
        sb.AppendLine("    <thead>");
        sb.AppendLine("      <tr>");
        sb.AppendLine("        <th>Component</th>");
        sb.AppendLine("        <th>Version</th>");
        sb.AppendLine("        <th>License</th>");
        sb.AppendLine("        <th>PURL</th>");
        sb.AppendLine("      </tr>");
        sb.AppendLine("    </thead>");
        sb.AppendLine("    <tbody>");

        foreach (var pkg in packages)
        {
            var purl = pkg.ExternalRefs?.FirstOrDefault(r => r.ReferenceType == "purl")?.ReferenceLocator ?? "";
            var versionDisplay = FormatVersionForSbom(pkg.VersionInfo);
            var purlDisplay = FormatPurlForSbom(purl);

            sb.AppendLine($"    <tr data-name=\"{EscapeHtml(pkg.Name.ToLowerInvariant())}\">");
            sb.AppendLine($"      <td class=\"component-name\">");
            sb.AppendLine($"        <strong>{EscapeHtml(pkg.Name)}</strong>");
            sb.AppendLine($"        <a href=\"{EscapeHtml(pkg.DownloadLocation)}\" target=\"_blank\" class=\"external-link\">View on NuGet</a>");
            sb.AppendLine($"      </td>");
            sb.AppendLine($"      <td>{versionDisplay}</td>");
            sb.AppendLine($"      <td><span class=\"license-badge\">{FormatLicense(pkg.LicenseDeclared)}</span></td>");
            sb.AppendLine($"      <td class=\"purl\"><code>{purlDisplay}</code></td>");
            sb.AppendLine($"    </tr>");
        }

        sb.AppendLine("    </tbody>");
        sb.AppendLine("  </table>");
        sb.AppendLine("</div>");

        // SBOM Export
        sb.AppendLine("<div class=\"export-section\">");
        sb.AppendLine("  <button onclick=\"exportSbom('spdx')\" class=\"export-btn\">Export SPDX JSON</button>");
        sb.AppendLine("  <button onclick=\"exportSbom('cyclonedx')\" class=\"export-btn\">Export CycloneDX</button>");
        sb.AppendLine("</div>");
    }

    private void GenerateLicensesSection(StringBuilder sb, CraReport report)
    {
        sb.AppendLine("<div class=\"section-header\">");
        sb.AppendLine("  <h2>License Compatibility</h2>");
        sb.AppendLine("  <p>Analysis of license types and potential compatibility issues</p>");
        sb.AppendLine("</div>");

        // Gather licenses from packages
        var packageLicenses = new List<(string PackageId, string? License)>();
        if (_healthDataCache != null)
        {
            foreach (var pkg in _healthDataCache)
            {
                packageLicenses.Add((pkg.PackageId, pkg.License));
            }
        }
        if (_transitiveDataCache != null)
        {
            foreach (var pkg in _transitiveDataCache)
            {
                packageLicenses.Add((pkg.PackageId, pkg.License));
            }
        }

        var licenseReport = LicenseCompatibility.AnalyzeLicenses(packageLicenses);

        // Status banner
        var statusClass = licenseReport.OverallStatus switch
        {
            "Compatible" => "healthy",
            "Review Recommended" => "warning",
            _ => "critical"
        };
        sb.AppendLine($"<div class=\"license-status {statusClass}\">");
        sb.AppendLine($"  <span class=\"status-icon\">{(licenseReport.ErrorCount == 0 ? "✓" : "⚠")}</span>");
        sb.AppendLine($"  <span class=\"status-text\">{licenseReport.OverallStatus}</span>");
        if (licenseReport.ErrorCount > 0)
            sb.AppendLine($"  <span class=\"status-detail\">{licenseReport.ErrorCount} potential issues found</span>");
        sb.AppendLine("</div>");

        // License distribution chart (simple bar chart)
        sb.AppendLine("<div class=\"license-distribution\">");
        sb.AppendLine("  <h3>License Distribution</h3>");
        sb.AppendLine("  <div class=\"distribution-chart\">");

        var total = licenseReport.CategoryDistribution.Values.Sum();
        if (total > 0)
        {
            foreach (var (category, count) in licenseReport.CategoryDistribution.OrderByDescending(x => x.Value))
            {
                if (count == 0) continue;
                var percent = (count * 100) / total;
                var categoryClass = category switch
                {
                    LicenseCompatibility.LicenseCategory.Permissive => "permissive",
                    LicenseCompatibility.LicenseCategory.WeakCopyleft => "weak-copyleft",
                    LicenseCompatibility.LicenseCategory.StrongCopyleft => "strong-copyleft",
                    LicenseCompatibility.LicenseCategory.PublicDomain => "public-domain",
                    _ => "unknown"
                };
                sb.AppendLine($"    <div class=\"dist-bar {categoryClass}\" style=\"width: {Math.Max(percent, 5)}%\" title=\"{category}: {count} packages ({percent}%)\">");
                sb.AppendLine($"      <span class=\"dist-label\">{category}</span>");
                sb.AppendLine($"      <span class=\"dist-count\">{count}</span>");
                sb.AppendLine("    </div>");
            }
        }
        sb.AppendLine("  </div>");
        sb.AppendLine("</div>");

        // License table
        sb.AppendLine("<div class=\"license-table-container\">");
        sb.AppendLine("  <h3>Packages by License</h3>");
        sb.AppendLine("  <table class=\"license-table\">");
        sb.AppendLine("    <thead>");
        sb.AppendLine("      <tr><th>License</th><th>Category</th><th>Packages</th></tr>");
        sb.AppendLine("    </thead>");
        sb.AppendLine("    <tbody>");

        foreach (var (license, count) in licenseReport.LicenseDistribution.OrderByDescending(x => x.Value))
        {
            var info = LicenseCompatibility.GetLicenseInfo(license);
            var category = info?.Category.ToString() ?? "Unknown";
            var categoryClass = info?.Category switch
            {
                LicenseCompatibility.LicenseCategory.Permissive => "permissive",
                LicenseCompatibility.LicenseCategory.WeakCopyleft => "weak-copyleft",
                LicenseCompatibility.LicenseCategory.StrongCopyleft => "strong-copyleft",
                LicenseCompatibility.LicenseCategory.PublicDomain => "public-domain",
                _ => "unknown"
            };
            sb.AppendLine($"      <tr>");
            sb.AppendLine($"        <td>{FormatLicense(license)}</td>");
            sb.AppendLine($"        <td><span class=\"category-badge {categoryClass}\">{category}</span></td>");
            sb.AppendLine($"        <td>{count}</td>");
            sb.AppendLine($"      </tr>");
        }

        sb.AppendLine("    </tbody>");
        sb.AppendLine("  </table>");
        sb.AppendLine("</div>");

        // Compatibility issues
        if (licenseReport.CompatibilityResults.Count > 0)
        {
            var issues = licenseReport.CompatibilityResults.Where(r => !r.IsCompatible).ToList();
            if (issues.Count > 0)
            {
                sb.AppendLine("<div class=\"license-issues\">");
                sb.AppendLine("  <h3>Compatibility Issues</h3>");
                foreach (var issue in issues)
                {
                    var issueClass = issue.Severity.ToLowerInvariant();
                    sb.AppendLine($"  <div class=\"issue-item {issueClass}\">");
                    sb.AppendLine($"    <span class=\"issue-severity\">{issue.Severity}</span>");
                    sb.AppendLine($"    <span class=\"issue-message\">{EscapeHtml(issue.Message)}</span>");
                    if (!string.IsNullOrEmpty(issue.Recommendation))
                        sb.AppendLine($"    <span class=\"issue-recommendation\">{EscapeHtml(issue.Recommendation)}</span>");
                    sb.AppendLine("  </div>");
                }
                sb.AppendLine("</div>");
            }
        }

        // Unknown licenses
        if (licenseReport.UnknownLicenses.Count > 0)
        {
            sb.AppendLine("<div class=\"unknown-licenses\">");
            sb.AppendLine("  <h3>Unrecognized Licenses</h3>");
            sb.AppendLine("  <p>The following licenses could not be automatically categorized:</p>");
            sb.AppendLine("  <ul>");
            foreach (var license in licenseReport.UnknownLicenses.Take(20))
            {
                sb.AppendLine($"    <li><code>{EscapeHtml(license)}</code></li>");
            }
            if (licenseReport.UnknownLicenses.Count > 20)
                sb.AppendLine($"    <li><em>...and {licenseReport.UnknownLicenses.Count - 20} more</em></li>");
            sb.AppendLine("  </ul>");
            sb.AppendLine("</div>");
        }
    }

    private void GenerateVulnerabilitiesSection(StringBuilder sb, CraReport report)
    {
        sb.AppendLine("<div class=\"section-header\">");
        sb.AppendLine("  <h2>Vulnerability Status (VEX)</h2>");
        sb.AppendLine("</div>");

        var statements = report.Vex.Statements;

        if (statements.Count == 0)
        {
            sb.AppendLine("<div class=\"card empty-state\">");
            sb.AppendLine("  <div class=\"empty-icon\">&#10003;</div>");
            sb.AppendLine("  <h3>No Known Vulnerabilities</h3>");
            sb.AppendLine("  <p>No vulnerabilities were found in the analyzed packages.</p>");
            sb.AppendLine("</div>");
            return;
        }

        // Vulnerability summary
        var affectedCount = statements.Count(s => s.Status == VexStatus.Affected);
        var fixedCount = statements.Count(s => s.Status == VexStatus.Fixed);
        var notAffectedCount = statements.Count(s => s.Status == VexStatus.NotAffected);

        sb.AppendLine("<div class=\"vuln-summary\">");
        sb.AppendLine($"  <div class=\"vuln-stat affected\"><span class=\"count\">{affectedCount}</span><span class=\"label\">Affected</span></div>");
        sb.AppendLine($"  <div class=\"vuln-stat fixed\"><span class=\"count\">{fixedCount}</span><span class=\"label\">Fixed</span></div>");
        sb.AppendLine($"  <div class=\"vuln-stat not-affected\"><span class=\"count\">{notAffectedCount}</span><span class=\"label\">Not Affected</span></div>");
        sb.AppendLine("</div>");

        sb.AppendLine("<div class=\"vulnerabilities-list\">");

        foreach (var stmt in statements)
        {
            var statusClass = stmt.Status switch
            {
                VexStatus.Affected => "affected",
                VexStatus.Fixed => "fixed",
                _ => "not-affected"
            };

            sb.AppendLine($"  <div class=\"vuln-card {statusClass}\">");
            sb.AppendLine("    <div class=\"vuln-header\">");
            sb.AppendLine($"      <span class=\"vuln-id\">{EscapeHtml(stmt.Vulnerability.Name)}</span>");
            sb.AppendLine($"      <span class=\"vuln-status {statusClass}\">{stmt.Status.Replace("_", " ")}</span>");
            sb.AppendLine("    </div>");
            sb.AppendLine($"    <p class=\"vuln-description\">{EscapeHtml(stmt.Vulnerability.Description ?? "")}</p>");
            sb.AppendLine("    <div class=\"vuln-products\">");
            sb.AppendLine("      <strong>Affected Package:</strong>");
            foreach (var product in stmt.Products)
            {
                sb.AppendLine($"      <code>{EscapeHtml(product.Identifiers.Purl)}</code>");
            }
            sb.AppendLine("    </div>");
            if (!string.IsNullOrEmpty(stmt.ActionStatement))
            {
                sb.AppendLine($"    <div class=\"vuln-action\"><strong>Action:</strong> {EscapeHtml(stmt.ActionStatement)}</div>");
            }
            if (stmt.Vulnerability.Aliases?.Count > 0)
            {
                sb.AppendLine($"    <div class=\"vuln-aliases\"><strong>CVEs:</strong> {string.Join(", ", stmt.Vulnerability.Aliases.Select(EscapeHtml))}</div>");
            }
            sb.AppendLine("  </div>");
        }

        sb.AppendLine("</div>");
    }

    private void GenerateComplianceSection(StringBuilder sb, CraReport report)
    {
        sb.AppendLine("<div class=\"section-header\">");
        sb.AppendLine("  <h2>CRA Compliance Checklist</h2>");
        sb.AppendLine("</div>");

        sb.AppendLine("<div class=\"compliance-list\">");

        foreach (var item in report.ComplianceItems)
        {
            var statusClass = item.Status switch
            {
                CraComplianceStatus.Compliant => "compliant",
                CraComplianceStatus.ActionRequired => "action-required",
                _ => "non-compliant"
            };

            sb.AppendLine($"  <div class=\"compliance-item {statusClass}\">");
            sb.AppendLine("    <div class=\"compliance-header\">");
            sb.AppendLine($"      <div class=\"compliance-icon\">{(item.Status == CraComplianceStatus.Compliant ? "&#10003;" : item.Status == CraComplianceStatus.ActionRequired ? "!" : "&#10007;")}</div>");
            sb.AppendLine("      <div class=\"compliance-info\">");
            sb.AppendLine($"        <h3>{EscapeHtml(item.Requirement)}</h3>");
            sb.AppendLine($"        <p>{EscapeHtml(item.Description)}</p>");
            sb.AppendLine("      </div>");
            sb.AppendLine($"      <span class=\"compliance-status {statusClass}\">{item.Status}</span>");
            sb.AppendLine("    </div>");
            sb.AppendLine("    <div class=\"compliance-evidence\">");
            sb.AppendLine($"      <strong>Evidence:</strong> {EscapeHtml(item.Evidence ?? "N/A")}");
            sb.AppendLine("    </div>");
            if (!string.IsNullOrEmpty(item.Recommendation))
            {
                sb.AppendLine($"    <div class=\"compliance-recommendation\">");
                sb.AppendLine($"      <strong>Recommendation:</strong> {EscapeHtml(item.Recommendation)}");
                sb.AppendLine("    </div>");
            }
            sb.AppendLine("  </div>");
        }

        sb.AppendLine("</div>");

        // Legal disclaimer
        sb.AppendLine("<div class=\"card disclaimer\">");
        sb.AppendLine("  <h4>Disclaimer</h4>");
        sb.AppendLine("  <p>This report assists with EU Cyber Resilience Act compliance assessment. It is not legal advice. Consult legal counsel for authoritative compliance guidance.</p>");
        sb.AppendLine("</div>");
    }

    private static string GetHtmlStyles()
    {
        return @"
  <style>
    :root {
      --primary: #0066cc;
      --primary-dark: #004c99;
      --success: #28a745;
      --warning: #ffc107;
      --danger: #dc3545;
      --watch: #17a2b8;
      --bg: #f8f9fa;
      --card-bg: #ffffff;
      --text: #212529;
      --text-muted: #6c757d;
      --border: #dee2e6;
      --sidebar-width: 240px;
    }

    * { box-sizing: border-box; margin: 0; padding: 0; }

    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', sans-serif;
      background: var(--bg);
      color: var(--text);
      line-height: 1.6;
    }

    .sidebar {
      position: fixed;
      left: 0;
      top: 0;
      bottom: 0;
      width: var(--sidebar-width);
      background: linear-gradient(180deg, #1a1a2e 0%, #16213e 100%);
      color: white;
      padding: 20px 0;
      overflow-y: auto;
    }

    .sidebar-header {
      padding: 0 20px 20px;
      border-bottom: 1px solid rgba(255,255,255,0.1);
      margin-bottom: 20px;
    }

    .sidebar-header h2 {
      font-size: 1.25rem;
      font-weight: 600;
    }

    .nav-links {
      list-style: none;
    }

    .nav-links a {
      display: block;
      padding: 12px 20px;
      color: rgba(255,255,255,0.7);
      text-decoration: none;
      transition: all 0.2s;
      border-left: 3px solid transparent;
    }

    .nav-links a:hover, .nav-links a.active {
      background: rgba(255,255,255,0.1);
      color: white;
      border-left-color: var(--primary);
    }

    .main-content {
      margin-left: var(--sidebar-width);
      padding: 30px;
      min-height: 100vh;
    }

    .header {
      margin-bottom: 30px;
    }

    .header h1 {
      font-size: 1.75rem;
      font-weight: 600;
      color: var(--text);
    }

    .subtitle {
      color: var(--text-muted);
      font-size: 0.9rem;
    }

    .section {
      display: none;
    }

    .section.active {
      display: block;
    }

    .section-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 20px;
      flex-wrap: wrap;
      gap: 15px;
    }

    .section-header h2 {
      font-size: 1.5rem;
      font-weight: 600;
    }

    .card {
      background: var(--card-bg);
      border-radius: 12px;
      padding: 24px;
      margin-bottom: 20px;
      box-shadow: 0 1px 3px rgba(0,0,0,0.1);
    }

    .overview-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 20px;
      margin-bottom: 30px;
    }

    .score-card {
      text-align: center;
    }

    .score-gauge {
      position: relative;
      width: 150px;
      height: 80px;
      margin: 20px auto;
    }

    .score-gauge svg {
      width: 100%;
      height: 100%;
    }

    .gauge-bg {
      fill: none;
      stroke: #e9ecef;
      stroke-width: 8;
      stroke-linecap: round;
    }

    .gauge-fill {
      fill: none;
      stroke: var(--primary);
      stroke-width: 8;
      stroke-linecap: round;
      transform-origin: center;
      transition: stroke-dasharray 0.5s;
    }

    .score-gauge.healthy .gauge-fill { stroke: var(--success); }
    .score-gauge.watch .gauge-fill { stroke: var(--watch); }
    .score-gauge.warning .gauge-fill { stroke: var(--warning); }
    .score-gauge.critical .gauge-fill { stroke: var(--danger); }

    .score-value {
      position: absolute;
      bottom: 0;
      left: 50%;
      transform: translateX(-50%);
      font-size: 2rem;
      font-weight: 700;
    }

    .score-label {
      font-weight: 600;
      text-transform: uppercase;
      font-size: 0.85rem;
    }

    .score-label.healthy, .healthy { color: var(--success); }
    .score-label.watch, .watch { color: var(--watch); }
    .score-label.warning, .warning { color: var(--warning); }
    .score-label.critical, .critical { color: var(--danger); }

    .status-card {
      text-align: center;
    }

    .status-card.healthy { border-left: 4px solid var(--success); }
    .status-card.warning { border-left: 4px solid var(--warning); }
    .status-card.critical { border-left: 4px solid var(--danger); }

    .big-status {
      font-size: 1.5rem;
      font-weight: 700;
      margin: 15px 0;
    }

    .status-detail {
      color: var(--text-muted);
      font-size: 0.9rem;
    }

    .metric-card {
      text-align: center;
    }

    .metric-value {
      font-size: 2.5rem;
      font-weight: 700;
      color: var(--primary);
    }

    .metric-label {
      color: var(--text-muted);
      font-size: 0.9rem;
    }

    .search-input {
      padding: 10px 15px;
      border: 1px solid var(--border);
      border-radius: 8px;
      font-size: 0.9rem;
      width: 250px;
    }

    .filter-bar {
      display: flex;
      gap: 10px;
      margin-bottom: 20px;
      flex-wrap: wrap;
    }

    .filter-btn {
      padding: 8px 16px;
      border: 1px solid var(--border);
      background: white;
      border-radius: 20px;
      cursor: pointer;
      font-size: 0.85rem;
      transition: all 0.2s;
    }

    .filter-btn:hover, .filter-btn.active {
      background: var(--primary);
      color: white;
      border-color: var(--primary);
    }

    .filter-btn.healthy.active { background: var(--success); border-color: var(--success); }
    .filter-btn.watch.active { background: var(--watch); border-color: var(--watch); }
    .filter-btn.warning.active { background: var(--warning); border-color: var(--warning); color: #000; }
    .filter-btn.critical.active { background: var(--danger); border-color: var(--danger); }

    .packages-list {
      display: flex;
      flex-direction: column;
      gap: 10px;
    }

    .package-card {
      background: var(--card-bg);
      border-radius: 8px;
      overflow: hidden;
      box-shadow: 0 1px 3px rgba(0,0,0,0.1);
    }

    .package-card[data-status='healthy'] { border-left: 4px solid var(--success); }
    .package-card[data-status='watch'] { border-left: 4px solid var(--watch); }
    .package-card[data-status='warning'] { border-left: 4px solid var(--warning); }
    .package-card[data-status='critical'] { border-left: 4px solid var(--danger); }

    .package-header {
      display: flex;
      align-items: center;
      padding: 15px 20px;
      cursor: pointer;
      transition: background 0.2s;
    }

    .package-header:hover {
      background: var(--bg);
    }

    .package-info {
      flex: 1;
    }

    .package-name {
      font-weight: 600;
      font-size: 1rem;
    }

    .package-version {
      color: var(--text-muted);
      font-size: 0.85rem;
      margin-left: 10px;
    }

    .package-score {
      width: 40px;
      height: 40px;
      border-radius: 50%;
      display: flex;
      align-items: center;
      justify-content: center;
      font-weight: 700;
      color: white;
      margin-right: 15px;
    }

    .package-score.healthy { background: var(--success); }
    .package-score.watch { background: var(--watch); }
    .package-score.warning { background: var(--warning); color: #000; }
    .package-score.critical { background: var(--danger); }

    .expand-icon {
      font-size: 1.25rem;
      color: var(--text-muted);
      transition: transform 0.2s;
    }

    .package-card.expanded .expand-icon {
      transform: rotate(45deg);
    }

    .package-details {
      display: none;
      padding: 20px;
      border-top: 1px solid var(--border);
      background: var(--bg);
    }

    .package-card.expanded .package-details {
      display: block;
    }

    .detail-grid {
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(180px, 1fr));
      gap: 15px;
      margin-bottom: 20px;
    }

    .detail-item {
      min-width: 0;
      overflow: hidden;
    }

    .detail-item .label {
      display: block;
      color: var(--text-muted);
      font-size: 0.8rem;
      margin-bottom: 3px;
    }

    .detail-item .value {
      font-weight: 500;
      word-break: break-word;
      overflow-wrap: break-word;
      display: block;
      max-width: 100%;
    }

    .detail-item .value a {
      color: var(--primary);
      text-decoration: none;
    }

    .detail-item .value a:hover {
      text-decoration: underline;
    }

    .detail-item.full-width {
      grid-column: 1 / -1;
    }

    .unresolved-version {
      background: #fff3cd;
      color: #856404;
      padding: 2px 6px;
      border-radius: 4px;
      font-size: 0.85rem;
      cursor: help;
    }

    .version-hint {
      font-size: 0.75rem;
      opacity: 0.7;
      margin-left: 2px;
    }

    .unknown-date {
      color: #6c757d;
      font-style: italic;
      cursor: help;
    }

    .license-unknown {
      background: #f8d7da;
      color: #721c24;
      padding: 2px 8px;
      border-radius: 4px;
      font-size: 0.85rem;
      cursor: help;
    }

    .license-link {
      color: var(--primary);
      text-decoration: none;
    }

    .license-link:hover {
      text-decoration: underline;
    }

    .msb-warning {
      background: #fff3cd;
      border: 1px solid #ffc107;
      border-left: 4px solid #ffc107;
      border-radius: 8px;
      padding: 15px 20px;
      margin-bottom: 20px;
    }

    .msb-warning h4 {
      color: #856404;
      margin-bottom: 8px;
      font-size: 1rem;
    }

    .msb-warning p {
      color: #856404;
      font-size: 0.9rem;
      margin: 0;
    }

    .msb-warning code {
      background: rgba(0,0,0,0.1);
      padding: 2px 6px;
      border-radius: 3px;
      font-size: 0.85rem;
    }

    .sbom-warning {
      background: linear-gradient(135deg, #fff3cd 0%, #ffeeba 100%);
      border: 1px solid #ffc107;
      border-left: 4px solid #e65100;
      border-radius: 8px;
      padding: 20px;
      margin-bottom: 24px;
    }

    .sbom-warning h4 {
      color: #e65100;
      margin: 0 0 12px 0;
      font-size: 1.1rem;
    }

    .sbom-warning p {
      color: #5d4037;
      font-size: 0.9rem;
      margin: 8px 0;
    }

    .sbom-warning ul {
      margin: 12px 0;
      padding-left: 24px;
      color: #5d4037;
    }

    .sbom-warning li {
      margin: 6px 0;
      font-size: 0.9rem;
    }

    .sbom-warning code {
      background: rgba(0,0,0,0.1);
      padding: 2px 8px;
      border-radius: 4px;
      font-size: 0.9rem;
      font-family: monospace;
    }

    /* License Section Styles */
    .license-status {
      display: flex;
      align-items: center;
      gap: 12px;
      padding: 16px 20px;
      border-radius: 8px;
      margin-bottom: 24px;
    }

    .license-status.healthy {
      background: linear-gradient(135deg, #d4edda 0%, #c3e6cb 100%);
      border: 1px solid #28a745;
    }

    .license-status.warning {
      background: linear-gradient(135deg, #fff3cd 0%, #ffeeba 100%);
      border: 1px solid #ffc107;
    }

    .license-status.critical {
      background: linear-gradient(135deg, #f8d7da 0%, #f5c6cb 100%);
      border: 1px solid #dc3545;
    }

    .license-status .status-icon {
      font-size: 1.5rem;
    }

    .license-status .status-text {
      font-weight: 600;
      font-size: 1.1rem;
    }

    .license-status .status-detail {
      color: #666;
      font-size: 0.9rem;
    }

    .license-distribution {
      background: white;
      border-radius: 8px;
      padding: 20px;
      margin-bottom: 24px;
      box-shadow: var(--shadow);
    }

    .license-distribution h3 {
      margin: 0 0 16px 0;
      color: var(--text);
    }

    .distribution-chart {
      display: flex;
      flex-direction: column;
      gap: 8px;
    }

    .dist-bar {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 10px 16px;
      border-radius: 6px;
      color: white;
      font-weight: 500;
      min-width: 120px;
      transition: transform 0.2s;
    }

    .dist-bar:hover {
      transform: translateX(4px);
    }

    .dist-bar.permissive { background: linear-gradient(90deg, #28a745, #34ce57); }
    .dist-bar.weak-copyleft { background: linear-gradient(90deg, #17a2b8, #20c9e0); }
    .dist-bar.strong-copyleft { background: linear-gradient(90deg, #dc3545, #e4606d); }
    .dist-bar.public-domain { background: linear-gradient(90deg, #6f42c1, #8b5cf6); }
    .dist-bar.unknown { background: linear-gradient(90deg, #6c757d, #868e96); }

    .dist-count {
      background: rgba(255,255,255,0.2);
      padding: 2px 8px;
      border-radius: 10px;
      font-size: 0.85rem;
    }

    .license-table-container {
      background: white;
      border-radius: 8px;
      padding: 20px;
      margin-bottom: 24px;
      box-shadow: var(--shadow);
    }

    .license-table {
      width: 100%;
      border-collapse: collapse;
    }

    .license-table th, .license-table td {
      padding: 12px;
      text-align: left;
      border-bottom: 1px solid var(--border);
    }

    .license-table th {
      background: #f8f9fa;
      font-weight: 600;
    }

    .category-badge {
      display: inline-block;
      padding: 4px 12px;
      border-radius: 12px;
      font-size: 0.8rem;
      font-weight: 500;
      color: white;
    }

    .category-badge.permissive { background: #28a745; }
    .category-badge.weak-copyleft { background: #17a2b8; }
    .category-badge.strong-copyleft { background: #dc3545; }
    .category-badge.public-domain { background: #6f42c1; }
    .category-badge.unknown { background: #6c757d; }

    .license-issues {
      background: white;
      border-radius: 8px;
      padding: 20px;
      margin-bottom: 24px;
      box-shadow: var(--shadow);
    }

    .issue-item {
      display: flex;
      flex-direction: column;
      gap: 4px;
      padding: 12px;
      border-radius: 6px;
      margin-bottom: 8px;
    }

    .issue-item.error {
      background: #f8d7da;
      border-left: 4px solid #dc3545;
    }

    .issue-item.warning {
      background: #fff3cd;
      border-left: 4px solid #ffc107;
    }

    .issue-severity {
      font-weight: 600;
      font-size: 0.85rem;
      text-transform: uppercase;
    }

    .issue-message {
      color: #333;
    }

    .issue-recommendation {
      color: #666;
      font-size: 0.9rem;
      font-style: italic;
    }

    .unknown-licenses {
      background: #f8f9fa;
      border-radius: 8px;
      padding: 20px;
      margin-bottom: 24px;
    }

    .unknown-licenses ul {
      margin: 12px 0;
      padding-left: 24px;
    }

    .unknown-licenses li {
      margin: 4px 0;
    }

    .package-dependencies {
      margin-top: 15px;
      padding: 15px;
      background: #f8f9fa;
      border-radius: 8px;
      border: 1px solid var(--border);
    }

    .package-dependencies h4 {
      margin-bottom: 10px;
      font-size: 0.9rem;
      color: var(--text-muted);
    }

    .dep-list {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
    }

    .dep-item {
      display: inline-block;
      padding: 4px 10px;
      background: white;
      border: 1px solid var(--border);
      border-radius: 15px;
      font-size: 0.8rem;
      color: var(--primary);
      text-decoration: none;
      transition: all 0.2s;
    }

    .dep-item:hover {
      background: var(--primary);
      color: white;
      border-color: var(--primary);
    }

    .dep-more {
      display: inline-block;
      padding: 4px 10px;
      font-size: 0.8rem;
      color: var(--text-muted);
    }

    .dep-internal {
      background: #e8f4f8;
      border-color: var(--primary);
      cursor: pointer;
    }

    .dep-internal::after {
      content: ' ↗';
      font-size: 0.7rem;
      opacity: 0.6;
    }

    .dep-internal:hover {
      background: var(--primary);
      color: white;
    }

    .dep-external {
      background: #f8f8f8;
      border-color: #ddd;
    }

    .dep-external::after {
      content: ' ↗';
      font-size: 0.7rem;
      opacity: 0.4;
    }

    .package-card.highlight {
      animation: highlightPulse 2s ease-out;
    }

    @keyframes highlightPulse {
      0% { box-shadow: 0 0 0 4px rgba(37, 99, 235, 0.6); }
      100% { box-shadow: none; }
    }

    .recommendations {
      background: #fff3cd;
      padding: 15px;
      border-radius: 8px;
      margin-bottom: 15px;
    }

    .recommendations h4 {
      margin-bottom: 10px;
      color: #856404;
    }

    .recommendations ul {
      margin-left: 20px;
    }

    .vulnerabilities-badge {
      background: var(--danger);
      color: white;
      padding: 8px 15px;
      border-radius: 8px;
      display: inline-block;
    }

    .package-links {
      margin-top: 15px;
    }

    .package-links a {
      color: var(--primary);
      margin-right: 15px;
      text-decoration: none;
    }

    .package-links a:hover {
      text-decoration: underline;
    }

    .sbom-table {
      width: 100%;
      border-collapse: collapse;
      margin-top: 15px;
    }

    .sbom-table th, .sbom-table td {
      padding: 12px;
      text-align: left;
      border-bottom: 1px solid var(--border);
    }

    .sbom-table th {
      background: var(--bg);
      font-weight: 600;
    }

    .component-name strong {
      display: block;
    }

    .external-link {
      font-size: 0.8rem;
      color: var(--primary);
    }

    .license-badge {
      background: var(--bg);
      padding: 4px 8px;
      border-radius: 4px;
      font-size: 0.85rem;
    }

    .purl code {
      background: var(--bg);
      padding: 4px 8px;
      border-radius: 4px;
      font-size: 0.75rem;
      word-break: break-all;
    }

    .export-section {
      margin-top: 20px;
      display: flex;
      gap: 10px;
    }

    .export-btn {
      padding: 10px 20px;
      background: var(--primary);
      color: white;
      border: none;
      border-radius: 8px;
      cursor: pointer;
      font-size: 0.9rem;
    }

    .export-btn:hover {
      background: var(--primary-dark);
    }

    .vuln-summary {
      display: flex;
      gap: 20px;
      margin-bottom: 30px;
    }

    .vuln-stat {
      flex: 1;
      text-align: center;
      padding: 20px;
      border-radius: 12px;
      background: var(--card-bg);
    }

    .vuln-stat .count {
      display: block;
      font-size: 2rem;
      font-weight: 700;
    }

    .vuln-stat.affected .count { color: var(--danger); }
    .vuln-stat.fixed .count { color: var(--success); }
    .vuln-stat.not-affected .count { color: var(--text-muted); }

    .vulnerabilities-list {
      display: flex;
      flex-direction: column;
      gap: 15px;
    }

    .vuln-card {
      background: var(--card-bg);
      border-radius: 12px;
      padding: 20px;
      border-left: 4px solid var(--border);
    }

    .vuln-card.affected { border-left-color: var(--danger); }
    .vuln-card.fixed { border-left-color: var(--success); }

    .vuln-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 10px;
    }

    .vuln-id {
      font-weight: 700;
      font-size: 1.1rem;
    }

    .vuln-status {
      padding: 4px 12px;
      border-radius: 20px;
      font-size: 0.8rem;
      font-weight: 600;
      text-transform: uppercase;
    }

    .vuln-status.affected { background: #f8d7da; color: #721c24; }
    .vuln-status.fixed { background: #d4edda; color: #155724; }
    .vuln-status.not-affected { background: #e9ecef; color: #6c757d; }

    .vuln-description {
      color: var(--text-muted);
      margin-bottom: 15px;
    }

    .vuln-products, .vuln-action, .vuln-aliases {
      margin-top: 10px;
      font-size: 0.9rem;
    }

    .vuln-products code {
      background: var(--bg);
      padding: 2px 6px;
      border-radius: 4px;
    }

    .vuln-action {
      background: #fff3cd;
      padding: 10px;
      border-radius: 8px;
    }

    .compliance-list {
      display: flex;
      flex-direction: column;
      gap: 15px;
    }

    .compliance-item {
      background: var(--card-bg);
      border-radius: 12px;
      padding: 20px;
      border-left: 4px solid var(--border);
    }

    .compliance-item.compliant { border-left-color: var(--success); }
    .compliance-item.action-required { border-left-color: var(--warning); }
    .compliance-item.non-compliant { border-left-color: var(--danger); }

    .compliance-header {
      display: flex;
      align-items: flex-start;
      gap: 15px;
    }

    .compliance-icon {
      width: 40px;
      height: 40px;
      border-radius: 50%;
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 1.25rem;
      flex-shrink: 0;
    }

    .compliance-item.compliant .compliance-icon { background: #d4edda; color: var(--success); }
    .compliance-item.action-required .compliance-icon { background: #fff3cd; color: #856404; }
    .compliance-item.non-compliant .compliance-icon { background: #f8d7da; color: var(--danger); }

    .compliance-info {
      flex: 1;
    }

    .compliance-info h3 {
      font-size: 1rem;
      margin-bottom: 5px;
    }

    .compliance-info p {
      color: var(--text-muted);
      font-size: 0.9rem;
    }

    .compliance-status {
      padding: 4px 12px;
      border-radius: 20px;
      font-size: 0.8rem;
      font-weight: 600;
    }

    .compliance-status.compliant { background: #d4edda; color: #155724; }
    .compliance-status.action-required { background: #fff3cd; color: #856404; }
    .compliance-status.non-compliant { background: #f8d7da; color: #721c24; }

    .compliance-evidence, .compliance-recommendation {
      margin-top: 15px;
      padding-top: 15px;
      border-top: 1px solid var(--border);
      font-size: 0.9rem;
    }

    .compliance-recommendation {
      background: #fff3cd;
      padding: 15px;
      border-radius: 8px;
      border-top: none;
    }

    .empty-state {
      text-align: center;
      padding: 60px 20px;
    }

    .empty-icon {
      font-size: 4rem;
      color: var(--success);
      margin-bottom: 20px;
    }

    .disclaimer {
      background: var(--bg);
      border-left: 4px solid var(--primary);
    }

    .disclaimer h4 {
      margin-bottom: 10px;
    }

    .action-list {
      margin-left: 20px;
    }

    .action-list li {
      margin-bottom: 10px;
    }

    .sbom-meta {
      display: flex;
      gap: 20px;
    }

    .meta-item {
      color: var(--text-muted);
      font-size: 0.9rem;
    }

    /* Transitive Dependencies */
    .transitive-section {
      margin-top: 30px;
      background: var(--card-bg);
      border-radius: 12px;
      overflow: hidden;
      box-shadow: 0 1px 3px rgba(0,0,0,0.1);
    }

    .transitive-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 15px 20px;
      background: linear-gradient(90deg, #f8f9fa 0%, #e9ecef 100%);
      cursor: pointer;
      border-bottom: 1px solid var(--border);
    }

    .transitive-header:hover {
      background: linear-gradient(90deg, #e9ecef 0%, #dee2e6 100%);
    }

    .transitive-header h3 {
      font-size: 1rem;
      color: var(--text);
      margin: 0;
    }

    .transitive-toggle {
      padding: 4px 12px;
      background: var(--primary);
      color: white;
      border-radius: 20px;
      font-size: 0.8rem;
      font-weight: 500;
    }

    .transitive-list {
      padding: 15px;
      background: #fafafa;
    }

    .dep-type-badge {
      padding: 2px 8px;
      border-radius: 10px;
      font-size: 0.7rem;
      margin-left: 10px;
      font-weight: 500;
      text-transform: lowercase;
    }

    .dep-type-badge.direct {
      background: #0d6efd;
      color: white;
    }

    .dep-type-badge.transitive {
      background: #6c757d;
      color: white;
    }

    .dep-type-badge.sub-dep {
      background: #6f42c1;
      color: white;
    }

    .package-card.transitive {
      opacity: 0.9;
      border-left-width: 3px;
    }

    @media (max-width: 768px) {
      .sidebar {
        width: 100%;
        position: relative;
        height: auto;
      }
      .main-content {
        margin-left: 0;
      }
      .overview-grid {
        grid-template-columns: 1fr;
      }
    }
  </style>";
    }

    private string GetHtmlScripts(CraReport report)
    {
        var sbomJson = JsonSerializer.Serialize(report.Sbom, new JsonSerializerOptions { WriteIndented = true });
        var vexJson = JsonSerializer.Serialize(report.Vex, new JsonSerializerOptions { WriteIndented = true, PropertyNamingPolicy = JsonNamingPolicy.CamelCase });

        return $@"
<script>
const sbomData = {sbomJson};
const vexData = {vexJson};

function showSection(sectionId) {{
  document.querySelectorAll('.section').forEach(s => s.classList.remove('active'));
  document.querySelectorAll('.nav-links a').forEach(a => a.classList.remove('active'));
  document.getElementById(sectionId).classList.add('active');
  document.querySelector(`[data-section='${{sectionId}}']`).classList.add('active');
}}

function togglePackage(header) {{
  header.parentElement.classList.toggle('expanded');
}}

function filterPackages() {{
  const search = document.getElementById('package-search').value.toLowerCase();
  document.querySelectorAll('.package-card').forEach(card => {{
    const name = card.dataset.name;
    card.style.display = name.includes(search) ? '' : 'none';
  }});
}}

let currentFilter = 'all';
function filterByStatus(status) {{
  currentFilter = status;
  document.querySelectorAll('.filter-btn').forEach(btn => btn.classList.remove('active'));
  event.target.classList.add('active');

  document.querySelectorAll('.package-card').forEach(card => {{
    if (status === 'all' || card.dataset.status === status) {{
      card.style.display = '';
    }} else {{
      card.style.display = 'none';
    }}
  }});
}}

function filterSbom() {{
  const search = document.getElementById('sbom-search').value.toLowerCase();
  document.querySelectorAll('#sbom-table tbody tr').forEach(row => {{
    const name = row.dataset.name;
    row.style.display = name.includes(search) ? '' : 'none';
  }});
}}

function toggleTransitive() {{
  const list = document.getElementById('transitive-list');
  const toggle = document.getElementById('transitive-toggle');
  if (list.style.display === 'none') {{
    list.style.display = '';
    toggle.textContent = 'Hide';
  }} else {{
    list.style.display = 'none';
    toggle.textContent = 'Show';
  }}
}}

function navigateToPackage(packageId) {{
  const targetId = 'pkg-' + packageId;
  const target = document.getElementById(targetId);
  if (!target) {{
    // Package not found on page, open NuGet instead
    window.open('https://www.nuget.org/packages/' + encodeURIComponent(packageId), '_blank');
    return;
  }}

  // Show the packages section first
  showSection('packages');

  // If it's a transitive dependency, expand the transitive section
  if (target.classList.contains('transitive')) {{
    const list = document.getElementById('transitive-list');
    const toggle = document.getElementById('transitive-toggle');
    if (list.style.display === 'none') {{
      list.style.display = '';
      toggle.textContent = 'Hide';
    }}
  }}

  // Clear any search/filter that might be hiding the package
  const searchInput = document.getElementById('package-search');
  if (searchInput) {{
    searchInput.value = '';
    filterPackages();
  }}

  // Reset status filter to 'all'
  currentFilter = 'all';
  document.querySelectorAll('.filter-btn').forEach(btn => {{
    btn.classList.remove('active');
    if (btn.textContent.toLowerCase() === 'all') btn.classList.add('active');
  }});
  document.querySelectorAll('.package-card').forEach(card => card.style.display = '');

  // Expand the package card
  target.classList.add('expanded');

  // Scroll to the element with a small offset for the header
  setTimeout(() => {{
    target.scrollIntoView({{ behavior: 'smooth', block: 'center' }});
    // Add a highlight effect
    target.classList.add('highlight');
    setTimeout(() => target.classList.remove('highlight'), 2000);
  }}, 100);
}}

function exportSbom(format) {{
  let data, filename, type;
  if (format === 'spdx') {{
    data = JSON.stringify(sbomData, null, 2);
    filename = 'sbom.spdx.json';
    type = 'application/json';
  }} else {{
    // Convert to CycloneDX format
    data = JSON.stringify(sbomData, null, 2);
    filename = 'sbom.cyclonedx.json';
    type = 'application/json';
  }}

  const blob = new Blob([data], {{ type }});
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}}
</script>";
    }

    private List<PackageHealth>? _healthDataCache;
    private List<PackageHealth>? _transitiveDataCache;
    private bool _hasIncompleteTransitive;
    private bool _hasUnresolvedVersions;

    /// <summary>
    /// Set package health data for detailed report generation.
    /// </summary>
    public void SetHealthData(IEnumerable<PackageHealth> packages)
    {
        _healthDataCache = packages.ToList();
    }

    /// <summary>
    /// Set transitive dependency health data for detailed report generation.
    /// </summary>
    public void SetTransitiveData(IEnumerable<PackageHealth> packages)
    {
        _transitiveDataCache = packages.ToList();
    }

    /// <summary>
    /// Set SBOM completeness warnings.
    /// </summary>
    public void SetCompletenessWarnings(bool incompleteTransitive, bool unresolvedVersions)
    {
        _hasIncompleteTransitive = incompleteTransitive;
        _hasUnresolvedVersions = unresolvedVersions;
    }

    private static string GetScoreClass(int score) => score switch
    {
        >= 80 => "healthy",
        >= 60 => "watch",
        >= 40 => "warning",
        _ => "critical"
    };

    private static string FormatNumber(long number) => number switch
    {
        >= 1_000_000_000 => $"{number / 1_000_000_000.0:F1}B",
        >= 1_000_000 => $"{number / 1_000_000.0:F1}M",
        >= 1_000 => $"{number / 1_000.0:F1}K",
        _ => number.ToString()
    };

    // Known SPDX license URLs
    private static readonly Dictionary<string, string> LicenseUrls = new(StringComparer.OrdinalIgnoreCase)
    {
        ["MIT"] = "https://opensource.org/licenses/MIT",
        ["Apache-2.0"] = "https://opensource.org/licenses/Apache-2.0",
        ["BSD-2-Clause"] = "https://opensource.org/licenses/BSD-2-Clause",
        ["BSD-3-Clause"] = "https://opensource.org/licenses/BSD-3-Clause",
        ["GPL-2.0"] = "https://opensource.org/licenses/GPL-2.0",
        ["GPL-3.0"] = "https://opensource.org/licenses/GPL-3.0",
        ["LGPL-2.1"] = "https://opensource.org/licenses/LGPL-2.1",
        ["LGPL-3.0"] = "https://opensource.org/licenses/LGPL-3.0",
        ["MPL-2.0"] = "https://opensource.org/licenses/MPL-2.0",
        ["ISC"] = "https://opensource.org/licenses/ISC",
        ["Unlicense"] = "https://unlicense.org/",
        ["CC0-1.0"] = "https://creativecommons.org/publicdomain/zero/1.0/",
        ["MS-PL"] = "https://opensource.org/licenses/MS-PL",
    };

    private static string FormatLicense(string? license)
    {
        if (string.IsNullOrEmpty(license))
            return "<span class=\"license-unknown\">Unknown</span>";

        // Handle NOASSERTION - SPDX term for unknown/unspecified license
        if (license.Equals("NOASSERTION", StringComparison.OrdinalIgnoreCase))
        {
            return "<span class=\"license-unknown\" title=\"License not specified in package metadata\">Not Specified</span>";
        }

        // Check for known SPDX licenses and add links
        if (LicenseUrls.TryGetValue(license, out var url))
        {
            return $"<a href=\"{url}\" target=\"_blank\" class=\"license-link\">{EscapeHtml(license)}</a>";
        }

        // If it's a URL, make it a clickable link with truncated display
        if (license.StartsWith("http://", StringComparison.OrdinalIgnoreCase) ||
            license.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
        {
            // Extract license name from URL if possible
            var displayName = "View License";
            try
            {
                var uri = new Uri(license);
                var segments = uri.Segments;
                if (segments.Length > 0)
                {
                    var lastSegment = segments[^1].TrimEnd('/');
                    if (!string.IsNullOrEmpty(lastSegment) &&
                        !lastSegment.Equals("license", StringComparison.OrdinalIgnoreCase) &&
                        !lastSegment.Equals("licenses", StringComparison.OrdinalIgnoreCase))
                    {
                        displayName = lastSegment;
                    }
                }
            }
            catch { /* Use default display name */ }

            return $"<a href=\"{EscapeHtml(license)}\" target=\"_blank\" title=\"{EscapeHtml(license)}\" class=\"license-link\">{EscapeHtml(displayName)}</a>";
        }

        // For other license identifiers, try to link to SPDX
        return $"<a href=\"https://spdx.org/licenses/{EscapeHtml(license)}.html\" target=\"_blank\" class=\"license-link\">{EscapeHtml(license)}</a>";
    }

    private static string FormatVersionForSbom(string? version)
    {
        if (string.IsNullOrEmpty(version))
            return "<span class=\"unresolved-version\">Unknown</span>";

        if (version.Contains("$("))
        {
            return $"<span class=\"unresolved-version\" title=\"MSBuild variable not resolved: {EscapeHtml(version)}\">Not resolved ⓘ</span>";
        }

        return EscapeHtml(version);
    }

    private static string FormatPurlForSbom(string? purl)
    {
        if (string.IsNullOrEmpty(purl))
            return "<span class=\"text-muted\">-</span>";

        if (purl.Contains("$("))
        {
            // Extract the package name from the purl and show a cleaner version
            var match = System.Text.RegularExpressions.Regex.Match(purl, @"pkg:nuget/([^@]+)");
            if (match.Success)
            {
                return $"<span class=\"unresolved-version\" title=\"Full PURL: {EscapeHtml(purl)}\">pkg:nuget/{EscapeHtml(match.Groups[1].Value)}@? ⓘ</span>";
            }
            return $"<span class=\"unresolved-version\" title=\"{EscapeHtml(purl)}\">Not resolved ⓘ</span>";
        }

        return EscapeHtml(purl);
    }

    private static string FormatDaysSinceRelease(int? days)
    {
        if (!days.HasValue)
            return "<span class=\"unknown-date\" title=\"Release date not available from NuGet API\">Unknown</span>";

        return $"{days.Value} days ago";
    }

    private static string FormatVersion(string? version, string packageId)
    {
        if (string.IsNullOrEmpty(version))
            return "<span class=\"unresolved-version\">Unknown</span>";

        // Check for unresolved MSBuild variable
        if (version.StartsWith("$(") || version.Contains("$("))
        {
            // Extract variable name for the tooltip
            var varName = version;
            var tooltip = $"Version uses MSBuild variable '{varName}' which wasn't resolved. Run 'dotnet restore' first, or ensure Directory.Build.props defines this variable.";
            return $"<span class=\"unresolved-version\" title=\"{EscapeHtml(tooltip)}\">Version not resolved <span class=\"version-hint\">ⓘ</span></span>";
        }

        return EscapeHtml(version);
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

    private static string EscapeJs(string input)
    {
        return input
            .Replace("\\", "\\\\")
            .Replace("'", "\\'")
            .Replace("\"", "\\\"")
            .Replace("\n", "\\n")
            .Replace("\r", "\\r");
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
