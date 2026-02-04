using System.Text;
using System.Text.Json;
using DepSafe.Models;

namespace DepSafe.Compliance;

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
    /// <param name="healthReport">The health report data.</param>
    /// <param name="vulnerabilities">Vulnerability data by package.</param>
    /// <param name="startTime">Optional start time for calculating generation duration.</param>
    public CraReport Generate(
        ProjectReport healthReport,
        IReadOnlyDictionary<string, List<VulnerabilityInfo>> vulnerabilities,
        DateTime? startTime = null)
    {
        // Build reverse dependency lookup for "Required by" information
        BuildParentLookup();

        // Build effective CRA scores (capped by worst dependency score)
        BuildEffectiveCraScores();

        // Include both direct and transitive packages in SBOM for CRA compliance
        var allPackagesForSbom = healthReport.Packages.AsEnumerable();
        if (_transitiveDataCache is not null)
        {
            allPackagesForSbom = allPackagesForSbom.Concat(_transitiveDataCache);
        }

        var sbom = _sbomGenerator.Generate(healthReport.ProjectPath, allPackagesForSbom);
        // VEX should include both direct and transitive packages for proper vulnerability counting
        var vex = _vexGenerator.Generate(allPackagesForSbom, vulnerabilities);

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

        // Vulnerability documentation - only count ACTIVE vulnerabilities (affecting current versions)
        var activeVulnCount = vex.Statements.Count(s => s.Status == VexStatus.Affected);
        var fixedVulnCount = vex.Statements.Count(s => s.Status == VexStatus.Fixed);
        var totalVulnStatements = vex.Statements.Count;
        complianceItems.Add(new CraComplianceItem
        {
            Requirement = "CRA Article 11 - Vulnerability Handling",
            Description = "Documentation of known vulnerabilities and their status",
            Status = activeVulnCount == 0 ? CraComplianceStatus.Compliant : CraComplianceStatus.ActionRequired,
            Evidence = activeVulnCount == 0
                ? $"No active vulnerabilities. {fixedVulnCount} vulnerabilities addressed in current versions."
                : $"{activeVulnCount} active vulnerabilities require attention. {fixedVulnCount} already addressed.",
            Recommendation = activeVulnCount > 0
                ? "Update affected packages to patched versions"
                : null
        });

        // Security Updates - CRA requires a mechanism for updates, not that packages be recently updated
        // Having an SBOM and VEX demonstrates capability to track and respond to security issues
        complianceItems.Add(new CraComplianceItem
        {
            Requirement = "CRA Article 10(6) - Security Updates",
            Description = "Mechanism to ensure timely security updates",
            Status = CraComplianceStatus.Compliant,
            Evidence = $"SBOM tracks {sbom.Packages.Count} components. VEX documents {totalVulnStatements} vulnerability assessments.",
            Recommendation = null
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

        // Collect dependency issues from all trees
        var versionConflictCount = _dependencyTrees.Sum(t => t.VersionConflictCount);
        var allDependencyIssues = _dependencyTrees.SelectMany(t => t.Issues).ToList();

        return new CraReport
        {
            GeneratedAt = DateTime.UtcNow,
            GenerationDuration = startTime.HasValue ? DateTime.UtcNow - startTime.Value : null,
            ProjectPath = healthReport.ProjectPath,
            HealthScore = healthReport.OverallScore,
            HealthStatus = healthReport.OverallStatus,
            ComplianceItems = complianceItems,
            OverallComplianceStatus = DetermineOverallStatus(complianceItems),
            Sbom = sbom,
            Vex = vex,
            PackageCount = healthReport.Packages.Count,
            TransitivePackageCount = _transitiveDataCache?.Count ?? 0,
            VulnerabilityCount = activeVulnCount,
            CriticalPackageCount = healthReport.Summary.CriticalCount,
            VersionConflictCount = versionConflictCount,
            DependencyIssues = allDependencyIssues
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
        sb.AppendLine("    <h2>DepSafe</h2>");
        sb.AppendLine("  </div>");
        sb.AppendLine("  <ul class=\"nav-links\">");
        sb.AppendLine("    <li><a href=\"#\" onclick=\"showSection('overview')\" class=\"active\" data-section=\"overview\">Overview</a></li>");
        sb.AppendLine("    <li><a href=\"#\" onclick=\"showSection('packages')\" data-section=\"packages\">Packages</a></li>");
        sb.AppendLine("    <li><a href=\"#\" onclick=\"showSection('licenses')\" data-section=\"licenses\">Licenses</a></li>");
        sb.AppendLine("    <li><a href=\"#\" onclick=\"showSection('sbom')\" data-section=\"sbom\">SBOM</a></li>");
        sb.AppendLine("    <li><a href=\"#\" onclick=\"showSection('vulnerabilities')\" data-section=\"vulnerabilities\">Vulnerabilities</a></li>");
        sb.AppendLine("    <li><a href=\"#\" onclick=\"showSection('tree')\" data-section=\"tree\">Dependency Tree</a></li>");
        sb.AppendLine("    <li><a href=\"#\" onclick=\"showSection('issues')\" data-section=\"issues\">Dependency Issues</a></li>");
        sb.AppendLine("    <li><a href=\"#\" onclick=\"showSection('compliance')\" data-section=\"compliance\">Compliance</a></li>");
        sb.AppendLine("  </ul>");
        sb.AppendLine("</nav>");

        // Main Content
        sb.AppendLine("<main class=\"main-content\">");

        // Header
        sb.AppendLine("<header class=\"header\">");
        sb.AppendLine($"  <h1>{EscapeHtml(Path.GetFileName(report.ProjectPath))}</h1>");
        var durationText = report.GenerationDuration.HasValue
            ? $" in {FormatDuration(report.GenerationDuration.Value)}"
            : "";
        sb.AppendLine($"  <p class=\"subtitle\">Generated {report.GeneratedAt:MMMM dd, yyyy 'at' HH:mm} UTC{durationText}</p>");
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

        // Dependency Tree Section
        sb.AppendLine("<section id=\"tree\" class=\"section\">");
        GenerateDependencyTreeSection(sb);
        sb.AppendLine("</section>");

        // Dependency Issues Section
        sb.AppendLine("<section id=\"issues\" class=\"section\">");
        GenerateDependencyIssuesSection(sb, report);
        sb.AppendLine("</section>");

        // Compliance Section
        sb.AppendLine("<section id=\"compliance\" class=\"section\">");
        GenerateComplianceSection(sb, report);
        sb.AppendLine("</section>");

        sb.AppendLine("</main>");

        // Footer with disclaimer - visible on all views
        sb.AppendLine("<footer class=\"disclaimer-footer\">");
        sb.AppendLine("  <p>This report assists with EU Cyber Resilience Act compliance assessment. It is not legal advice. Consult legal counsel for authoritative compliance guidance.</p>");
        sb.AppendLine("</footer>");

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

        // CRA Compliance Score Card - based purely on regulatory requirements
        var craScore = CalculateProjectCraScore(_healthDataCache ?? [], _transitiveDataCache ?? [], report.VulnerabilityCount);
        var craScoreClass = GetCraScoreClass(craScore);
        sb.AppendLine("  <div class=\"card score-card\">");
        sb.AppendLine("    <h3>CRA Score</h3>");
        sb.AppendLine($"    <div class=\"score-gauge {craScoreClass}\">");
        sb.AppendLine($"      <svg viewBox=\"0 0 100 50\">");
        sb.AppendLine($"        <path class=\"gauge-bg\" d=\"M 10 50 A 40 40 0 0 1 90 50\" />");
        var craAngle = 180 * (craScore / 100.0);
        sb.AppendLine($"        <path class=\"gauge-fill\" d=\"M 10 50 A 40 40 0 0 1 90 50\" style=\"stroke-dasharray: {craAngle * 1.26}, 226\" />");
        sb.AppendLine($"      </svg>");
        sb.AppendLine($"      <div class=\"score-value\">{craScore}</div>");
        sb.AppendLine("    </div>");
        sb.AppendLine($"    <div class=\"score-label {craScoreClass}\">Vulnerabilities + Licenses</div>");
        sb.AppendLine("  </div>");

        // Health Score Card - based on freshness, activity, popularity
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
        sb.AppendLine($"    <div class=\"score-label {GetScoreClass(report.HealthScore)}\">Freshness + Activity</div>");
        sb.AppendLine("  </div>");

        // Compliance Status Card
        sb.AppendLine($"  <div class=\"card status-card {statusClass}\">");
        sb.AppendLine("    <h3>CRA Compliance</h3>");
        sb.AppendLine($"    <div class=\"big-status\">{report.OverallComplianceStatus}</div>");
        var compliantCount = report.ComplianceItems.Count(i => i.Status == CraComplianceStatus.Compliant);
        sb.AppendLine($"    <div class=\"status-detail\">{compliantCount}/{report.ComplianceItems.Count} requirements met</div>");
        sb.AppendLine("  </div>");

        // Summary Cards
        var totalPackages = report.PackageCount + report.TransitivePackageCount;
        sb.AppendLine("  <div class=\"card metric-card\">");
        sb.AppendLine($"    <div class=\"metric-value\">{totalPackages}</div>");
        sb.AppendLine($"    <div class=\"metric-label\">Total Packages</div>");
        sb.AppendLine($"    <div class=\"metric-detail\">{report.PackageCount} direct + {report.TransitivePackageCount} transitive</div>");
        sb.AppendLine("  </div>");

        sb.AppendLine("  <div class=\"card metric-card\">");
        sb.AppendLine($"    <div class=\"metric-value {(report.VulnerabilityCount > 0 ? "critical" : "")}\">{report.VulnerabilityCount}</div>");
        sb.AppendLine("    <div class=\"metric-label\">Vulnerabilities</div>");
        sb.AppendLine("  </div>");

        sb.AppendLine("  <div class=\"card metric-card\">");
        sb.AppendLine($"    <div class=\"metric-value {(report.CriticalPackageCount > 0 ? "critical" : "")}\">{report.CriticalPackageCount}</div>");
        sb.AppendLine("    <div class=\"metric-label\">Critical Packages</div>");
        sb.AppendLine("  </div>");

        sb.AppendLine("  <div class=\"card metric-card\">");
        sb.AppendLine($"    <div class=\"metric-value {(report.VersionConflictCount > 0 ? "warning" : "")}\">{report.VersionConflictCount}</div>");
        sb.AppendLine("    <div class=\"metric-label\">Version Conflicts</div>");
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
        sb.AppendLine("  <span class=\"filter-group\">");
        sb.AppendLine("    <span class=\"filter-label\">Status:</span>");
        sb.AppendLine("    <button class=\"filter-btn active\" onclick=\"filterByStatus('all')\">All</button>");
        sb.AppendLine("    <button class=\"filter-btn healthy\" onclick=\"filterByStatus('healthy')\">Healthy</button>");
        sb.AppendLine("    <button class=\"filter-btn watch\" onclick=\"filterByStatus('watch')\">Watch</button>");
        sb.AppendLine("    <button class=\"filter-btn warning\" onclick=\"filterByStatus('warning')\">Warning</button>");
        sb.AppendLine("    <button class=\"filter-btn critical\" onclick=\"filterByStatus('critical')\">Critical</button>");
        sb.AppendLine("  </span>");
        sb.AppendLine("  <span class=\"filter-group\">");
        sb.AppendLine("    <span class=\"filter-label\">Ecosystem:</span>");
        sb.AppendLine("    <button class=\"filter-btn ecosystem-btn active\" onclick=\"filterByEcosystem('all')\">All</button>");
        sb.AppendLine("    <button class=\"filter-btn ecosystem-btn nuget\" onclick=\"filterByEcosystem('nuget')\">NuGet</button>");
        sb.AppendLine("    <button class=\"filter-btn ecosystem-btn npm\" onclick=\"filterByEcosystem('npm')\">npm</button>");
        sb.AppendLine("  </span>");
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

        // Build set of direct package IDs for filtering
        var directPackageIds = new HashSet<string>(
            _healthDataCache?.Select(h => h.PackageId) ?? [],
            StringComparer.OrdinalIgnoreCase);

        // Only render direct packages here (transitives are shown in separate section)
        foreach (var pkg in report.Sbom.Packages.Skip(1).Where(p => directPackageIds.Contains(p.Name)))
        {
            var pkgName = pkg.Name;
            var version = pkg.VersionInfo;
            var score = 70; // Default score
            var status = "watch";

            // Find matching health data
            var healthData = _healthDataCache?.FirstOrDefault(h => h.PackageId == pkgName);
            var ecosystemAttr = "nuget"; // Default for data attribute
            if (healthData != null)
            {
                score = healthData.Score;
                status = healthData.Status.ToString().ToLowerInvariant();
                ecosystemAttr = healthData.Ecosystem == PackageEcosystem.Npm ? "npm" : "nuget";
            }

            var craScore = healthData?.CraScore ?? 100;
            sb.AppendLine($"  <div class=\"package-card\" id=\"pkg-{EscapeHtml(pkgName)}\" data-status=\"{status}\" data-name=\"{EscapeHtml(pkgName.ToLowerInvariant())}\" data-ecosystem=\"{ecosystemAttr}\">");
            sb.AppendLine("    <div class=\"package-header\" onclick=\"togglePackage(this)\">");
            sb.AppendLine($"      <div class=\"package-info\">");
            sb.AppendLine($"        <span class=\"package-name\">{EscapeHtml(pkgName)}</span>");
            sb.AppendLine($"        <span class=\"package-version\">{FormatVersion(version, pkgName)}</span>");
            sb.AppendLine($"        <span class=\"dep-type-badge direct\" title=\"Direct dependency - referenced in your project file\">direct</span>");
            sb.AppendLine($"      </div>");
            sb.AppendLine($"      <div class=\"package-scores\">");
            sb.AppendLine($"        <div class=\"package-score-item\" title=\"CRA Compliance Score - vulnerabilities &amp; licenses\">");
            sb.AppendLine($"          <span class=\"score-label\">CRA</span>");
            sb.AppendLine($"          <span class=\"score-circle\" style=\"{GetScoreStyle(craScore)}\">{craScore}</span>");
            sb.AppendLine($"        </div>");
            sb.AppendLine($"        <div class=\"package-score-item\" title=\"Health Score - freshness &amp; activity\">");
            sb.AppendLine($"          <span class=\"score-label\">Health</span>");
            sb.AppendLine($"          <span class=\"score-circle\" style=\"{GetScoreStyle(score)}\">{score}</span>");
            sb.AppendLine($"        </div>");
            sb.AppendLine($"      </div>");
            sb.AppendLine($"      <span class=\"expand-icon\">+</span>");
            sb.AppendLine("    </div>");
            sb.AppendLine("    <div class=\"package-details\">");

            if (healthData != null)
            {
                sb.AppendLine("      <div class=\"detail-grid\">");
                sb.AppendLine($"        <div class=\"detail-item\"><span class=\"label\">License</span><span class=\"value\">{FormatLicense(healthData.License)}</span></div>");
                sb.AppendLine($"        <div class=\"detail-item\"><span class=\"label\">Last Release</span><span class=\"value\">{FormatDaysSinceRelease(healthData.Metrics.DaysSinceLastRelease)}</span></div>");
                sb.AppendLine($"        <div class=\"detail-item\"><span class=\"label\">Releases/Year</span><span class=\"value\">{healthData.Metrics.ReleasesPerYear:F1}</span></div>");
                sb.AppendLine($"        <div class=\"detail-item\"><span class=\"label\">Downloads</span><span class=\"value\">{FormatDownloads(healthData.Metrics.TotalDownloads)}</span></div>");
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

            var ecosystem = healthData?.Ecosystem ?? pkg.Ecosystem;
            var registryUrl = ecosystem == PackageEcosystem.Npm
                ? $"https://www.npmjs.com/package/{Uri.EscapeDataString(pkgName)}/v/{Uri.EscapeDataString(version)}"
                : $"https://www.nuget.org/packages/{EscapeHtml(pkgName)}/{EscapeHtml(version)}";
            var registryName = ecosystem == PackageEcosystem.Npm ? "npm" : "NuGet";

            sb.AppendLine($"      <div class=\"package-links\">");
            sb.AppendLine($"        <a href=\"{registryUrl}\" target=\"_blank\">{registryName}</a>");
            if (!string.IsNullOrEmpty(healthData?.RepositoryUrl))
                sb.AppendLine($"        <a href=\"{EscapeHtml(healthData.RepositoryUrl)}\" target=\"_blank\">Repository</a>");
            sb.AppendLine($"      </div>");
            sb.AppendLine("    </div>");
            sb.AppendLine("  </div>");
        }

        sb.AppendLine("</div>");

        // Transitive Dependencies Section (exclude sub-dependencies - they're only for tree navigation)
        var actualTransitives = _transitiveDataCache?.Where(h => h.DependencyType != DependencyType.SubDependency).ToList() ?? [];
        if (actualTransitives.Count > 0)
        {
            sb.AppendLine("<div class=\"transitive-section\">");
            sb.AppendLine("  <div class=\"transitive-header\" onclick=\"toggleTransitive()\">");
            sb.AppendLine($"    <h3>Transitive Dependencies ({actualTransitives.Count})</h3>");
            sb.AppendLine("    <span class=\"transitive-toggle\" id=\"transitive-toggle\">Show</span>");
            sb.AppendLine("  </div>");
            sb.AppendLine("  <div id=\"transitive-list\" class=\"packages-list transitive-list\" style=\"display: none;\">");

            foreach (var healthData in actualTransitives.OrderBy(h => h.Score))
            {
                var pkgName = healthData.PackageId;
                var version = healthData.Version;
                var score = healthData.Score;
                var status = healthData.Status.ToString().ToLowerInvariant();

                var ecosystemName = healthData.Ecosystem == PackageEcosystem.Npm ? "npm" : "NuGet";
                var depTypeBadge = $"<span class=\"dep-type-badge transitive\" title=\"Transitive dependency - pulled in by {ecosystemName} dependency resolution\">transitive</span>";

                var craScore = healthData.CraScore;
                var ecosystemAttr = healthData.Ecosystem == PackageEcosystem.Npm ? "npm" : "nuget";

                // Check if we have real health data (not just defaults)
                var hasRealHealthData = healthData.Metrics.TotalDownloads > 0 ||
                                        healthData.Metrics.DaysSinceLastRelease.HasValue ||
                                        healthData.Metrics.ReleasesPerYear > 0;

                sb.AppendLine($"  <div class=\"package-card transitive\" id=\"pkg-{EscapeHtml(pkgName)}\" data-status=\"{status}\" data-name=\"{EscapeHtml(pkgName.ToLowerInvariant())}\" data-ecosystem=\"{ecosystemAttr}\">");
                sb.AppendLine("    <div class=\"package-header\" onclick=\"togglePackage(this)\">");
                sb.AppendLine($"      <div class=\"package-info\">");
                sb.AppendLine($"        <span class=\"package-name\">{EscapeHtml(pkgName)}</span>");
                sb.AppendLine($"        <span class=\"package-version\">{FormatVersion(version, pkgName)}</span>");
                sb.AppendLine($"        {depTypeBadge}");
                sb.AppendLine($"      </div>");
                sb.AppendLine($"      <div class=\"package-scores\">");
                if (hasRealHealthData)
                {
                    sb.AppendLine($"        <div class=\"package-score-item\" title=\"Health Score - freshness &amp; activity\">");
                    sb.AppendLine($"          <span class=\"score-label\">HEALTH</span>");
                    sb.AppendLine($"          <span class=\"score-circle\" style=\"{GetScoreStyle(score)}\">{score}</span>");
                    sb.AppendLine($"        </div>");
                }
                else
                {
                    sb.AppendLine($"        <div class=\"package-score-item\" title=\"Health Score not available - use --deep for full analysis\">");
                    sb.AppendLine($"          <span class=\"score-label\">HEALTH</span>");
                    sb.AppendLine($"          <span class=\"score-circle na\">—</span>");
                    sb.AppendLine($"        </div>");
                }
                sb.AppendLine($"        <div class=\"package-score-item\" title=\"CRA Compliance Score - vulnerabilities &amp; licenses\">");
                sb.AppendLine($"          <span class=\"score-label\">CRA</span>");
                sb.AppendLine($"          <span class=\"score-circle\" style=\"{GetScoreStyle(craScore)}\">{craScore}</span>");
                sb.AppendLine($"        </div>");
                sb.AppendLine($"      </div>");
                sb.AppendLine($"      <span class=\"expand-icon\">+</span>");
                sb.AppendLine("    </div>");
                sb.AppendLine("    <div class=\"package-details\">");

                // Check if we have actual metrics data (not just empty defaults from tree extraction)
                var hasMetrics = healthData.Metrics.TotalDownloads > 0 ||
                                 healthData.Metrics.DaysSinceLastRelease.HasValue ||
                                 healthData.Metrics.ReleasesPerYear > 0;

                sb.AppendLine("      <div class=\"detail-grid\">");
                sb.AppendLine($"        <div class=\"detail-item\"><span class=\"label\">License</span><span class=\"value\">{FormatLicense(healthData.License)}</span></div>");
                if (hasMetrics)
                {
                    sb.AppendLine($"        <div class=\"detail-item\"><span class=\"label\">Last Release</span><span class=\"value\">{FormatDaysSinceRelease(healthData.Metrics.DaysSinceLastRelease)}</span></div>");
                    sb.AppendLine($"        <div class=\"detail-item\"><span class=\"label\">Releases/Year</span><span class=\"value\">{healthData.Metrics.ReleasesPerYear:F1}</span></div>");
                    sb.AppendLine($"        <div class=\"detail-item\"><span class=\"label\">Downloads</span><span class=\"value\">{FormatDownloads(healthData.Metrics.TotalDownloads)}</span></div>");
                    if (healthData.Metrics.Stars.HasValue)
                        sb.AppendLine($"        <div class=\"detail-item\"><span class=\"label\">GitHub Stars</span><span class=\"value\">{FormatNumber(healthData.Metrics.Stars.Value)}</span></div>");
                    if (healthData.Metrics.DaysSinceLastCommit.HasValue)
                        sb.AppendLine($"        <div class=\"detail-item\"><span class=\"label\">Last Commit</span><span class=\"value\">{healthData.Metrics.DaysSinceLastCommit} days ago</span></div>");
                }
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

                // Show "Required by" - which packages depend on this transitive package
                if (_parentLookup.TryGetValue(pkgName, out var parents) && parents.Count > 0)
                {
                    sb.AppendLine("      <div class=\"required-by\">");
                    sb.AppendLine("        <span class=\"required-by-label\">Required by:</span>");
                    sb.AppendLine("        <div class=\"parent-packages\">");
                    foreach (var parentId in parents.Take(5)) // Limit to 5 parents
                    {
                        // Check if parent is a direct dependency
                        var isDirect = _healthDataCache?.Any(p => p.PackageId.Equals(parentId, StringComparison.OrdinalIgnoreCase)) == true;
                        var badgeClass = isDirect ? "parent-badge direct" : "parent-badge";
                        sb.AppendLine($"          <a href=\"#\" class=\"{badgeClass}\" onclick=\"navigateToPackage('{EscapeHtml(parentId.ToLowerInvariant())}'); return false;\" title=\"{(isDirect ? "Direct dependency" : "Transitive dependency")}\">{EscapeHtml(parentId)}</a>");
                    }
                    if (parents.Count > 5)
                    {
                        sb.AppendLine($"          <span class=\"more-parents\">+{parents.Count - 5} more</span>");
                    }
                    sb.AppendLine("        </div>");
                    sb.AppendLine("      </div>");
                }

                var registryUrl = healthData.Ecosystem == PackageEcosystem.Npm
                    ? $"https://www.npmjs.com/package/{Uri.EscapeDataString(pkgName)}/v/{Uri.EscapeDataString(version)}"
                    : $"https://www.nuget.org/packages/{EscapeHtml(pkgName)}/{EscapeHtml(version)}";

                sb.AppendLine($"      <div class=\"package-links\">");
                sb.AppendLine($"        <a href=\"{registryUrl}\" target=\"_blank\">{ecosystemName}</a>");
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

            var registryName = pkg.Ecosystem == PackageEcosystem.Npm ? "npm" : "NuGet";
            sb.AppendLine($"    <tr data-name=\"{EscapeHtml(pkg.Name.ToLowerInvariant())}\">");
            sb.AppendLine($"      <td class=\"component-name\">");
            sb.AppendLine($"        <strong>{EscapeHtml(pkg.Name)}</strong>");
            sb.AppendLine($"        <a href=\"{EscapeHtml(pkg.DownloadLocation)}\" target=\"_blank\" class=\"external-link\">View on {registryName}</a>");
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

        // License distribution chart (stacked horizontal bar)
        sb.AppendLine("<div class=\"license-distribution\">");
        sb.AppendLine("  <h3>License Distribution</h3>");

        var total = licenseReport.CategoryDistribution.Values.Sum();
        if (total > 0)
        {
            // Stacked bar
            sb.AppendLine("  <div class=\"distribution-stacked-bar\">");
            foreach (var (category, count) in licenseReport.CategoryDistribution.OrderByDescending(x => x.Value))
            {
                if (count == 0) continue;
                var percent = (count * 100.0) / total;
                var categoryClass = category switch
                {
                    LicenseCompatibility.LicenseCategory.Permissive => "permissive",
                    LicenseCompatibility.LicenseCategory.WeakCopyleft => "weak-copyleft",
                    LicenseCompatibility.LicenseCategory.StrongCopyleft => "strong-copyleft",
                    LicenseCompatibility.LicenseCategory.PublicDomain => "public-domain",
                    _ => "unknown"
                };
                // Only show label if segment is wide enough (>10%)
                var label = percent >= 10 ? $"<span class=\"segment-label\">{category}</span>" : "";
                sb.AppendLine($"    <div class=\"bar-segment {categoryClass}\" style=\"width: {percent:F1}%\" title=\"{category}: {count} packages ({percent:F1}%)\">{label}</div>");
            }
            sb.AppendLine("  </div>");

            // Legend below the bar
            sb.AppendLine("  <div class=\"distribution-legend\">");
            foreach (var (category, count) in licenseReport.CategoryDistribution.OrderByDescending(x => x.Value))
            {
                if (count == 0) continue;
                var percent = (count * 100.0) / total;
                var categoryClass = category switch
                {
                    LicenseCompatibility.LicenseCategory.Permissive => "permissive",
                    LicenseCompatibility.LicenseCategory.WeakCopyleft => "weak-copyleft",
                    LicenseCompatibility.LicenseCategory.StrongCopyleft => "strong-copyleft",
                    LicenseCompatibility.LicenseCategory.PublicDomain => "public-domain",
                    _ => "unknown"
                };
                sb.AppendLine($"    <div class=\"legend-item\">");
                sb.AppendLine($"      <span class=\"legend-color {categoryClass}\"></span>");
                sb.AppendLine($"      <span class=\"legend-label\">{category}</span>");
                sb.AppendLine($"      <span class=\"legend-count\">{count}</span>");
                sb.AppendLine($"      <span class=\"legend-percent\">({percent:F1}%)</span>");
                sb.AppendLine($"    </div>");
            }
            sb.AppendLine("  </div>");
        }
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
        var affectedStatements = statements.Where(s => s.Status == VexStatus.Affected).ToList();
        var safeStatements = statements.Where(s => s.Status != VexStatus.Affected).ToList();

        // Summary: focus on what needs action
        if (affectedStatements.Count == 0)
        {
            sb.AppendLine("<div class=\"card empty-state success\">");
            sb.AppendLine("  <div class=\"empty-icon\">&#10003;</div>");
            sb.AppendLine("  <h3>No Vulnerabilities Requiring Action</h3>");
            if (safeStatements.Count > 0)
            {
                sb.AppendLine($"  <p>{safeStatements.Count} vulnerabilities were checked - your package versions are safe.</p>");
            }
            else
            {
                sb.AppendLine("  <p>No known vulnerabilities found in your packages.</p>");
            }
            sb.AppendLine("</div>");

            // Show reviewed items in collapsible section for audit
            if (safeStatements.Count > 0)
            {
                sb.AppendLine("<div class=\"reviewed-vulns-section\">");
                sb.AppendLine("  <div class=\"reviewed-header\" onclick=\"toggleReviewedVulns()\">");
                sb.AppendLine($"    <span>Show {safeStatements.Count} reviewed vulnerabilities (for audit)</span>");
                sb.AppendLine("    <span id=\"reviewed-toggle\">+</span>");
                sb.AppendLine("  </div>");
                sb.AppendLine("  <div id=\"reviewed-vulns-list\" class=\"vulnerabilities-list\" style=\"display:none;\">");
                foreach (var stmt in safeStatements)
                {
                    GenerateVulnerabilityCard(sb, stmt);
                }
                sb.AppendLine("  </div>");
                sb.AppendLine("</div>");
            }
            return;
        }

        // Show count of vulnerabilities needing action
        sb.AppendLine("<div class=\"vuln-alert\">");
        sb.AppendLine($"  <span class=\"vuln-alert-icon\">&#9888;</span>");
        sb.AppendLine($"  <span class=\"vuln-alert-text\"><strong>{affectedStatements.Count}</strong> vulnerabilit{(affectedStatements.Count == 1 ? "y requires" : "ies require")} action</span>");
        if (safeStatements.Count > 0)
        {
            sb.AppendLine($"  <span class=\"vuln-safe-note\">({safeStatements.Count} others checked and safe)</span>");
        }
        sb.AppendLine("</div>");

        // Show affected vulnerabilities
        sb.AppendLine("<div class=\"vulnerabilities-list\">");
        foreach (var stmt in affectedStatements)
        {
            GenerateVulnerabilityCard(sb, stmt);
        }
        sb.AppendLine("</div>");

        // Show reviewed items in collapsible section
        if (safeStatements.Count > 0)
        {
            sb.AppendLine("<div class=\"reviewed-vulns-section\">");
            sb.AppendLine("  <div class=\"reviewed-header\" onclick=\"toggleReviewedVulns()\">");
            sb.AppendLine($"    <span>Show {safeStatements.Count} reviewed vulnerabilities (safe)</span>");
            sb.AppendLine("    <span id=\"reviewed-toggle\">+</span>");
            sb.AppendLine("  </div>");
            sb.AppendLine("  <div id=\"reviewed-vulns-list\" class=\"vulnerabilities-list\" style=\"display:none;\">");
            foreach (var stmt in safeStatements)
            {
                GenerateVulnerabilityCard(sb, stmt);
            }
            sb.AppendLine("  </div>");
            sb.AppendLine("</div>");
        }
    }

    private void GenerateVulnerabilityCard(StringBuilder sb, VexStatement stmt)
    {
        var statusClass = stmt.Status switch
        {
            VexStatus.Affected => "affected",
            VexStatus.Fixed => "fixed",
            _ => "not-affected"
        };

        var statusLabel = stmt.Status switch
        {
            VexStatus.Affected => "ACTION REQUIRED",
            VexStatus.Fixed => "PATCHED",
            _ => "NOT APPLICABLE"
        };

        sb.AppendLine($"  <div class=\"vuln-card {statusClass}\">");
        sb.AppendLine("    <div class=\"vuln-header\">");
        sb.AppendLine($"      <a href=\"{EscapeHtml(stmt.Vulnerability.Id)}\" target=\"_blank\" class=\"vuln-id\">{EscapeHtml(stmt.Vulnerability.Name)}</a>");
        sb.AppendLine($"      <span class=\"vuln-status {statusClass}\">{statusLabel}</span>");
        sb.AppendLine("    </div>");

        var description = !string.IsNullOrWhiteSpace(stmt.Vulnerability.Description)
            ? stmt.Vulnerability.Description
            : "No description available. Click the vulnerability ID above for details.";
        sb.AppendLine($"    <p class=\"vuln-description\">{EscapeHtml(description)}</p>");

        sb.AppendLine("    <div class=\"vuln-products\">");
        foreach (var product in stmt.Products)
        {
            sb.AppendLine($"      <div class=\"vuln-package-info\">");
            sb.AppendLine($"        <strong>Package:</strong> <code>{EscapeHtml(product.Identifiers.Purl)}</code>");
            if (stmt.Status == VexStatus.Fixed)
            {
                sb.AppendLine($"        <span class=\"vuln-patched-note\">&#10003; Your version includes the fix</span>");
            }
            else if (stmt.Status == VexStatus.Affected)
            {
                sb.AppendLine($"        <span class=\"vuln-affected-note\">&#9888; Your version is vulnerable</span>");
                if (!string.IsNullOrEmpty(stmt.PatchedVersion))
                {
                    sb.AppendLine($"        <span class=\"vuln-fixed-in\">Fixed in {EscapeHtml(stmt.PatchedVersion)}</span>");
                }
            }
            sb.AppendLine($"      </div>");
        }
        sb.AppendLine("    </div>");

        if (!string.IsNullOrEmpty(stmt.ActionStatement) && stmt.Status == VexStatus.Affected)
        {
            sb.AppendLine($"    <div class=\"vuln-action\"><strong>Recommended Action:</strong> {EscapeHtml(stmt.ActionStatement)}</div>");
        }
        if (stmt.Vulnerability.Aliases?.Count > 0)
        {
            sb.AppendLine($"    <div class=\"vuln-aliases\"><strong>CVEs:</strong> {string.Join(", ", stmt.Vulnerability.Aliases.Select(EscapeHtml))}</div>");
        }
        sb.AppendLine("  </div>");
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
    }

    private void GenerateDependencyTreeSection(StringBuilder sb)
    {
        sb.AppendLine("<div class=\"section-header\">");
        sb.AppendLine("  <h2>Dependency Tree</h2>");
        sb.AppendLine("</div>");

        if (_dependencyTrees.Count == 0 || _dependencyTrees.All(t => t.Roots.Count == 0))
        {
            sb.AppendLine("<div class=\"card empty-state\">");
            sb.AppendLine("  <div class=\"empty-icon\">&#128230;</div>");
            sb.AppendLine("  <h3>No Dependency Tree Available</h3>");
            sb.AppendLine("  <p>Dependency tree data was not generated for this report.</p>");
            sb.AppendLine("</div>");
            return;
        }

        // Overall stats
        var totalPackages = _dependencyTrees.Sum(t => t.TotalPackages);
        var maxDepth = _dependencyTrees.Max(t => t.MaxDepth);
        var vulnerableCount = _dependencyTrees.Sum(t => t.VulnerableCount);

        sb.AppendLine("<div class=\"tree-stats\">");
        sb.AppendLine($"  <span class=\"tree-stat\"><strong>Total Packages:</strong> {totalPackages}</span>");
        sb.AppendLine($"  <span class=\"tree-stat\"><strong>Max Depth:</strong> {maxDepth}</span>");
        if (vulnerableCount > 0)
        {
            sb.AppendLine($"  <span class=\"tree-stat vulnerable\"><strong>Vulnerable:</strong> {vulnerableCount}</span>");
        }
        if (_dependencyTrees.Count > 1)
        {
            sb.AppendLine($"  <span class=\"tree-stat\"><strong>Ecosystems:</strong> {string.Join(", ", _dependencyTrees.Select(t => t.ProjectType))}</span>");
        }
        else
        {
            sb.AppendLine($"  <span class=\"tree-stat\"><strong>Type:</strong> {_dependencyTrees[0].ProjectType}</span>");
        }
        sb.AppendLine("</div>");

        // Tree controls
        sb.AppendLine("<div class=\"tree-controls\">");
        sb.AppendLine("  <button class=\"tree-btn\" onclick=\"expandAllTree()\">Expand All</button>");
        sb.AppendLine("  <button class=\"tree-btn\" onclick=\"collapseAllTree()\">Collapse All</button>");
        sb.AppendLine("  <input type=\"text\" id=\"tree-search\" class=\"search-input\" placeholder=\"Search packages...\" onkeyup=\"filterTree()\">");
        if (_dependencyTrees.Count > 1)
        {
            sb.AppendLine("  <span class=\"filter-group tree-ecosystem-filter\">");
            sb.AppendLine("    <span class=\"filter-label\">Ecosystem:</span>");
            sb.AppendLine("    <button class=\"filter-btn ecosystem-btn active\" onclick=\"filterTreeByEcosystem('all')\">All</button>");
            sb.AppendLine("    <button class=\"filter-btn ecosystem-btn nuget\" onclick=\"filterTreeByEcosystem('nuget')\">NuGet</button>");
            sb.AppendLine("    <button class=\"filter-btn ecosystem-btn npm\" onclick=\"filterTreeByEcosystem('npm')\">npm</button>");
            sb.AppendLine("  </span>");
        }
        sb.AppendLine("</div>");

        // Generate tree for each ecosystem
        foreach (var tree in _dependencyTrees)
        {
            if (tree.Roots.Count == 0) continue;

            var ecosystemValue = tree.ProjectType == ProjectType.Npm ? "npm" : "nuget";

            // Ecosystem header (only if multiple ecosystems)
            if (_dependencyTrees.Count > 1)
            {
                var ecosystemIcon = tree.ProjectType == ProjectType.Npm ? "📦" : "🔷";
                var ecosystemLabel = tree.ProjectType == ProjectType.Npm ? "npm" : "NuGet";
                sb.AppendLine($"<div class=\"ecosystem-header\" data-ecosystem=\"{ecosystemValue}\">");
                sb.AppendLine($"  <span class=\"ecosystem-icon\">{ecosystemIcon}</span>");
                sb.AppendLine($"  <span class=\"ecosystem-label\">{ecosystemLabel}</span>");
                sb.AppendLine($"  <span class=\"ecosystem-count\">{tree.TotalPackages} packages</span>");
                sb.AppendLine($"</div>");
            }

            // Tree container
            sb.AppendLine($"<div class=\"dependency-tree\" data-ecosystem=\"{ecosystemValue}\">");
            sb.AppendLine("  <ul class=\"tree-root\">");

            foreach (var root in tree.Roots)
            {
                GenerateTreeNode(sb, root, 1);
            }

            sb.AppendLine("  </ul>");
            sb.AppendLine("</div>");
        }
    }

    private void GenerateTreeNode(StringBuilder sb, DependencyTreeNode node, int indent)
    {
        var hasChildren = node.Children.Count > 0;
        var indentStr = new string(' ', indent * 2);

        var nodeClasses = new List<string> { "tree-node" };
        if (node.IsDuplicate) nodeClasses.Add("duplicate");
        if (node.HasVulnerabilities) nodeClasses.Add("has-vuln");
        if (node.HasVulnerableDescendant) nodeClasses.Add("has-vuln-descendant");

        var scoreClass = node.HealthScore.HasValue ? GetScoreClass(node.HealthScore.Value) : "";

        sb.AppendLine($"{indentStr}<li class=\"{string.Join(" ", nodeClasses)}\" data-name=\"{EscapeHtml(node.PackageId.ToLowerInvariant())}\">");

        if (hasChildren && !node.IsDuplicate)
        {
            // Trees are collapsed by default, so show [+]
            sb.AppendLine($"{indentStr}  <span class=\"tree-toggle\" onclick=\"toggleTreeNode(this)\">[+]</span>");
        }
        else
        {
            sb.AppendLine($"{indentStr}  <span class=\"tree-toggle leaf\">&nbsp;&bull;&nbsp;</span>");
        }

        // Package name as link to registry
        var packageUrl = node.Ecosystem == PackageEcosystem.Npm
            ? $"https://www.npmjs.com/package/{Uri.EscapeDataString(node.PackageId)}"
            : $"https://www.nuget.org/packages/{node.PackageId}";
        sb.AppendLine($"{indentStr}  <a href=\"{EscapeHtml(packageUrl)}\" target=\"_blank\" class=\"node-name\">{EscapeHtml(node.PackageId)}</a>");
        sb.AppendLine($"{indentStr}  <span class=\"node-version\">{EscapeHtml(node.Version)}</span>");

        // Look up package health data for CRA score
        var healthData = _healthDataCache?.FirstOrDefault(p => p.PackageId.Equals(node.PackageId, StringComparison.OrdinalIgnoreCase))
                      ?? _transitiveDataCache?.FirstOrDefault(p => p.PackageId.Equals(node.PackageId, StringComparison.OrdinalIgnoreCase));

        if (healthData is not null)
        {
            // Get effective CRA score (considers dependency scores)
            var ownCraScore = healthData.CraScore;
            var effectiveCraScore = _effectiveCraScores.TryGetValue(node.PackageId, out var eff) ? eff : ownCraScore;
            _craLimitingDependency.TryGetValue(node.PackageId, out var limitingDep);
            var craScoreClass = GetCraScoreClass(effectiveCraScore);

            // Build detailed tooltip explaining the score
            var tooltip = BuildCraScoreTooltip(healthData, effectiveCraScore, limitingDep);
            sb.AppendLine($"{indentStr}  <span class=\"node-score cra {craScoreClass}\" title=\"{tooltip}\">{effectiveCraScore}</span>");

            // Show Health score
            var healthScoreClass = GetScoreClass(healthData.Score);
            sb.AppendLine($"{indentStr}  <span class=\"node-score health {healthScoreClass}\" title=\"Health Score\">{healthData.Score}</span>");
        }
        else if (node.HealthScore.HasValue)
        {
            // Fallback to tree node score if no health data found
            sb.AppendLine($"{indentStr}  <span class=\"node-score {scoreClass}\">{node.HealthScore.Value}</span>");
        }

        if (node.IsDuplicate)
        {
            var dupTooltip = "Appears elsewhere in the tree";
            if (_parentLookup.TryGetValue(node.PackageId, out var parents) && parents.Count > 0)
            {
                dupTooltip = $"Required by: {string.Join(", ", parents.Distinct().Take(5))}";
                if (parents.Distinct().Count() > 5)
                    dupTooltip += $" (+{parents.Distinct().Count() - 5} more)";
            }
            sb.AppendLine($"{indentStr}  <span class=\"node-badge duplicate\" title=\"{EscapeHtml(dupTooltip)}\">dup</span>");
        }

        if (node.HasVulnerabilities)
        {
            var vulnUrl = node.VulnerabilityUrl ?? $"https://osv.dev/list?ecosystem={(node.Ecosystem == PackageEcosystem.Npm ? "npm" : "NuGet")}&q={Uri.EscapeDataString(node.PackageId)}";
            var vulnTooltip = EscapeHtml(node.VulnerabilitySummary ?? "Click for vulnerability details");
            sb.AppendLine($"{indentStr}  <a href=\"{EscapeHtml(vulnUrl)}\" target=\"_blank\" class=\"node-badge vuln\" title=\"{vulnTooltip}\">VULN</a>");
        }
        else if (node.HasVulnerableDescendant)
        {
            sb.AppendLine($"{indentStr}  <span class=\"node-badge transitive-vuln\" title=\"Has vulnerable sub-dependencies\">&#9888;</span>");
        }

        if (node.HasVersionConflict && node.ConflictingVersions.Count > 0)
        {
            var conflictTooltip = $"Also found: {string.Join(", ", node.ConflictingVersions)}";
            sb.AppendLine($"{indentStr}  <span class=\"node-badge version-conflict\" title=\"{EscapeHtml(conflictTooltip)}\">CONFLICT</span>");
        }

        if (!string.IsNullOrEmpty(node.License))
        {
            sb.AppendLine($"{indentStr}  <span class=\"node-license\">{FormatLicenseWithLinks(node.License)}</span>");
        }

        if (hasChildren && !node.IsDuplicate)
        {
            // Trees are collapsed by default
            sb.AppendLine($"{indentStr}  <ul class=\"tree-children collapsed\">");
            foreach (var child in node.Children)
            {
                GenerateTreeNode(sb, child, indent + 2);
            }
            sb.AppendLine($"{indentStr}  </ul>");
        }

        sb.AppendLine($"{indentStr}</li>");
    }

    private static void GenerateDependencyIssuesSection(StringBuilder sb, CraReport report)
    {
        sb.AppendLine("<div class=\"section-header\">");
        sb.AppendLine("  <h2>Dependency Issues</h2>");
        sb.AppendLine("</div>");

        if (report.DependencyIssues.Count == 0)
        {
            sb.AppendLine("<div class=\"card empty-state\">");
            sb.AppendLine("  <div class=\"empty-icon\">&#10004;</div>");
            sb.AppendLine("  <h3>No Dependency Issues</h3>");
            sb.AppendLine("  <p>No version conflicts or dependency issues detected.</p>");
            sb.AppendLine("</div>");
            return;
        }

        // Summary stats
        sb.AppendLine("<div class=\"issues-summary\">");
        var versionConflicts = report.DependencyIssues.Count(i => i.Type == DependencyIssueType.VersionConflict);
        var peerMismatches = report.DependencyIssues.Count(i => i.Type == DependencyIssueType.PeerDependencyMismatch);
        sb.AppendLine($"  <span class=\"issue-stat\"><strong>{versionConflicts}</strong> version conflicts</span>");
        if (peerMismatches > 0)
        {
            sb.AppendLine($"  <span class=\"issue-stat\"><strong>{peerMismatches}</strong> peer dependency mismatches</span>");
        }
        sb.AppendLine("</div>");

        // Issues list
        sb.AppendLine("<div class=\"issues-list\">");
        foreach (var issue in report.DependencyIssues.OrderByDescending(i => i.Versions.Count))
        {
            var severityClass = issue.Severity.ToLowerInvariant();
            sb.AppendLine($"<div class=\"card issue-card {severityClass}\">");
            sb.AppendLine($"  <div class=\"issue-header\">");
            sb.AppendLine($"    <span class=\"issue-package\">{EscapeHtml(issue.PackageId)}</span>");
            sb.AppendLine($"    <span class=\"issue-badge {severityClass}\">{issue.Versions.Count} versions</span>");
            sb.AppendLine($"  </div>");
            sb.AppendLine($"  <div class=\"issue-versions\">");
            foreach (var version in issue.Versions)
            {
                sb.AppendLine($"    <span class=\"version-tag\">{EscapeHtml(version)}</span>");
            }
            sb.AppendLine($"  </div>");
            if (!string.IsNullOrEmpty(issue.Recommendation))
            {
                sb.AppendLine($"  <div class=\"issue-recommendation\">");
                sb.AppendLine($"    <strong>Recommendation:</strong> {EscapeHtml(issue.Recommendation)}");
                sb.AppendLine($"  </div>");
            }
            sb.AppendLine("</div>");
        }
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
      padding-bottom: 60px;
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

    .metric-detail {
      color: var(--text-muted);
      font-size: 0.75rem;
      margin-top: 0.25rem;
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

    .filter-group {
      display: flex;
      align-items: center;
      gap: 8px;
    }

    .filter-label {
      font-size: 0.85rem;
      color: var(--text-muted);
      font-weight: 500;
    }

    .filter-btn.nuget.active { background: #512bd4; border-color: #512bd4; }
    .filter-btn.npm.active { background: #cb3837; border-color: #cb3837; }

    .tree-ecosystem-filter {
      margin-left: auto;
    }

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

    .package-scores {
      display: flex;
      gap: 12px;
      margin-right: 15px;
    }

    .package-score-item {
      display: flex;
      flex-direction: column;
      align-items: center;
      gap: 2px;
    }

    .package-score-item .score-label {
      font-size: 0.65rem;
      color: var(--text-muted);
      text-transform: uppercase;
      font-weight: 600;
    }

    .package-score-item .score-value {
      width: 36px;
      height: 36px;
      border-radius: 50%;
      display: flex;
      align-items: center;
      justify-content: center;
      font-weight: 700;
      font-size: 0.85rem;
      color: white;
      background-color: #6c757d;
    }

    .package-score-item .score-value.healthy { background-color: #28a745 !important; }
    .package-score-item .score-value.watch { background-color: #17a2b8 !important; }
    .package-score-item .score-value.warning { background-color: #ffc107 !important; color: #000; }
    .package-score-item .score-value.critical { background-color: #dc3545 !important; }

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

    .distribution-stacked-bar {
      display: flex;
      height: 40px;
      border-radius: 8px;
      overflow: hidden;
      box-shadow: inset 0 1px 2px rgba(0,0,0,0.1);
    }

    .bar-segment {
      display: flex;
      align-items: center;
      justify-content: center;
      color: white;
      font-weight: 500;
      font-size: 0.85rem;
      transition: filter 0.2s;
      min-width: 0;
    }

    .bar-segment:hover {
      filter: brightness(1.1);
    }

    .bar-segment .segment-label {
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
      padding: 0 8px;
      text-shadow: 0 1px 2px rgba(0,0,0,0.2);
    }

    .bar-segment.permissive { background: linear-gradient(180deg, #34ce57, #28a745); }
    .bar-segment.weak-copyleft { background: linear-gradient(180deg, #20c9e0, #17a2b8); }
    .bar-segment.strong-copyleft { background: linear-gradient(180deg, #e4606d, #dc3545); }
    .bar-segment.public-domain { background: linear-gradient(180deg, #8b5cf6, #6f42c1); }
    .bar-segment.unknown { background: linear-gradient(180deg, #868e96, #6c757d); }

    .distribution-legend {
      display: flex;
      flex-wrap: wrap;
      gap: 16px;
      margin-top: 16px;
    }

    .legend-item {
      display: flex;
      align-items: center;
      gap: 8px;
      font-size: 0.9rem;
    }

    .legend-color {
      width: 16px;
      height: 16px;
      border-radius: 4px;
    }

    .legend-color.permissive { background: #28a745; }
    .legend-color.weak-copyleft { background: #17a2b8; }
    .legend-color.strong-copyleft { background: #dc3545; }
    .legend-color.public-domain { background: #6f42c1; }
    .legend-color.unknown { background: #6c757d; }

    .legend-label {
      font-weight: 500;
      color: var(--text);
    }

    .legend-count {
      font-weight: 600;
      color: var(--text);
    }

    .legend-percent {
      color: var(--text-muted);
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

    .highlight-flash {
      animation: flashHighlight 2s ease-out;
    }

    @keyframes flashHighlight {
      0%, 20% { background-color: rgba(37, 99, 235, 0.3); box-shadow: 0 0 0 3px rgba(37, 99, 235, 0.5); }
      100% { background-color: transparent; box-shadow: none; }
    }

    .tree-node.highlight-flash {
      background-color: rgba(37, 99, 235, 0.2);
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

    .required-by {
      margin-top: 12px;
      padding: 10px 12px;
      background: var(--bg);
      border-radius: 8px;
      border: 1px solid var(--border);
    }

    .required-by-label {
      font-size: 0.85rem;
      color: var(--text-muted);
      margin-right: 8px;
    }

    .parent-packages {
      display: inline-flex;
      flex-wrap: wrap;
      gap: 6px;
      margin-top: 4px;
    }

    .parent-badge {
      display: inline-block;
      padding: 3px 10px;
      background: var(--primary);
      color: white;
      border-radius: 12px;
      font-size: 0.8rem;
      text-decoration: none;
      cursor: pointer;
      transition: background 0.2s;
    }

    .parent-badge:hover {
      background: var(--primary-dark);
      text-decoration: none;
    }

    .parent-badge.direct {
      background: var(--success);
    }

    .parent-badge.direct:hover {
      background: #1e7e34;
    }

    .more-parents {
      font-size: 0.8rem;
      color: var(--text-muted);
      padding: 3px 6px;
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

    .empty-state.success {
      border: 2px solid var(--success);
      background: rgba(34, 197, 94, 0.05);
    }

    .empty-state.success .empty-icon {
      color: var(--success);
    }

    .vuln-alert {
      display: flex;
      align-items: center;
      gap: 12px;
      padding: 16px 20px;
      background: rgba(239, 68, 68, 0.1);
      border: 1px solid var(--danger);
      border-radius: 8px;
      margin-bottom: 20px;
    }

    .vuln-alert-icon {
      font-size: 1.5rem;
      color: var(--danger);
    }

    .vuln-alert-text {
      font-size: 1.1rem;
      color: var(--danger);
    }

    .vuln-safe-note {
      color: var(--text-muted);
      font-size: 0.9rem;
    }

    .reviewed-vulns-section {
      margin-top: 30px;
      border-top: 1px solid var(--border);
      padding-top: 20px;
    }

    .reviewed-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 12px 16px;
      background: var(--card-bg);
      border-radius: 8px;
      cursor: pointer;
      color: var(--text-muted);
      font-size: 0.9rem;
    }

    .reviewed-header:hover {
      background: var(--border);
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

    .vuln-stat .label {
      display: block;
      font-weight: 600;
      margin-top: 5px;
    }

    .vuln-stat .sublabel {
      display: block;
      font-size: 0.8rem;
      color: var(--text-muted);
      margin-top: 4px;
    }

    .vuln-package-info {
      margin: 8px 0;
    }

    .vuln-patched-note {
      display: block;
      color: var(--success);
      font-size: 0.9rem;
      margin-top: 4px;
    }

    .vuln-affected-note {
      display: block;
      color: var(--danger);
      font-size: 0.9rem;
      margin-top: 4px;
    }

    .vuln-fixed-in {
      display: block;
      color: var(--primary);
      font-size: 0.9rem;
      font-weight: 600;
      margin-top: 4px;
    }

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
      color: var(--primary);
      text-decoration: none;
    }
    .vuln-id:hover {
      text-decoration: underline;
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

    .disclaimer-footer {
      position: fixed;
      bottom: 0;
      left: var(--sidebar-width);
      right: 0;
      background: var(--card-bg);
      border-top: 1px solid var(--border);
      padding: 12px 30px;
      text-align: center;
      font-size: 0.8rem;
      color: var(--text-muted);
      z-index: 100;
    }

    .disclaimer-footer p {
      margin: 0;
      max-width: 800px;
      margin: 0 auto;
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

    /* Dependency Issues */
    .issues-summary {
      display: flex;
      gap: 20px;
      margin-bottom: 20px;
      flex-wrap: wrap;
    }

    .issue-stat {
      background: var(--bg);
      padding: 8px 16px;
      border-radius: 6px;
      font-size: 0.9rem;
    }

    .issues-list {
      display: flex;
      flex-direction: column;
      gap: 12px;
    }

    .issue-card {
      border-left: 4px solid var(--warning);
    }

    .issue-card.critical {
      border-left-color: var(--danger);
    }

    .issue-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 12px;
    }

    .issue-package {
      font-weight: 600;
      font-size: 1.1rem;
    }

    .issue-badge {
      padding: 4px 10px;
      border-radius: 12px;
      font-size: 0.8rem;
      font-weight: 500;
      background: var(--warning);
      color: #000;
    }

    .issue-badge.critical {
      background: var(--danger);
      color: white;
    }

    .issue-versions {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      margin-bottom: 12px;
    }

    .version-tag {
      background: var(--bg);
      padding: 4px 10px;
      border-radius: 4px;
      font-family: monospace;
      font-size: 0.85rem;
    }

    .issue-recommendation {
      background: rgba(255, 193, 7, 0.1);
      padding: 10px 12px;
      border-radius: 4px;
      font-size: 0.9rem;
    }

    /* Dependency Tree */
    .tree-stats {
      display: flex;
      gap: 20px;
      margin-bottom: 15px;
      flex-wrap: wrap;
    }

    .tree-stat {
      padding: 8px 16px;
      background: var(--card-bg);
      border-radius: 8px;
      font-size: 0.9rem;
      box-shadow: 0 1px 3px rgba(0,0,0,0.1);
    }

    .tree-stat.vulnerable {
      background: #f8d7da;
      color: var(--danger);
    }

    .tree-controls {
      display: flex;
      gap: 10px;
      margin-bottom: 20px;
      flex-wrap: wrap;
      align-items: center;
    }

    .tree-btn {
      padding: 8px 16px;
      border: 1px solid var(--border);
      background: white;
      border-radius: 8px;
      cursor: pointer;
      font-size: 0.85rem;
      transition: all 0.2s;
    }

    .tree-btn:hover {
      background: var(--primary);
      color: white;
      border-color: var(--primary);
    }

    .dependency-tree {
      background: var(--card-bg);
      border-radius: 12px;
      padding: 20px;
      box-shadow: 0 1px 3px rgba(0,0,0,0.1);
      font-family: 'SF Mono', Monaco, 'Cascadia Code', Consolas, monospace;
      font-size: 0.9rem;
      overflow-x: auto;
    }

    .tree-root, .tree-children {
      list-style: none;
      padding-left: 0;
      margin: 0;
    }

    .tree-children {
      margin-left: 16px;
      margin-top: 4px;
      padding: 8px 8px 8px 16px;
      border-left: 3px solid var(--primary);
      background: rgba(0, 102, 204, 0.03);
      border-radius: 0 8px 8px 0;
    }

    .tree-children .tree-children {
      border-left-color: var(--success);
      background: rgba(40, 167, 69, 0.03);
    }

    .tree-children .tree-children .tree-children {
      border-left-color: var(--watch);
      background: rgba(23, 162, 184, 0.03);
    }

    .tree-children .tree-children .tree-children .tree-children {
      border-left-color: var(--warning);
      background: rgba(255, 193, 7, 0.03);
    }

    .tree-node {
      padding: 8px 12px;
      margin: 4px 0;
      display: flex;
      align-items: center;
      flex-wrap: wrap;
      gap: 8px;
      background: white;
      border-radius: 6px;
      border: 1px solid var(--border);
      transition: box-shadow 0.2s;
    }

    .tree-node:hover {
      box-shadow: 0 2px 8px rgba(0,0,0,0.1);
    }

    .tree-node.duplicate {
      opacity: 0.6;
    }

    .tree-node.duplicate .node-name {
      font-style: italic;
    }

    .tree-node.has-vuln {
      background: rgba(220, 53, 69, 0.15);
      margin: 0 -10px;
      padding: 6px 10px;
      border-radius: 4px;
    }

    .tree-node.has-vuln-descendant:not(.has-vuln) {
      border-left: 3px solid var(--danger);
      margin-left: -3px;
      padding-left: 7px;
    }

    .tree-node.has-vuln-descendant:not(.has-vuln) > .tree-toggle,
    .tree-node.has-vuln-descendant:not(.has-vuln) > .node-name {
      color: var(--danger);
    }

    .tree-toggle {
      cursor: pointer;
      color: var(--text-muted);
      width: 24px;
      text-align: center;
      user-select: none;
      flex-shrink: 0;
    }

    .tree-toggle:not(.leaf):hover {
      color: var(--primary);
    }

    .tree-toggle.leaf {
      cursor: default;
      color: var(--border);
    }

    .node-name {
      font-weight: 600;
      color: var(--text);
    }

    .node-version {
      color: var(--text-muted);
      font-size: 0.85em;
    }

    .node-score {
      padding: 2px 6px;
      border-radius: 4px;
      font-size: 0.7em;
      font-weight: 600;
      color: white;
    }

    .node-score::before {
      font-weight: 400;
      margin-right: 3px;
      opacity: 0.9;
    }

    .node-score.cra::before { content: ""CRA""; }
    .node-score.health::before { content: ""H""; }

    .node-score.healthy { background: var(--success); }
    .node-score.watch { background: var(--watch); }
    .node-score.warning { background: var(--warning); color: #000; }
    .node-score.critical { background: var(--danger); }

    .node-badge {
      padding: 1px 6px;
      border-radius: 4px;
      font-size: 0.7em;
      font-weight: 600;
      text-transform: uppercase;
    }

    .node-badge.duplicate {
      background: var(--text-muted);
      color: white;
    }

    a.node-badge.vuln {
      background: var(--danger);
      color: white;
      text-decoration: none;
      cursor: pointer;
    }

    a.node-badge.vuln:hover {
      background: #c82333;
      text-decoration: underline;
    }

    .node-badge.transitive-vuln {
      background: transparent;
      color: var(--danger);
      font-size: 1em;
      padding: 0 4px;
    }

    .node-badge.version-conflict {
      background: var(--warning);
      color: #000;
    }

    .node-license {
      color: var(--text-muted);
      font-size: 0.75em;
      padding: 1px 6px;
      background: var(--bg);
      border-radius: 4px;
    }

    .tree-children.collapsed {
      display: none;
    }

    .tree-node.hidden {
      display: none;
    }

    .ecosystem-header {
      display: flex;
      align-items: center;
      gap: 10px;
      padding: 12px 16px;
      background: linear-gradient(90deg, #f8f9fa 0%, #e9ecef 100%);
      border-radius: 8px;
      margin: 20px 0 10px 0;
      border-left: 4px solid var(--primary);
    }

    .ecosystem-header:first-of-type {
      margin-top: 0;
    }

    .ecosystem-icon {
      font-size: 1.25rem;
    }

    .ecosystem-label {
      font-weight: 600;
      font-size: 1.1rem;
    }

    .ecosystem-count {
      color: var(--text-muted);
      font-size: 0.9rem;
      margin-left: auto;
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

function navigateToPackage(packageName) {{
  // First try to find in direct packages
  const directPkg = document.querySelector(`.package-card:not(.transitive)[data-name='${{packageName}}']`);
  if (directPkg) {{
    showSection('packages');
    directPkg.scrollIntoView({{ behavior: 'smooth', block: 'center' }});
    directPkg.classList.add('expanded');
    directPkg.classList.add('highlight-flash');
    setTimeout(() => directPkg.classList.remove('highlight-flash'), 2000);
    return;
  }}

  // Try transitive packages
  const transitivePkg = document.querySelector(`.package-card.transitive[data-name='${{packageName}}']`);
  if (transitivePkg) {{
    showSection('packages');
    // Expand transitive section if collapsed
    const transitiveList = document.getElementById('transitive-list');
    if (transitiveList && transitiveList.style.display === 'none') {{
      toggleTransitive();
    }}
    transitivePkg.scrollIntoView({{ behavior: 'smooth', block: 'center' }});
    transitivePkg.classList.add('expanded');
    transitivePkg.classList.add('highlight-flash');
    setTimeout(() => transitivePkg.classList.remove('highlight-flash'), 2000);
    return;
  }}

  // Try dependency tree
  const treeNode = document.querySelector(`.tree-node[data-name='${{packageName}}']`);
  if (treeNode) {{
    showSection('tree');
    // Expand parent nodes to make this node visible
    let parent = treeNode.parentElement;
    while (parent) {{
      if (parent.classList && parent.classList.contains('tree-children')) {{
        parent.style.display = 'block';
        const toggle = parent.previousElementSibling?.querySelector('.tree-toggle');
        if (toggle && toggle.textContent === '[+]') {{
          toggle.textContent = '[-]';
        }}
      }}
      parent = parent.parentElement;
    }}
    treeNode.scrollIntoView({{ behavior: 'smooth', block: 'center' }});
    treeNode.classList.add('highlight-flash');
    setTimeout(() => treeNode.classList.remove('highlight-flash'), 2000);
  }}
}}

function filterPackages() {{
  const search = document.getElementById('package-search').value.toLowerCase();
  document.querySelectorAll('.package-card').forEach(card => {{
    const name = card.dataset.name;
    card.style.display = name.includes(search) ? '' : 'none';
  }});
}}

let currentStatusFilter = 'all';
let currentEcosystemFilter = 'all';

function filterByStatus(status) {{
  currentStatusFilter = status;
  document.querySelectorAll('.filter-btn:not(.ecosystem-btn)').forEach(btn => btn.classList.remove('active'));
  event.target.classList.add('active');
  applyPackageFilters();
}}

function filterByEcosystem(ecosystem) {{
  currentEcosystemFilter = ecosystem;
  document.querySelectorAll('.filter-btn.ecosystem-btn').forEach(btn => btn.classList.remove('active'));
  event.target.classList.add('active');
  applyPackageFilters();
}}

function applyPackageFilters() {{
  document.querySelectorAll('.package-card').forEach(card => {{
    const statusMatch = currentStatusFilter === 'all' || card.dataset.status === currentStatusFilter;
    const ecosystemMatch = currentEcosystemFilter === 'all' || card.dataset.ecosystem === currentEcosystemFilter;
    card.style.display = (statusMatch && ecosystemMatch) ? '' : 'none';
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

function toggleReviewedVulns() {{
  const list = document.getElementById('reviewed-vulns-list');
  const toggle = document.getElementById('reviewed-toggle');
  if (list.style.display === 'none') {{
    list.style.display = '';
    toggle.textContent = '-';
  }} else {{
    list.style.display = 'none';
    toggle.textContent = '+';
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

  // Reset filters to 'all'
  currentStatusFilter = 'all';
  currentEcosystemFilter = 'all';
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

// Dependency Tree functions
function toggleTreeNode(toggle) {{
  const li = toggle.closest('.tree-node');
  const children = li.querySelector('.tree-children');
  if (children) {{
    const isCollapsed = children.classList.contains('collapsed');
    children.classList.toggle('collapsed');
    toggle.textContent = isCollapsed ? '[-]' : '[+]';
  }}
}}

function expandAllTree() {{
  document.querySelectorAll('.tree-children').forEach(el => {{
    el.classList.remove('collapsed');
  }});
  document.querySelectorAll('.tree-toggle:not(.leaf)').forEach(el => {{
    el.textContent = '[-]';
  }});
}}

function collapseAllTree() {{
  document.querySelectorAll('.tree-children').forEach(el => {{
    el.classList.add('collapsed');
  }});
  document.querySelectorAll('.tree-toggle:not(.leaf)').forEach(el => {{
    el.textContent = '[+]';
  }});
}}

function filterTree() {{
  const search = document.getElementById('tree-search').value.toLowerCase();

  if (!search) {{
    // Show all nodes
    document.querySelectorAll('.tree-node').forEach(node => {{
      node.classList.remove('hidden');
    }});
    return;
  }}

  // First, hide all nodes
  document.querySelectorAll('.tree-node').forEach(node => {{
    node.classList.add('hidden');
  }});

  // Find matching nodes and show them with their ancestors
  document.querySelectorAll('.tree-node').forEach(node => {{
    const name = node.dataset.name || '';
    if (name.includes(search)) {{
      // Show this node
      node.classList.remove('hidden');

      // Show all ancestors
      let parent = node.parentElement;
      while (parent) {{
        if (parent.classList && parent.classList.contains('tree-node')) {{
          parent.classList.remove('hidden');
        }}
        parent = parent.parentElement;
      }}

      // Expand ancestor tree-children
      let ancestor = node.parentElement;
      while (ancestor) {{
        if (ancestor.classList && ancestor.classList.contains('tree-children')) {{
          ancestor.classList.remove('collapsed');
          const toggle = ancestor.previousElementSibling?.querySelector('.tree-toggle');
          if (toggle && !toggle.classList.contains('leaf')) {{
            toggle.textContent = '[-]';
          }}
        }}
        ancestor = ancestor.parentElement;
      }}
    }}
  }});
}}

function filterTreeByEcosystem(ecosystem) {{
  document.querySelectorAll('.tree-ecosystem-filter .filter-btn').forEach(btn => btn.classList.remove('active'));
  event.target.classList.add('active');

  document.querySelectorAll('.dependency-tree').forEach(tree => {{
    const header = tree.previousElementSibling;
    if (ecosystem === 'all') {{
      tree.style.display = '';
      if (header && header.classList.contains('ecosystem-header')) {{
        header.style.display = '';
      }}
    }} else {{
      const match = tree.dataset.ecosystem === ecosystem;
      tree.style.display = match ? '' : 'none';
      if (header && header.classList.contains('ecosystem-header')) {{
        header.style.display = match ? '' : 'none';
      }}
    }}
  }});
}}
</script>";
    }

    private List<PackageHealth>? _healthDataCache;
    private List<PackageHealth>? _transitiveDataCache;
    private List<DependencyTree> _dependencyTrees = [];
    private Dictionary<string, List<string>> _parentLookup = new(StringComparer.OrdinalIgnoreCase);
    private Dictionary<string, int> _effectiveCraScores = new(StringComparer.OrdinalIgnoreCase);
    private Dictionary<string, string?> _craLimitingDependency = new(StringComparer.OrdinalIgnoreCase);
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

    /// <summary>
    /// Set dependency tree for tree visualization.
    /// </summary>
    public void SetDependencyTree(DependencyTree? tree)
    {
        if (tree is not null)
        {
            _dependencyTrees = [tree];
        }
    }

    /// <summary>
    /// Add a dependency tree for tree visualization (supports multiple ecosystems).
    /// </summary>
    public void AddDependencyTree(DependencyTree? tree)
    {
        if (tree is not null)
        {
            _dependencyTrees.Add(tree);
        }
    }

    /// <summary>
    /// Build reverse dependency lookup (package -> list of packages that depend on it).
    /// Must be called after setting dependency trees.
    /// </summary>
    private void BuildParentLookup()
    {
        _parentLookup.Clear();

        foreach (var tree in _dependencyTrees)
        {
            foreach (var root in tree.Roots)
            {
                BuildParentLookupRecursive(root, null);
            }
        }
    }

    private void BuildParentLookupRecursive(DependencyTreeNode node, string? parentId)
    {
        // Record this node's parent
        if (parentId is not null)
        {
            if (!_parentLookup.TryGetValue(node.PackageId, out var parents))
            {
                parents = [];
                _parentLookup[node.PackageId] = parents;
            }
            if (!parents.Contains(parentId, StringComparer.OrdinalIgnoreCase))
            {
                parents.Add(parentId);
            }
        }

        // Process children
        foreach (var child in node.Children)
        {
            BuildParentLookupRecursive(child, node.PackageId);
        }
    }

    /// <summary>
    /// Build effective CRA scores that account for dependency scores.
    /// A package's effective CRA score is capped by its worst dependency's score.
    /// </summary>
    private void BuildEffectiveCraScores()
    {
        _effectiveCraScores.Clear();
        _craLimitingDependency.Clear();

        foreach (var tree in _dependencyTrees)
        {
            foreach (var root in tree.Roots)
            {
                CalculateEffectiveCraScore(root);
            }
        }
    }

    /// <summary>
    /// Calculate effective CRA score for a node (minimum of own score and all descendants).
    /// Returns (effectiveScore, limitingPackageId).
    /// </summary>
    private (int Score, string? LimitingPackage) CalculateEffectiveCraScore(DependencyTreeNode node)
    {
        // Get this package's own CRA score
        var healthData = _healthDataCache?.FirstOrDefault(p => p.PackageId.Equals(node.PackageId, StringComparison.OrdinalIgnoreCase))
                      ?? _transitiveDataCache?.FirstOrDefault(p => p.PackageId.Equals(node.PackageId, StringComparison.OrdinalIgnoreCase));

        var ownScore = healthData?.CraScore ?? 100;

        // Find minimum score among all children and track which one limits
        var minChildScore = 100;
        string? limitingChild = null;
        foreach (var child in node.Children)
        {
            var (childEffectiveScore, childLimiter) = CalculateEffectiveCraScore(child);
            if (childEffectiveScore < minChildScore)
            {
                minChildScore = childEffectiveScore;
                // The limiter is either the child itself or what limits the child
                limitingChild = childLimiter ?? child.PackageId;
            }
        }

        // Effective score is minimum of own and children's scores
        int effectiveScore;
        string? limitingPackage;
        if (minChildScore < ownScore)
        {
            effectiveScore = minChildScore;
            limitingPackage = limitingChild;
        }
        else
        {
            effectiveScore = ownScore;
            limitingPackage = null; // Own score is the limit
        }

        // Store for lookup (use the worst effective score if package appears multiple times)
        if (_effectiveCraScores.TryGetValue(node.PackageId, out var existing))
        {
            if (effectiveScore < existing)
            {
                _effectiveCraScores[node.PackageId] = effectiveScore;
                _craLimitingDependency[node.PackageId] = limitingPackage;
            }
        }
        else
        {
            _effectiveCraScores[node.PackageId] = effectiveScore;
            _craLimitingDependency[node.PackageId] = limitingPackage;
        }

        return (effectiveScore, limitingPackage);
    }

    /// <summary>
    /// Build a detailed tooltip explaining the CRA score.
    /// </summary>
    private string BuildCraScoreTooltip(PackageHealth healthData, int effectiveScore, string? limitingDep)
    {
        var parts = new List<string>();

        // Explain own score breakdown
        var vulnCount = healthData.Vulnerabilities.Count;
        var license = healthData.License;

        if (vulnCount > 0)
        {
            parts.Add($"Vulnerabilities: {vulnCount} found (-points)");
        }
        else
        {
            parts.Add("Vulnerabilities: None ✓");
        }

        if (string.IsNullOrWhiteSpace(license) ||
            license.Equals("UNKNOWN", StringComparison.OrdinalIgnoreCase) ||
            license.Equals("NOASSERTION", StringComparison.OrdinalIgnoreCase))
        {
            parts.Add("License: Unknown (-25 points)");
        }
        else
        {
            parts.Add($"License: {license} ✓");
        }

        parts.Add($"Own CRA score: {healthData.CraScore}");

        // Explain if limited by dependency
        if (limitingDep is not null && effectiveScore < healthData.CraScore)
        {
            parts.Add($"Limited by: {limitingDep} (CRA {effectiveScore})");
        }

        return string.Join("&#10;", parts); // &#10; is newline in HTML title
    }

    private static string GetScoreClass(int score) => score switch
    {
        >= 80 => "healthy",
        >= 60 => "watch",
        >= 40 => "warning",
        _ => "critical"
    };

    private static string GetCraScoreClass(int score) => score switch
    {
        >= 90 => "healthy",
        >= 70 => "watch",
        >= 50 => "warning",
        _ => "critical"
    };

    /// <summary>
    /// Get inline style for score circle with explicit colors.
    /// </summary>
    private static string GetScoreStyle(int score)
    {
        var (bg, fg) = score switch
        {
            >= 80 => ("#28a745", "#fff"),  // green
            >= 60 => ("#17a2b8", "#fff"),  // teal
            >= 40 => ("#ffc107", "#000"),  // yellow
            _ => ("#dc3545", "#fff")       // red
        };
        return $"background-color:{bg};color:{fg};width:36px;height:36px;border-radius:50%;display:inline-flex;align-items:center;justify-content:center;font-weight:700;font-size:0.85rem;";
    }

    /// <summary>
    /// Calculate aggregate CRA compliance score for the project.
    /// Based on vulnerabilities and license coverage - not freshness/activity.
    /// </summary>
    private static int CalculateProjectCraScore(
        IEnumerable<PackageHealth> directPackages,
        IEnumerable<PackageHealth> transitivePackages,
        int activeVulnerabilityCount = 0)
    {
        var allPackages = directPackages.Concat(transitivePackages).ToList();
        if (allPackages.Count == 0) return 100;

        // Calculate base score from individual package CRA scores
        var totalCraScore = 0;
        foreach (var pkg in allPackages)
        {
            totalCraScore += pkg.CraScore;
        }
        var baseScore = (double)totalCraScore / allPackages.Count;

        // Count packages with unknown/missing licenses (CRA Article 10(9) requirement)
        var unknownLicenseCount = allPackages.Count(p =>
            string.IsNullOrWhiteSpace(p.License) ||
            p.License.Equals("UNKNOWN", StringComparison.OrdinalIgnoreCase) ||
            p.License.Equals("NOASSERTION", StringComparison.OrdinalIgnoreCase));

        // Use VEX-counted vulnerabilities if provided, otherwise count from package data
        var vulnerableCount = activeVulnerabilityCount > 0
            ? activeVulnerabilityCount
            : allPackages.Count(p => p.Vulnerabilities.Count > 0);

        // Apply penalties based on compliance gaps
        var penalty = 0.0;

        // Unknown licenses penalty - CRA requires license identification
        if (unknownLicenseCount > 0)
        {
            var unknownPercent = (double)unknownLicenseCount / allPackages.Count * 100;
            // Scale penalty: 1-5 packages = 5 points, 5%+ = 10 points, 10%+ = 15 points
            penalty += unknownPercent switch
            {
                >= 10 => 15,
                >= 5 => 10,
                _ => Math.Min(unknownLicenseCount, 5)  // 1 point per package, max 5
            };
        }

        // Vulnerable packages penalty - critical for CRA compliance
        if (vulnerableCount > 0)
        {
            // More aggressive penalty for vulnerabilities
            penalty += vulnerableCount switch
            {
                >= 10 => 30,
                >= 5 => 25,
                >= 3 => 20,
                >= 1 => 15,
                _ => 10
            };
        }

        var finalScore = Math.Max(0, baseScore - penalty);
        return (int)Math.Round(finalScore);
    }

    private static string FormatNumber(long number) => number switch
    {
        >= 1_000_000_000 => $"{number / 1_000_000_000.0:F1}B",
        >= 1_000_000 => $"{number / 1_000_000.0:F1}M",
        >= 1_000 => $"{number / 1_000.0:F1}K",
        _ => number.ToString()
    };

    private static string FormatDownloads(long downloads) =>
        downloads == 0 ? "N/A" : FormatNumber(downloads);

    private static string FormatDuration(TimeSpan duration) => duration.TotalSeconds switch
    {
        < 1 => $"{duration.TotalMilliseconds:F0}ms",
        < 60 => $"{duration.TotalSeconds:F1}s",
        < 3600 => $"{duration.Minutes}m {duration.Seconds}s",
        _ => $"{duration.Hours}h {duration.Minutes}m"
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

    private static string? GetLicenseUrl(string license)
    {
        // Normalize license identifier
        var normalized = license.Trim();

        // Map common license identifiers to SPDX URLs
        return normalized.ToUpperInvariant() switch
        {
            "MIT" => "https://spdx.org/licenses/MIT.html",
            "APACHE-2.0" or "APACHE 2.0" or "APACHE2" => "https://spdx.org/licenses/Apache-2.0.html",
            "BSD-2-CLAUSE" or "BSD 2-CLAUSE" => "https://spdx.org/licenses/BSD-2-Clause.html",
            "BSD-3-CLAUSE" or "BSD 3-CLAUSE" => "https://spdx.org/licenses/BSD-3-Clause.html",
            "GPL-2.0" or "GPL-2.0-ONLY" or "GPL2" => "https://spdx.org/licenses/GPL-2.0-only.html",
            "GPL-3.0" or "GPL-3.0-ONLY" or "GPL3" => "https://spdx.org/licenses/GPL-3.0-only.html",
            "GPL-3.0-OR-LATER" => "https://spdx.org/licenses/GPL-3.0-or-later.html",
            "LGPL-2.1" or "LGPL-2.1-ONLY" => "https://spdx.org/licenses/LGPL-2.1-only.html",
            "LGPL-3.0" or "LGPL-3.0-ONLY" => "https://spdx.org/licenses/LGPL-3.0-only.html",
            "ISC" => "https://spdx.org/licenses/ISC.html",
            "MPL-2.0" => "https://spdx.org/licenses/MPL-2.0.html",
            "UNLICENSE" or "UNLICENSED" => "https://spdx.org/licenses/Unlicense.html",
            "CC0-1.0" or "CC0" => "https://spdx.org/licenses/CC0-1.0.html",
            "WTFPL" => "https://spdx.org/licenses/WTFPL.html",
            "0BSD" => "https://spdx.org/licenses/0BSD.html",
            "MS-PL" => "https://spdx.org/licenses/MS-PL.html",
            "MS-RL" => "https://spdx.org/licenses/MS-RL.html",
            "ZLIB" => "https://spdx.org/licenses/Zlib.html",
            _ => normalized.StartsWith("HTTP", StringComparison.OrdinalIgnoreCase)
                ? normalized  // Already a URL
                : $"https://spdx.org/licenses/{Uri.EscapeDataString(normalized)}.html"  // Try SPDX lookup
        };
    }

    /// <summary>
    /// Format a license expression with individual links for each license.
    /// Handles SPDX expressions like "(MIT OR GPL-3.0-or-later)".
    /// </summary>
    private static string FormatLicenseWithLinks(string license)
    {
        if (string.IsNullOrWhiteSpace(license))
            return EscapeHtml(license);

        // Remove outer parentheses for display
        var text = license.Trim();
        if (text.StartsWith('(') && text.EndsWith(')'))
        {
            text = text[1..^1].Trim();
        }

        // Check for compound expressions
        if (text.Contains(" OR ", StringComparison.OrdinalIgnoreCase))
        {
            var parts = text.Split(new[] { " OR " }, StringSplitOptions.RemoveEmptyEntries);
            var linkedParts = parts.Select(p => FormatSingleLicenseLink(p.Trim()));
            return "(" + string.Join(" OR ", linkedParts) + ")";
        }

        if (text.Contains(" AND ", StringComparison.OrdinalIgnoreCase))
        {
            var parts = text.Split(new[] { " AND " }, StringSplitOptions.RemoveEmptyEntries);
            var linkedParts = parts.Select(p => FormatSingleLicenseLink(p.Trim()));
            return "(" + string.Join(" AND ", linkedParts) + ")";
        }

        if (text.Contains(" WITH ", StringComparison.OrdinalIgnoreCase))
        {
            var parts = text.Split(new[] { " WITH " }, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length >= 2)
            {
                return FormatSingleLicenseLink(parts[0].Trim()) + " WITH " + EscapeHtml(parts[1].Trim());
            }
        }

        // Simple single license
        return FormatSingleLicenseLink(text);
    }

    /// <summary>
    /// Format a single license identifier as a link.
    /// </summary>
    private static string FormatSingleLicenseLink(string license)
    {
        var url = GetLicenseUrl(license);
        if (url is not null)
        {
            return $"<a href=\"{EscapeHtml(url)}\" target=\"_blank\" title=\"View license\">{EscapeHtml(license)}</a>";
        }
        return EscapeHtml(license);
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
    public TimeSpan? GenerationDuration { get; init; }
    public required string ProjectPath { get; init; }
    public required int HealthScore { get; init; }
    public required HealthStatus HealthStatus { get; init; }
    public required List<CraComplianceItem> ComplianceItems { get; init; }
    public required CraComplianceStatus OverallComplianceStatus { get; init; }
    public required SbomDocument Sbom { get; init; }
    public required VexDocument Vex { get; init; }
    public required int PackageCount { get; init; }
    public required int TransitivePackageCount { get; init; }
    public required int VulnerabilityCount { get; init; }
    public required int CriticalPackageCount { get; init; }
    public int VersionConflictCount { get; init; }
    public List<DependencyIssue> DependencyIssues { get; init; } = [];
}

public sealed class CraComplianceItem
{
    public required string Requirement { get; init; }
    public required string Description { get; init; }
    public required CraComplianceStatus Status { get; init; }
    public string? Evidence { get; init; }
    public string? Recommendation { get; init; }
}

// CraComplianceStatus enum is defined in Models/PackageHealth.cs
