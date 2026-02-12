using System.Text;
using DepSafe.DataSources;
using DepSafe.Models;
using DepSafe.Scoring;

namespace DepSafe.Compliance;

public sealed partial class CraReportGenerator
{
    private void GenerateOverviewSection(StringBuilder sb, CraReport report)
    {
        // SBOM completeness warning
        if (_hasIncompleteTransitive || _hasUnresolvedVersions)
        {
            sb.AppendLine("<div class=\"sbom-warning\">");
            sb.AppendLine("  <h4>\u26A0\uFE0F SBOM Completeness Warning</h4>");
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

        // Health Score Card - based on freshness, activity, popularity
        sb.AppendLine("  <div class=\"card score-card\" title=\"Average health of your dependencies based on repository freshness, commit activity, community engagement, and maintenance status.\">");
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

        // CRA Readiness Score Card
        sb.AppendLine($"  <div class=\"card score-card\" title=\"Weighted compliance score across all EU Cyber Resilience Act requirements. Critical items like known exploited vulnerabilities carry more weight than documentation checks.\">");
        sb.AppendLine("    <h3>CRA Readiness</h3>");
        sb.AppendLine($"    <div class=\"score-gauge {GetScoreClass(report.CraReadinessScore)}\">");
        sb.AppendLine($"      <svg viewBox=\"0 0 100 50\">");
        sb.AppendLine($"        <path class=\"gauge-bg\" d=\"M 10 50 A 40 40 0 0 1 90 50\" />");
        var readinessAngle = 180 * (report.CraReadinessScore / 100.0);
        sb.AppendLine($"        <path class=\"gauge-fill\" d=\"M 10 50 A 40 40 0 0 1 90 50\" style=\"stroke-dasharray: {readinessAngle * 1.26}, 226\" />");
        sb.AppendLine($"      </svg>");
        sb.AppendLine($"      <div class=\"score-value\">{report.CraReadinessScore}</div>");
        sb.AppendLine("    </div>");
        sb.AppendLine($"    <div class=\"score-label {GetScoreClass(report.CraReadinessScore)}\">Weighted Compliance</div>");
        sb.AppendLine("  </div>");

        // Compliance Status Card
        sb.AppendLine($"  <div class=\"card status-card {statusClass}\" title=\"Overall compliance status based on EU Cyber Resilience Act Articles 10, 11, 13 and Annexes I, II. ActionRequired means one or more items need attention before the product can be considered CRA-compliant.\">");
        sb.AppendLine("    <h3>CRA Compliance</h3>");
        sb.AppendLine($"    <div class=\"big-status\">{report.OverallComplianceStatus}</div>");
        var compliantCount = report.ComplianceItems.Count(i => i.Status == CraComplianceStatus.Compliant);
        sb.AppendLine($"    <div class=\"status-detail\">{compliantCount}/{report.ComplianceItems.Count} requirements met</div>");
        sb.AppendLine("  </div>");

        // Summary Cards
        var totalPackages = report.PackageCount + report.TransitivePackageCount;
        sb.AppendLine("  <div class=\"card metric-card\" title=\"Total number of direct and transitive (indirect) dependencies in your project. Each package increases your supply chain attack surface.\">");
        sb.AppendLine($"    <div class=\"metric-value\">{totalPackages}</div>");
        sb.AppendLine($"    <div class=\"metric-label\">Total Packages</div>");
        sb.AppendLine($"    <div class=\"metric-detail\">{report.PackageCount} direct + {report.TransitivePackageCount} transitive</div>");
        sb.AppendLine("  </div>");

        sb.AppendLine("  <div class=\"card metric-card\" title=\"Known security vulnerabilities found in your dependencies by scanning the OSV (Open Source Vulnerabilities) database.\">");
        sb.AppendLine($"    <div class=\"metric-value {(report.VulnerabilityCount > 0 ? "critical" : "")}\">{report.VulnerabilityCount}</div>");
        sb.AppendLine("    <div class=\"metric-label\">Vulnerabilities</div>");
        sb.AppendLine("  </div>");

        sb.AppendLine("  <div class=\"card metric-card\" title=\"Packages with severe issues: known exploited vulnerabilities (CISA KEV), critical CVSS scores, or high EPSS exploit probability.\">");
        sb.AppendLine($"    <div class=\"metric-value {(report.CriticalPackageCount > 0 ? "critical" : "")}\">{report.CriticalPackageCount}</div>");
        sb.AppendLine("    <div class=\"metric-label\">Critical Packages</div>");
        sb.AppendLine("  </div>");

        sb.AppendLine("  <div class=\"card metric-card\" title=\"Cases where different packages require different versions of the same dependency, which can cause runtime issues.\">");
        sb.AppendLine($"    <div class=\"metric-value {(report.VersionConflictCount > 0 ? "warning" : "")}\">{report.VersionConflictCount}</div>");
        sb.AppendLine("    <div class=\"metric-label\">Version Conflicts</div>");
        sb.AppendLine("  </div>");

        // License Summary Card (using cached license data)
        var licenseReport = _licenseReportCache ??= LicenseCompatibility.AnalyzeLicenses(GetPackageLicenses());
        var licenseStatusClass = licenseReport.OverallStatus switch
        {
            "Compatible" => "healthy",
            "Review Recommended" => "warning",
            _ => "critical"
        };
        var unknownCount = licenseReport.CategoryDistribution.GetValueOrDefault(LicenseCategory.Unknown, 0);

        sb.AppendLine($"  <div class=\"card metric-card license-card\" onclick=\"showSection('licenses')\" style=\"cursor: pointer;\" title=\"License compatibility analysis across all dependencies. Checks for copyleft conflicts, unknown licenses, and compliance risks. Click to view details.\">");
        sb.AppendLine($"    <div class=\"metric-value {licenseStatusClass}\">{(licenseReport.ErrorCount == 0 ? "\u2713" : licenseReport.ErrorCount.ToString())}</div>");
        sb.AppendLine($"    <div class=\"metric-label\">License Status</div>");
        sb.AppendLine($"    <div class=\"metric-detail\">{licenseReport.OverallStatus}{(unknownCount > 0 ? $" ({unknownCount} unknown)" : "")}</div>");
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
        sb.AppendLine("  <span class=\"filter-group\">");
        sb.AppendLine("    <span class=\"filter-label\">Sort:</span>");
        sb.AppendLine("    <button class=\"filter-btn sort-btn\" onclick=\"sortPackages('name')\">Name</button>");
        sb.AppendLine("    <button class=\"filter-btn sort-btn active\" onclick=\"sortPackages('health')\">Health</button>");
        sb.AppendLine("    <button class=\"filter-btn sort-btn\" onclick=\"sortPackages('cra')\">CRA</button>");
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
        foreach (var pkg in report.Sbom.Packages.Skip(1).Where(p => directPackageIds.Contains(p.Name)).OrderBy(p => p.Name, StringComparer.OrdinalIgnoreCase))
        {
            var pkgName = pkg.Name;
            var pkgNameLower = pkgName.ToLowerInvariant();
            var version = pkg.VersionInfo;
            var score = 70; // Default score
            var status = "watch";

            // Find matching health data
            var healthData = _healthDataCache is not null ? _healthLookup.GetValueOrDefault(pkgName) : null;
            var ecosystemAttr = "nuget"; // Default for data attribute
            if (healthData != null)
            {
                score = healthData.Score;
                status = StatusToLower(healthData.Status);
                ecosystemAttr = healthData.Ecosystem == PackageEcosystem.Npm ? "npm" : "nuget";
            }

            var hasKev = _kevPackageIds.Contains(pkgName);
            var kevClass = hasKev ? " has-kev" : "";
            var craScore = healthData?.CraScore ?? 0;
            var craTooltip = GetCraBadgeTooltip(healthData);
            sb.AppendLine($"  <div class=\"package-card{kevClass}\" id=\"pkg-{EscapeHtml(pkgName)}\" data-status=\"{status}\" data-name=\"{EscapeHtml(pkgNameLower)}\" data-ecosystem=\"{ecosystemAttr}\" data-health=\"{score}\" data-cra=\"{craScore}\">");
            sb.AppendLine("    <div class=\"package-header\" onclick=\"togglePackage(this)\">");
            sb.AppendLine($"      <div class=\"package-info\">");
            sb.AppendLine($"        <span class=\"package-name\">{EscapeHtml(pkgName)}</span>");
            if (hasKev && healthData?.KevCves.Count > 0)
            {
                var kevCve = healthData.KevCves[0];
                var kevUrl = $"https://osv.dev/vulnerability/{Uri.EscapeDataString(kevCve)}";
                var kevTooltip = $"{kevCve} - Known Exploited Vulnerability (click for details)";
                sb.AppendLine($"        <a href=\"{EscapeHtml(kevUrl)}\" target=\"_blank\" class=\"kev-badge\" title=\"{EscapeHtml(kevTooltip)}\" onclick=\"event.stopPropagation()\">{EscapeHtml(kevCve)}</a>");
            }
            else if (hasKev)
            {
                sb.AppendLine($"        <span class=\"kev-badge\" title=\"Known Exploited Vulnerability - actively exploited in the wild\">KEV</span>");
            }
            if (healthData?.MaxEpssProbability is > 0 and var epssDirect)
            {
                var epssClass = GetEpssBadgeClass(epssDirect);
                var epssPct = (epssDirect * 100).ToString("F1");
                sb.AppendLine($"        <span class=\"epss-badge {epssClass}\" title=\"EPSS: {epssPct}% probability of exploitation in 30 days\">EPSS {epssPct}%</span>");
            }
            sb.AppendLine($"        <span class=\"package-version\">{FormatVersion(version, pkgName)}</span>");
            sb.AppendLine($"        <span class=\"dep-type-badge direct\" title=\"Direct dependency - referenced in your project file\">direct</span>");
            sb.AppendLine($"      </div>");
            sb.AppendLine($"      <div class=\"package-scores\">");
            sb.AppendLine($"        <div class=\"package-score-item score-clickable\" onclick=\"showScorePopover(event, '{EscapeHtml(pkgName)}', 'health')\" title=\"Health Score - freshness, activity, and maintenance \u2014 click for breakdown\">");
            sb.AppendLine($"          <span class=\"score-label\">HEALTH</span>");
            sb.AppendLine($"          <span class=\"score-value {GetScoreClass(score)}\">{score}</span>");
            sb.AppendLine($"        </div>");
            sb.AppendLine($"        <div class=\"package-score-item score-clickable\" onclick=\"showScorePopover(event, '{EscapeHtml(pkgName)}', 'cra')\" title=\"{EscapeHtml(craTooltip)} \u2014 click for breakdown\">");
            sb.AppendLine($"          <span class=\"score-label\">CRA</span>");
            sb.AppendLine($"          <span class=\"score-value {GetCraScoreClass(craScore)}\">{craScore}</span>");
            sb.AppendLine($"        </div>");
            // Trust score (only when data available)
            if (healthData?.MaintainerTrust is not null)
            {
                var trustScore = healthData.MaintainerTrust.Score;
                var trustClass = GetTrustScoreClass(trustScore);
                sb.AppendLine($"        <div class=\"package-score-item\" title=\"Maintainer Trust \u2014 contributor diversity, release discipline, community health\">");
                sb.AppendLine($"          <span class=\"score-label\">TRUST</span>");
                sb.AppendLine($"          <span class=\"score-value {trustClass}\">{trustScore}</span>");
                sb.AppendLine($"        </div>");
            }
            sb.AppendLine($"      </div>");
            sb.AppendLine($"      <span class=\"expand-icon\">+</span>");
            sb.AppendLine("    </div>");
            // Empty details container - content loaded lazily via JavaScript from packageData
            sb.AppendLine("    <div class=\"package-details\"></div>");
            sb.AppendLine("  </div>");
        }

        sb.AppendLine("</div>");

        // Transitive Dependencies Section (uses cached _actualTransitives, excluding sub-dependencies)
        if (_actualTransitives.Count > 0)
        {
            sb.AppendLine("<div class=\"transitive-section\">");
            sb.AppendLine("  <div class=\"transitive-header\" onclick=\"toggleTransitive()\">");
            sb.AppendLine($"    <h3>Transitive Dependencies ({_actualTransitives.Count})</h3>");
            sb.AppendLine("    <span class=\"transitive-toggle\" id=\"transitive-toggle\">Show</span>");
            sb.AppendLine("  </div>");
            sb.AppendLine("  <div id=\"transitive-list\" class=\"packages-list transitive-list\" style=\"display: none;\">");

            foreach (var healthData in _actualTransitives.OrderBy(h => h.PackageId, StringComparer.OrdinalIgnoreCase))
            {
                var pkgName = healthData.PackageId;
                var pkgNameLower = pkgName.ToLowerInvariant();
                var version = healthData.Version;
                var score = healthData.Score;
                var status = StatusToLower(healthData.Status);

                var ecosystemName = healthData.Ecosystem == PackageEcosystem.Npm ? "npm" : "NuGet";
                var depTypeBadge = $"<span class=\"dep-type-badge transitive\" title=\"Transitive dependency - pulled in by {ecosystemName} dependency resolution\">transitive</span>";

                var ecosystemAttr = healthData.Ecosystem == PackageEcosystem.Npm ? "npm" : "nuget";

                // Check if we have real health data (not just defaults)
                var hasRealHealthData = healthData.Metrics.TotalDownloads > 0 ||
                                        healthData.Metrics.DaysSinceLastRelease.HasValue ||
                                        healthData.Metrics.ReleasesPerYear > 0;

                var hasKevTrans = _kevPackageIds.Contains(pkgName);
                var kevClassTrans = hasKevTrans ? " has-kev" : "";
                var craScoreTrans = healthData.CraScore;
                var craTooltipTrans = GetCraBadgeTooltip(healthData);
                sb.AppendLine($"  <div class=\"package-card transitive{kevClassTrans}\" id=\"pkg-{EscapeHtml(pkgName)}\" data-status=\"{status}\" data-name=\"{EscapeHtml(pkgNameLower)}\" data-ecosystem=\"{ecosystemAttr}\" data-health=\"{score}\" data-cra=\"{craScoreTrans}\">");
                sb.AppendLine("    <div class=\"package-header\" onclick=\"togglePackage(this)\">");
                sb.AppendLine($"      <div class=\"package-info\">");
                sb.AppendLine($"        <span class=\"package-name\">{EscapeHtml(pkgName)}</span>");
                if (hasKevTrans && healthData.KevCves.Count > 0)
                {
                    var kevCve = healthData.KevCves[0];
                    var kevUrl = $"https://osv.dev/vulnerability/{Uri.EscapeDataString(kevCve)}";
                    var kevTooltip = $"{kevCve} - Known Exploited Vulnerability (click for details)";
                    sb.AppendLine($"        <a href=\"{EscapeHtml(kevUrl)}\" target=\"_blank\" class=\"kev-badge\" title=\"{EscapeHtml(kevTooltip)}\" onclick=\"event.stopPropagation()\">{EscapeHtml(kevCve)}</a>");
                }
                else if (hasKevTrans)
                {
                    sb.AppendLine($"        <span class=\"kev-badge\" title=\"Known Exploited Vulnerability - actively exploited in the wild\">KEV</span>");
                }
                if (healthData.MaxEpssProbability is > 0 and var epssTrans)
                {
                    var epssClass = GetEpssBadgeClass(epssTrans);
                    var epssPct = (epssTrans * 100).ToString("F1");
                    sb.AppendLine($"        <span class=\"epss-badge {epssClass}\" title=\"EPSS: {epssPct}% probability of exploitation in 30 days\">EPSS {epssPct}%</span>");
                }
                sb.AppendLine($"        <span class=\"package-version\">{FormatVersion(version, pkgName)}</span>");
                sb.AppendLine($"        {depTypeBadge}");
                sb.AppendLine($"      </div>");
                sb.AppendLine($"      <div class=\"package-scores\">");
                if (hasRealHealthData)
                {
                    sb.AppendLine($"        <div class=\"package-score-item score-clickable\" onclick=\"showScorePopover(event, '{EscapeHtml(pkgName)}', 'health')\" title=\"Health Score - freshness &amp; activity \u2014 click for breakdown\">");
                    sb.AppendLine($"          <span class=\"score-label\">HEALTH</span>");
                    sb.AppendLine($"          <span class=\"score-value {GetScoreClass(score)}\">{score}</span>");
                    sb.AppendLine($"        </div>");
                }
                else
                {
                    sb.AppendLine($"        <div class=\"package-score-item\" title=\"Health Score not available - use --deep for full analysis\">");
                    sb.AppendLine($"          <span class=\"score-label\">HEALTH</span>");
                    sb.AppendLine($"          <span class=\"score-value na\">\u2014</span>");
                    sb.AppendLine($"        </div>");
                }
                sb.AppendLine($"        <div class=\"package-score-item score-clickable\" onclick=\"showScorePopover(event, '{EscapeHtml(pkgName)}', 'cra')\" title=\"{EscapeHtml(craTooltipTrans)} \u2014 click for breakdown\">");
                sb.AppendLine($"          <span class=\"score-label\">CRA</span>");
                sb.AppendLine($"          <span class=\"score-value {GetCraScoreClass(craScoreTrans)}\">{craScoreTrans}</span>");
                sb.AppendLine($"        </div>");
                // Trust score (only when data available)
                if (healthData.MaintainerTrust is not null)
                {
                    var trustScore = healthData.MaintainerTrust.Score;
                    var trustClass = GetTrustScoreClass(trustScore);
                    sb.AppendLine($"        <div class=\"package-score-item\" title=\"Maintainer Trust \u2014 contributor diversity, release discipline, community health\">");
                    sb.AppendLine($"          <span class=\"score-label\">TRUST</span>");
                    sb.AppendLine($"          <span class=\"score-value {trustClass}\">{trustScore}</span>");
                    sb.AppendLine($"        </div>");
                }
                sb.AppendLine($"      </div>");
                sb.AppendLine($"      <span class=\"expand-icon\">+</span>");
                sb.AppendLine("    </div>");
                // Empty details container - content loaded lazily via JavaScript from packageData
                sb.AppendLine("    <div class=\"package-details\"></div>");
                sb.AppendLine("  </div>");
            }

            sb.AppendLine("  </div>");
            sb.AppendLine("</div>");
        }

        // Sub-Dependencies Section
        if (_subDependencies.Count > 0)
        {
            sb.AppendLine("<div class=\"transitive-section\">");
            sb.AppendLine("  <div class=\"transitive-header\" onclick=\"toggleSubDeps()\">");
            sb.AppendLine($"    <h3>Sub-Dependencies ({_subDependencies.Count})</h3>");
            sb.AppendLine("    <span class=\"transitive-toggle\" id=\"subdeps-toggle\">Show</span>");
            sb.AppendLine("  </div>");
            sb.AppendLine("  <div id=\"subdeps-list\" class=\"packages-list transitive-list\" style=\"display: none;\">");

            foreach (var healthData in _subDependencies.OrderBy(h => h.PackageId, StringComparer.OrdinalIgnoreCase))
            {
                var pkgName = healthData.PackageId;
                var pkgNameLower = pkgName.ToLowerInvariant();
                var version = healthData.Version;
                var score = healthData.Score;
                var status = StatusToLower(healthData.Status);

                var ecosystemName = healthData.Ecosystem == PackageEcosystem.Npm ? "npm" : "NuGet";
                var depTypeBadge = $"<span class=\"dep-type-badge transitive\" title=\"Sub-dependency - indirect dependency pulled in through the {ecosystemName} dependency tree\">sub-dep</span>";

                var ecosystemAttr = healthData.Ecosystem == PackageEcosystem.Npm ? "npm" : "nuget";

                var hasRealHealthData = healthData.Metrics.TotalDownloads > 0 ||
                                        healthData.Metrics.DaysSinceLastRelease.HasValue ||
                                        healthData.Metrics.ReleasesPerYear > 0;

                var hasKevSub = _kevPackageIds.Contains(pkgName);
                var kevClassSub = hasKevSub ? " has-kev" : "";
                var craScoreSub = healthData.CraScore;
                var craTooltipSub = GetCraBadgeTooltip(healthData);
                sb.AppendLine($"  <div class=\"package-card transitive{kevClassSub}\" id=\"pkg-{EscapeHtml(pkgName)}\" data-status=\"{status}\" data-name=\"{EscapeHtml(pkgNameLower)}\" data-ecosystem=\"{ecosystemAttr}\" data-health=\"{score}\" data-cra=\"{craScoreSub}\">");
                sb.AppendLine("    <div class=\"package-header\" onclick=\"togglePackage(this)\">");
                sb.AppendLine($"      <div class=\"package-info\">");
                sb.AppendLine($"        <span class=\"package-name\">{EscapeHtml(pkgName)}</span>");
                if (hasKevSub && healthData.KevCves.Count > 0)
                {
                    var kevCve = healthData.KevCves[0];
                    var kevUrl = $"https://osv.dev/vulnerability/{Uri.EscapeDataString(kevCve)}";
                    var kevTooltip = $"{kevCve} - Known Exploited Vulnerability (click for details)";
                    sb.AppendLine($"        <a href=\"{EscapeHtml(kevUrl)}\" target=\"_blank\" class=\"kev-badge\" title=\"{EscapeHtml(kevTooltip)}\" onclick=\"event.stopPropagation()\">{EscapeHtml(kevCve)}</a>");
                }
                else if (hasKevSub)
                {
                    sb.AppendLine($"        <span class=\"kev-badge\" title=\"Known Exploited Vulnerability - actively exploited in the wild\">KEV</span>");
                }
                if (healthData.MaxEpssProbability is > 0 and var epssSub)
                {
                    var epssClass = GetEpssBadgeClass(epssSub);
                    var epssPct = (epssSub * 100).ToString("F1");
                    sb.AppendLine($"        <span class=\"epss-badge {epssClass}\" title=\"EPSS: {epssPct}% probability of exploitation in 30 days\">EPSS {epssPct}%</span>");
                }
                sb.AppendLine($"        <span class=\"package-version\">{FormatVersion(version, pkgName)}</span>");
                sb.AppendLine($"        {depTypeBadge}");
                sb.AppendLine($"      </div>");
                sb.AppendLine($"      <div class=\"package-scores\">");
                if (hasRealHealthData)
                {
                    sb.AppendLine($"        <div class=\"package-score-item score-clickable\" onclick=\"showScorePopover(event, '{EscapeHtml(pkgName)}', 'health')\" title=\"Health Score - freshness &amp; activity \u2014 click for breakdown\">");
                    sb.AppendLine($"          <span class=\"score-label\">HEALTH</span>");
                    sb.AppendLine($"          <span class=\"score-value {GetScoreClass(score)}\">{score}</span>");
                    sb.AppendLine($"        </div>");
                }
                else
                {
                    sb.AppendLine($"        <div class=\"package-score-item\" title=\"Health Score not available - use --deep for full analysis\">");
                    sb.AppendLine($"          <span class=\"score-label\">HEALTH</span>");
                    sb.AppendLine($"          <span class=\"score-value na\">\u2014</span>");
                    sb.AppendLine($"        </div>");
                }
                sb.AppendLine($"        <div class=\"package-score-item score-clickable\" onclick=\"showScorePopover(event, '{EscapeHtml(pkgName)}', 'cra')\" title=\"{EscapeHtml(craTooltipSub)} \u2014 click for breakdown\">");
                sb.AppendLine($"          <span class=\"score-label\">CRA</span>");
                sb.AppendLine($"          <span class=\"score-value {GetCraScoreClass(craScoreSub)}\">{craScoreSub}</span>");
                sb.AppendLine($"        </div>");
                // Trust score (only when data available)
                if (healthData.MaintainerTrust is not null)
                {
                    var trustScore = healthData.MaintainerTrust.Score;
                    var trustClass = GetTrustScoreClass(trustScore);
                    sb.AppendLine($"        <div class=\"package-score-item\" title=\"Maintainer Trust \u2014 contributor diversity, release discipline, community health\">");
                    sb.AppendLine($"          <span class=\"score-label\">TRUST</span>");
                    sb.AppendLine($"          <span class=\"score-value {trustClass}\">{trustScore}</span>");
                    sb.AppendLine($"        </div>");
                }
                sb.AppendLine($"      </div>");
                sb.AppendLine($"      <span class=\"expand-icon\">+</span>");
                sb.AppendLine("    </div>");
                sb.AppendLine("    <div class=\"package-details\"></div>");
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
            var pkgNameLower = pkg.Name.ToLowerInvariant();
            sb.AppendLine($"    <tr data-name=\"{EscapeHtml(pkgNameLower)}\">");
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

        // Use cached license data
        var licenseReport = _licenseReportCache ??= LicenseCompatibility.AnalyzeLicenses(GetPackageLicenses());

        // Status banner
        var statusClass = licenseReport.OverallStatus switch
        {
            "Compatible" => "healthy",
            "Review Recommended" => "warning",
            _ => "critical"
        };
        sb.AppendLine($"<div class=\"license-status {statusClass}\">");
        sb.AppendLine($"  <span class=\"status-icon\">{(licenseReport.ErrorCount == 0 ? "\u2713" : "\u26A0")}</span>");
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
                    LicenseCategory.Permissive => "permissive",
                    LicenseCategory.WeakCopyleft => "weak-copyleft",
                    LicenseCategory.StrongCopyleft => "strong-copyleft",
                    LicenseCategory.PublicDomain => "public-domain",
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
                    LicenseCategory.Permissive => "permissive",
                    LicenseCategory.WeakCopyleft => "weak-copyleft",
                    LicenseCategory.StrongCopyleft => "strong-copyleft",
                    LicenseCategory.PublicDomain => "public-domain",
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
                LicenseCategory.Permissive => "permissive",
                LicenseCategory.WeakCopyleft => "weak-copyleft",
                LicenseCategory.StrongCopyleft => "strong-copyleft",
                LicenseCategory.PublicDomain => "public-domain",
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

        // Compatibility matrix
        GenerateCompatibilityMatrix(sb, licenseReport);

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

    private static void GenerateCompatibilityMatrix(StringBuilder sb, LicenseReport licenseReport)
    {
        // Determine the project license category for row highlighting
        var projectLicenseInfo = LicenseCompatibility.GetLicenseInfo(licenseReport.ProjectLicense);
        var projectCategory = projectLicenseInfo?.Category;

        sb.AppendLine("<div class=\"compatibility-matrix\">");
        sb.AppendLine("  <h3>Compatibility Matrix</h3>");
        sb.AppendLine("  <p>Reference guide showing which dependency license categories are compatible with your project license. ");
        if (licenseReport.ProjectLicense is not null)
            sb.AppendLine($"Your project license (<strong>{EscapeHtml(licenseReport.ProjectLicense)}</strong>) is highlighted.");
        sb.AppendLine("</p>");

        sb.AppendLine("  <table class=\"matrix-table\">");
        sb.AppendLine("    <thead>");
        sb.AppendLine("      <tr>");
        sb.AppendLine("        <th>Your Project License</th>");
        sb.AppendLine("        <th>Public Domain</th>");
        sb.AppendLine("        <th>Permissive</th>");
        sb.AppendLine("        <th>Weak Copyleft</th>");
        sb.AppendLine("        <th>Strong Copyleft</th>");
        sb.AppendLine("      </tr>");
        sb.AppendLine("    </thead>");
        sb.AppendLine("    <tbody>");

        // Row: Permissive (MIT, Apache-2.0, BSD, ISC)
        var permActive = projectCategory is LicenseCategory.Permissive
            or LicenseCategory.PublicDomain;
        sb.AppendLine($"      <tr{(permActive ? " class=\"active-row\"" : "")}>");
        sb.AppendLine("        <td>Permissive<span class=\"matrix-label\">MIT, Apache-2.0, BSD, ISC</span></td>");
        sb.AppendLine("        <td><span class=\"matrix-cell-ok\">\u2713</span></td>");
        sb.AppendLine("        <td><span class=\"matrix-cell-ok\">\u2713</span></td>");
        sb.AppendLine("        <td><span class=\"matrix-cell-warn\">\u26A0</span><span class=\"matrix-label\">Modifications must be shared</span></td>");
        sb.AppendLine("        <td><span class=\"matrix-cell-no\">\u2716</span><span class=\"matrix-label\">Requires relicensing</span></td>");
        sb.AppendLine("      </tr>");

        // Row: Weak Copyleft (LGPL, MPL, EPL)
        var weakActive = projectCategory == LicenseCategory.WeakCopyleft;
        sb.AppendLine($"      <tr{(weakActive ? " class=\"active-row\"" : "")}>");
        sb.AppendLine("        <td>Weak Copyleft<span class=\"matrix-label\">LGPL, MPL, EPL</span></td>");
        sb.AppendLine("        <td><span class=\"matrix-cell-ok\">\u2713</span></td>");
        sb.AppendLine("        <td><span class=\"matrix-cell-ok\">\u2713</span></td>");
        sb.AppendLine("        <td><span class=\"matrix-cell-warn\">\u26A0</span><span class=\"matrix-label\">Modifications must be shared</span></td>");
        sb.AppendLine("        <td><span class=\"matrix-cell-no\">\u2716</span><span class=\"matrix-label\">Requires relicensing</span></td>");
        sb.AppendLine("      </tr>");

        // Row: Strong Copyleft (GPL)
        var strongActive = projectCategory == LicenseCategory.StrongCopyleft;
        sb.AppendLine($"      <tr{(strongActive ? " class=\"active-row\"" : "")}>");
        sb.AppendLine("        <td>Strong Copyleft<span class=\"matrix-label\">GPL-2.0, GPL-3.0, AGPL-3.0</span></td>");
        sb.AppendLine("        <td><span class=\"matrix-cell-ok\">\u2713</span></td>");
        sb.AppendLine("        <td><span class=\"matrix-cell-ok\">\u2713</span></td>");
        sb.AppendLine("        <td><span class=\"matrix-cell-ok\">\u2713</span></td>");
        sb.AppendLine("        <td><span class=\"matrix-cell-ok\">\u2713</span><span class=\"matrix-label\">Compatible copyleft</span></td>");
        sb.AppendLine("      </tr>");

        sb.AppendLine("    </tbody>");
        sb.AppendLine("  </table>");
        sb.AppendLine("</div>");
    }

    private void GenerateVulnerabilitiesSection(StringBuilder sb, CraReport report)
    {
        sb.AppendLine("<div class=\"section-header\">");
        sb.AppendLine("  <h2>Vulnerability Status (VEX)</h2>");
        sb.AppendLine("</div>");

        var statements = report.Vex.Statements;
        // Single pass partition instead of dual Where() filters
        var affectedStatements = new List<VexStatement>();
        var safeStatements = new List<VexStatement>();
        foreach (var s in statements)
        {
            (s.Status == VexStatus.Affected ? affectedStatements : safeStatements).Add(s);
        }

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

            // EPSS scores for each CVE
            var cveEpssEntries = new List<EpssScore>();
            foreach (var cve in stmt.Vulnerability.Aliases)
            {
                if (_epssScores.TryGetValue(cve, out var score) && score.Probability > 0)
                    cveEpssEntries.Add(score);
            }
            cveEpssEntries.Sort((a, b) => b.Probability.CompareTo(a.Probability));

            if (cveEpssEntries.Count > 0)
            {
                sb.AppendLine("    <div class=\"vuln-epss\">");
                sb.AppendLine("      <strong>EPSS (Exploit Probability):</strong>");
                foreach (var epss in cveEpssEntries)
                {
                    var pct = (epss.Probability * 100).ToString("F1");
                    var percentile = (int)(epss.Percentile * 100);
                    var badgeClass = GetEpssBadgeClass(epss.Probability);
                    sb.AppendLine($"      <span class=\"epss-badge {badgeClass}\" title=\"{EscapeHtml(epss.Cve)}: {pct}% chance of exploitation in 30 days (percentile: {percentile})\">{EscapeHtml(epss.Cve)} {pct}% <small>p{percentile}</small></span>");
                }
                sb.AppendLine("    </div>");
            }
        }
        sb.AppendLine("  </div>");
    }

    // =============================================
    // v1.2 CRA Detail Sections
    // =============================================

    private void GenerateRemediationSection(StringBuilder sb)
    {
        sb.AppendLine("<div class=\"section-header\">");
        sb.AppendLine("  <h2>Remediation Actions</h2>");
        sb.AppendLine("</div>");

        sb.AppendLine("<div class=\"info-box\">");
        sb.AppendLine("  <div class=\"info-box-title\">What is this?</div>");
        sb.AppendLine("  <p>These are known security vulnerabilities in your dependencies that already have a fix available &mdash; you just need to update the package version. The <strong>Days Overdue</strong> column shows how long the fix has been available but not applied.</p>");
        sb.AppendLine("  <p style=\"margin-top:8px;\"><strong>What to do:</strong> Run <code>dotnet add package [name] --version [patch version]</code> or update your <code>package.json</code> to the patched version shown below. Prioritize packages marked in red first.</p>");
        sb.AppendLine("</div>");

        var sorted = _remediationData.OrderByDescending(r => r.DaysSince).ToList();

        sb.AppendLine("<table class=\"detail-table\">");
        sb.AppendLine("  <thead><tr>");
        sb.AppendLine("    <th title=\"The package that contains the vulnerability\">Package</th>");
        sb.AppendLine("    <th title=\"The vulnerability identifier &mdash; search this on osv.dev for full details\">Vulnerability</th>");
        sb.AppendLine("    <th title=\"Update to this version to fix the vulnerability\">Update To</th>");
        sb.AppendLine("    <th title=\"How many days this fix has been available. Red = 30+ days, Yellow = 7-29 days\">Days Overdue</th>");
        sb.AppendLine("  </tr></thead>");
        sb.AppendLine("  <tbody>");

        foreach (var item in sorted)
        {
            var urgencyClass = item.DaysSince >= 30 ? "critical" : item.DaysSince >= 7 ? "warning" : "ok";
            sb.AppendLine("    <tr>");
            sb.AppendLine($"      <td><strong>{EscapeHtml(item.PackageId)}</strong></td>");
            sb.AppendLine($"      <td><a href=\"https://osv.dev/vulnerability/{EscapeHtml(item.VulnId)}\" target=\"_blank\" style=\"color:var(--accent);text-decoration:none;\"><code>{EscapeHtml(item.VulnId)}</code></a></td>");
            sb.AppendLine($"      <td><code>{EscapeHtml(item.PatchVersion)}</code></td>");
            sb.AppendLine($"      <td><span class=\"days-overdue {urgencyClass}\">{item.DaysSince} days</span></td>");
            sb.AppendLine("    </tr>");
        }

        sb.AppendLine("  </tbody>");
        sb.AppendLine("</table>");
    }

    private void GenerateReportingObligationsSection(StringBuilder sb)
    {
        sb.AppendLine("<div class=\"section-header\">");
        sb.AppendLine("  <h2>CRA Art. 14 \u2014 Reporting Obligations</h2>");
        sb.AppendLine("</div>");

        if (_reportingObligations.Count == 0)
        {
            sb.AppendLine("<div class=\"card empty-state success\">");
            sb.AppendLine("  <div class=\"empty-icon\">\u2713</div>");
            sb.AppendLine("  <h3>No Reportable Vulnerabilities Detected</h3>");
            sb.AppendLine("  <p>None of your dependencies contain vulnerabilities that trigger CRA Art. 14 reporting obligations. Reporting is required when a vulnerability appears in the <strong>CISA KEV catalog</strong> (confirmed active exploitation) or has an <strong>EPSS probability \u2265 0.5</strong> (high likelihood of exploitation within 30 days).</p>");
            sb.AppendLine("  <p style=\"margin-top:8px;\">This is a positive finding \u2014 no CSIRT notification is currently required under Art. 14.</p>");
            sb.AppendLine("</div>");
            return;
        }

        sb.AppendLine("<div class=\"info-box\" style=\"border-left-color:var(--danger);\">");
        sb.AppendLine("  <div class=\"info-box-title\" style=\"color:var(--danger);\">Urgent: CSIRT Notification Required</div>");
        sb.AppendLine("  <p>EU Cyber Resilience Act <strong>Article 14</strong> requires manufacturers to notify their designated CSIRT when they become aware of an actively exploited vulnerability in their product. The timeline is:</p>");
        sb.AppendLine("  <ul style=\"margin:8px 0 0 16px;line-height:1.8;\">");
        sb.AppendLine("    <li><strong>24 hours</strong> \u2014 Early warning to CSIRT (Art. 14(2)(a))</li>");
        sb.AppendLine("    <li><strong>72 hours</strong> \u2014 Full vulnerability notification with details and mitigations (Art. 14(2)(b))</li>");
        sb.AppendLine("    <li><strong>14 days</strong> \u2014 Final report including root cause and corrective measures (Art. 14(2)(c))</li>");
        sb.AppendLine("  </ul>");
        sb.AppendLine("  <p style=\"margin-top:8px;\"><strong>Detection criteria:</strong> A vulnerability is flagged as reportable if it appears in the <strong>CISA KEV catalog</strong> (confirmed active exploitation) or has an <strong>EPSS probability \u2265 0.5</strong> (high likelihood of exploitation within 30 days).</p>");
        sb.AppendLine("</div>");

        sb.AppendLine("<table class=\"detail-table\">");
        sb.AppendLine("  <thead><tr>");
        sb.AppendLine("    <th>Package</th>");
        sb.AppendLine("    <th>CVE(s)</th>");
        sb.AppendLine("    <th>Trigger</th>");
        sb.AppendLine("    <th>Severity</th>");
        sb.AppendLine("    <th title=\"Art. 14(2)(a) \u2014 Early warning deadline\">24h Deadline</th>");
        sb.AppendLine("    <th title=\"Art. 14(2)(b) \u2014 Full notification deadline\">72h Deadline</th>");
        sb.AppendLine("    <th title=\"Art. 14(2)(c) \u2014 Final report deadline\">14d Deadline</th>");
        sb.AppendLine("  </tr></thead>");
        sb.AppendLine("  <tbody>");

        foreach (var item in _reportingObligations)
        {
            var triggerBadge = item.Trigger switch
            {
                ReportingTrigger.Both => "<span class=\"reporting-obligation-badge both\">KEV + EPSS</span>",
                ReportingTrigger.KevExploitation => "<span class=\"reporting-obligation-badge kev\">KEV</span>",
                _ => "<span class=\"reporting-obligation-badge epss\">EPSS \u2265 0.5</span>"
            };

            var severityClass = item.Severity.ToUpperInvariant() switch
            {
                "CRITICAL" => "critical",
                "HIGH" => "warning",
                _ => "ok"
            };

            var now = DateTime.UtcNow;
            string FormatDeadline(DateTime deadline)
            {
                var overdue = now > deadline;
                var cls = overdue ? "reporting-deadline urgent" : "reporting-deadline";
                var label = overdue ? $"{(int)(now - deadline).TotalDays}d OVERDUE" : deadline.ToString("yyyy-MM-dd HH:mm");
                return $"<span class=\"{cls}\">{label}</span>";
            }

            var cveLinks = string.Join(", ", item.CveIds.Take(3).Select(cve =>
                $"<a href=\"https://nvd.nist.gov/vuln/detail/{EscapeHtml(cve)}\" target=\"_blank\" style=\"color:var(--accent);text-decoration:none;\"><code>{EscapeHtml(cve)}</code></a>"));
            if (item.CveIds.Count > 3)
                cveLinks += $" <span class=\"text-secondary\">+{item.CveIds.Count - 3} more</span>";

            sb.AppendLine("    <tr>");
            sb.AppendLine($"      <td><strong>{EscapeHtml(item.PackageId)}</strong><br/><span style=\"font-size:0.85em;color:var(--text-secondary);\">{EscapeHtml(item.Version)}</span></td>");
            sb.AppendLine($"      <td>{cveLinks}</td>");
            sb.AppendLine($"      <td>{triggerBadge}</td>");
            sb.AppendLine($"      <td><span class=\"days-overdue {severityClass}\">{EscapeHtml(item.Severity)}</span></td>");
            sb.AppendLine($"      <td>{FormatDeadline(item.EarlyWarningDeadline)}</td>");
            sb.AppendLine($"      <td>{FormatDeadline(item.FullNotificationDeadline)}</td>");
            sb.AppendLine($"      <td>{FormatDeadline(item.FinalReportDeadline)}</td>");
            sb.AppendLine("    </tr>");
        }

        sb.AppendLine("  </tbody>");
        sb.AppendLine("</table>");
    }

    private void GenerateRemediationRoadmapSection(StringBuilder sb)
    {
        sb.AppendLine("<div class=\"section-header\">");
        sb.AppendLine("  <h2>Remediation Roadmap</h2>");
        sb.AppendLine("</div>");

        if (_remediationRoadmap.Count == 0)
        {
            sb.AppendLine("<div class=\"card empty-state success\">");
            sb.AppendLine("  <div class=\"empty-icon\">\u2713</div>");
            sb.AppendLine("  <h3>No Remediation Actions Required</h3>");
            sb.AppendLine("  <p>None of your dependencies have known vulnerabilities that affect the installed versions. There are no package updates needed to improve your CRA compliance posture at this time.</p>");
            sb.AppendLine("  <p style=\"margin-top:8px;\">The remediation roadmap will display prioritized update recommendations when vulnerable packages are detected, ranked by their impact on your CRA readiness score.</p>");
            sb.AppendLine("</div>");
            return;
        }

        sb.AppendLine("<div class=\"info-box\">");
        sb.AppendLine("  <div class=\"info-box-title\">Prioritized Update Plan</div>");
        sb.AppendLine("  <p>This roadmap ranks your vulnerable dependencies by their <strong>impact on CRA compliance</strong>. Packages are prioritized by: actively exploited (CISA KEV) first, then high EPSS probability, then by vulnerability severity and estimated CRA score improvement.</p>");
        sb.AppendLine("  <p style=\"margin-top:8px;\"><strong>Score Lift</strong> estimates how much your CRA readiness score would improve if you fix that package. <strong>Upgrade Options</strong> show available fix paths at each semver tier \u2014 the \u2713 marks the recommended (lowest-risk) option. Alternative tiers are shown when fixes exist at different semver levels.</p>");
        sb.AppendLine("</div>");

        sb.AppendLine("<table class=\"detail-table\">");
        sb.AppendLine("  <thead><tr>");
        sb.AppendLine("    <th>#</th>");
        sb.AppendLine("    <th>Package</th>");
        sb.AppendLine("    <th>Upgrade Options</th>");
        sb.AppendLine("    <th>CVEs Fixed</th>");
        sb.AppendLine("    <th title=\"Estimated CRA readiness score improvement\">Score Lift</th>");
        sb.AppendLine("    <th title=\"Patch = safe, Minor = new features, Major = possible breaking changes\">Effort</th>");
        sb.AppendLine("    <th>Risk</th>");
        sb.AppendLine("  </tr></thead>");
        sb.AppendLine("  <tbody>");

        int rank = 0;
        foreach (var item in _remediationRoadmap)
        {
            rank++;

            var priorityClass = item.HasKevVulnerability ? "critical" :
                item.MaxEpssProbability >= 0.5 ? "critical" :
                item.PriorityScore >= 250 ? "warning" : "ok";

            var priorityLabel = item.HasKevVulnerability ? "CRITICAL" :
                item.MaxEpssProbability >= 0.5 ? "CRITICAL" :
                item.PriorityScore >= 250 ? "HIGH" : "MEDIUM";

            // Primary row — shows recommended tier (or existing single-version behavior)
            var primaryVersion = item.UpgradeTiers.Count > 0
                ? item.UpgradeTiers[0].TargetVersion
                : item.RecommendedVersion;
            var primaryEffort = item.UpgradeTiers.Count > 0
                ? item.UpgradeTiers[0].Effort
                : item.Effort;
            var primaryCveText = item.UpgradeTiers.Count > 0
                ? $"{item.UpgradeTiers[0].CvesFixed}/{item.UpgradeTiers[0].TotalCves} CVEs"
                : item.CveCount == 1 ? "1 CVE" : $"{item.CveCount} CVEs";

            var primaryEffortClass = primaryEffort switch
            {
                UpgradeEffort.Patch => "patch",
                UpgradeEffort.Minor => "minor",
                _ => "major"
            };
            var checkmark = item.UpgradeTiers.Count > 1 ? " \u2713" : "";
            var primaryEffortLabel = primaryEffort switch
            {
                UpgradeEffort.Patch => $"Patch{checkmark}",
                UpgradeEffort.Minor => $"Minor{checkmark}",
                _ => $"Major{checkmark}"
            };

            sb.AppendLine("    <tr>");
            sb.AppendLine($"      <td><span class=\"remediation-priority-badge {priorityClass}\">{rank}</span></td>");
            sb.AppendLine($"      <td><strong>{EscapeHtml(item.PackageId)}</strong></td>");
            sb.AppendLine($"      <td><code>{EscapeHtml(item.CurrentVersion)}</code> <span style=\"color:var(--text-secondary);\">\u2192</span> <code>{EscapeHtml(primaryVersion)}</code></td>");
            sb.AppendLine($"      <td>{primaryCveText}</td>");
            sb.AppendLine($"      <td><span class=\"score-lift\">+{item.ScoreLift} pts</span></td>");
            sb.AppendLine($"      <td><span class=\"upgrade-effort {primaryEffortClass}\">{primaryEffortLabel}</span></td>");
            // Risk assessment badge
            if (item.TierRiskAssessments is not null &&
                item.UpgradeTiers.Count > 0 &&
                item.TierRiskAssessments.TryGetValue(item.UpgradeTiers[0].TargetVersion, out var primaryRisk))
            {
                var riskClass = primaryRisk.RiskLevel.ToString().ToLowerInvariant();
                var riskFactorsTooltip = EscapeHtml(string.Join("; ", primaryRisk.RiskFactors));
                sb.AppendLine($"      <td><span class=\"risk-badge {riskClass}\" title=\"{riskFactorsTooltip}\">{primaryRisk.RiskLevel}</span><span class=\"risk-score\">{primaryRisk.RiskScore}/100</span></td>");
            }
            else
            {
                sb.AppendLine("      <td>\u2014</td>");
            }
            sb.AppendLine("    </tr>");

            // Sub-rows for alternative tiers (skip index 0, which is the primary)
            for (int i = 1; i < item.UpgradeTiers.Count; i++)
            {
                var tier = item.UpgradeTiers[i];
                var altEffortClass = tier.Effort switch
                {
                    UpgradeEffort.Patch => "patch",
                    UpgradeEffort.Minor => "minor",
                    _ => "major"
                };
                var altEffortLabel = tier.Effort switch
                {
                    UpgradeEffort.Patch => "Patch",
                    UpgradeEffort.Minor => "Minor",
                    _ => "Major"
                };
                var altCveText = $"{tier.CvesFixed}/{tier.TotalCves} CVEs";

                sb.AppendLine("    <tr class=\"upgrade-tier-alt\">");
                sb.AppendLine("      <td></td>");
                sb.AppendLine("      <td></td>");
                sb.AppendLine($"      <td><code>{EscapeHtml(item.CurrentVersion)}</code> <span style=\"color:var(--text-secondary);\">\u2192</span> <code>{EscapeHtml(tier.TargetVersion)}</code></td>");
                sb.AppendLine($"      <td>{altCveText}</td>");
                sb.AppendLine("      <td></td>");
                sb.AppendLine($"      <td><span class=\"upgrade-effort {altEffortClass}\">{altEffortLabel}</span></td>");
                // Risk for alt tier
                if (item.TierRiskAssessments is not null &&
                    item.TierRiskAssessments.TryGetValue(tier.TargetVersion, out var altRisk))
                {
                    var altRiskClass = altRisk.RiskLevel.ToString().ToLowerInvariant();
                    var altRiskFactorsTooltip = EscapeHtml(string.Join("; ", altRisk.RiskFactors));
                    sb.AppendLine($"      <td><span class=\"risk-badge {altRiskClass}\" title=\"{altRiskFactorsTooltip}\">{altRisk.RiskLevel}</span><span class=\"risk-score\">{altRisk.RiskScore}/100</span></td>");
                }
                else
                {
                    sb.AppendLine("      <td></td>");
                }
                sb.AppendLine("    </tr>");
            }
        }

        sb.AppendLine("  </tbody>");
        sb.AppendLine("</table>");
    }

    private void GenerateAttackSurfaceSection(StringBuilder sb)
    {
        sb.AppendLine("<div class=\"section-header\">");
        sb.AppendLine("  <h2>Attack Surface Analysis</h2>");
        sb.AppendLine("</div>");

        sb.AppendLine("<div class=\"info-box\">");
        sb.AppendLine("  <div class=\"info-box-title\">What is this?</div>");
        sb.AppendLine("  <p>Every dependency you add also pulls in its own dependencies (called <strong>transitive</strong> dependencies). These are packages you didn't choose, but any vulnerability in them affects your project. This section measures how wide and deep your dependency tree is.</p>");
        sb.AppendLine("  <p style=\"margin-top:8px;\"><strong>Why it matters:</strong> A high ratio means each package you add brings many hidden dependencies. A deep tree means vulnerabilities can hide several layers down, making them hard to track and update.</p>");
        sb.AppendLine("</div>");

        var surface = _attackSurface!;

        // Metric cards
        var ratioClass = surface.TransitiveToDirectRatio < 5.0 ? "ok" : surface.TransitiveToDirectRatio >= 10.0 ? "critical" : "warning";
        var depthClass = surface.MaxDepth < 8 ? "ok" : surface.MaxDepth >= 12 ? "critical" : "warning";

        sb.AppendLine("<div class=\"surface-metrics\">");
        sb.AppendLine("  <div class=\"surface-metric\" title=\"Packages you explicitly added to your project (in .csproj or package.json).\">");
        sb.AppendLine($"    <div class=\"metric-big\">{surface.DirectCount}</div>");
        sb.AppendLine("    <div class=\"metric-label\">Direct Dependencies</div>");
        sb.AppendLine("    <div class=\"metric-hint\">Packages you chose</div>");
        sb.AppendLine("  </div>");
        sb.AppendLine("  <div class=\"surface-metric\" title=\"Packages pulled in automatically by your direct dependencies. You didn't choose these, but they run in your project.\">");
        sb.AppendLine($"    <div class=\"metric-big\">{surface.TransitiveCount}</div>");
        sb.AppendLine("    <div class=\"metric-label\">Transitive Dependencies</div>");
        sb.AppendLine("    <div class=\"metric-hint\">Pulled in automatically</div>");
        sb.AppendLine("  </div>");
        sb.AppendLine("  <div class=\"surface-metric\" title=\"For every 1 package you add, this many come along as transitive dependencies. Lower is better. Under 5:1 is healthy, over 10:1 means your tree is very wide.\">");
        sb.AppendLine($"    <div class=\"metric-big days-overdue {ratioClass}\">{surface.TransitiveToDirectRatio}:1</div>");
        sb.AppendLine("    <div class=\"metric-label\">Hidden Dependency Ratio</div>");
        sb.AppendLine($"    <div class=\"metric-hint\">{(surface.TransitiveToDirectRatio < 5.0 ? "Healthy" : surface.TransitiveToDirectRatio >= 10.0 ? "Very wide &mdash; consider alternatives" : "Wider than ideal")}</div>");
        sb.AppendLine("  </div>");
        sb.AppendLine("  <div class=\"surface-metric\" title=\"The deepest chain of dependencies. A depth of 8+ means updates to a deep package need to propagate through many layers before reaching you.\">");
        sb.AppendLine($"    <div class=\"metric-big days-overdue {depthClass}\">{surface.MaxDepth}</div>");
        sb.AppendLine("    <div class=\"metric-label\">Deepest Chain</div>");
        sb.AppendLine($"    <div class=\"metric-hint\">{(surface.MaxDepth < 8 ? "Manageable depth" : surface.MaxDepth >= 12 ? "Very deep &mdash; slow to patch" : "Deeper than ideal")}</div>");
        sb.AppendLine("  </div>");
        sb.AppendLine("</div>");

        // Thresholds reference - make it a table for clarity
        sb.AppendLine("<div class=\"card\" style=\"margin-top:12px; padding:14px;\">");
        sb.AppendLine("  <strong>How to read these numbers</strong>");
        sb.AppendLine("  <table style=\"margin-top:8px;width:100%;font-size:0.9rem;\">");
        sb.AppendLine("    <tr><td style=\"color:var(--healthy);padding:4px 8px;\">&#9679; Good</td><td>Ratio under 5:1, depth under 8 &mdash; manageable supply chain</td></tr>");
        sb.AppendLine("    <tr><td style=\"color:var(--warning);padding:4px 8px;\">&#9679; Review</td><td>Ratio 5:1&ndash;10:1 or depth 8&ndash;11 &mdash; consider if all dependencies are needed</td></tr>");
        sb.AppendLine("    <tr><td style=\"color:var(--critical);padding:4px 8px;\">&#9679; Action</td><td>Ratio over 10:1 or depth 12+ &mdash; evaluate lighter alternatives for heavy packages</td></tr>");
        sb.AppendLine("  </table>");
        sb.AppendLine("</div>");

        // Heavy packages table
        if (surface.HeavyPackages.Count > 0)
        {
            sb.AppendLine("<h3 style=\"margin-top:20px;\">Heavy Packages</h3>");
            sb.AppendLine("<p style=\"color:var(--text-secondary);margin-bottom:12px;\">These packages each bring in over 20 transitive dependencies. They are the biggest contributors to your attack surface. Consider whether lighter alternatives exist.</p>");
            sb.AppendLine("<table class=\"detail-table\">");
            sb.AppendLine("  <thead><tr>");
            sb.AppendLine("    <th title=\"The direct dependency that pulls in many transitive packages\">Package</th>");
            sb.AppendLine("    <th title=\"How many additional packages this one brings into your project\">Hidden Packages Brought In</th>");
            sb.AppendLine("  </tr></thead>");
            sb.AppendLine("  <tbody>");

            foreach (var (packageId, count) in surface.HeavyPackages)
            {
                var weight = count >= 100 ? "critical" : count >= 50 ? "warning" : "";
                sb.AppendLine("    <tr>");
                sb.AppendLine($"      <td><strong>{EscapeHtml(packageId)}</strong></td>");
                sb.AppendLine($"      <td><span class=\"{weight}\">{count} packages</span></td>");
                sb.AppendLine("    </tr>");
            }

            sb.AppendLine("  </tbody>");
            sb.AppendLine("</table>");
        }
    }

    private void GenerateSbomQualitySection(StringBuilder sb)
    {
        sb.AppendLine("<div class=\"section-header\">");
        sb.AppendLine("  <h2>SBOM Quality</h2>");
        sb.AppendLine("</div>");

        sb.AppendLine("<div class=\"info-box\">");
        sb.AppendLine("  <div class=\"info-box-title\">What is this?</div>");
        sb.AppendLine("  <p>A <strong>Software Bill of Materials (SBOM)</strong> is a list of every component in your project &mdash; like a nutrition label for software. The EU Cyber Resilience Act requires SBOMs to include specific fields for each package so that vulnerabilities can be traced and managed.</p>");
        sb.AppendLine("  <p style=\"margin-top:8px;\">This section checks how complete your SBOM data is. A score of <strong>90% or higher</strong> means your SBOM meets the quality bar for CRA compliance. Missing fields don't block your build, but they weaken your ability to respond to security incidents.</p>");
        sb.AppendLine("</div>");

        var v = _sbomValidation!;
        var completeness = v.CompletenessPercent;
        var barClass = completeness >= 90 ? "high" : completeness >= 70 ? "medium" : "low";

        // Overall completeness bar
        sb.AppendLine("<div style=\"margin: 20px 0;\">");
        sb.AppendLine("  <div style=\"display: flex; justify-content: space-between; margin-bottom: 6px;\">");
        sb.AppendLine("    <strong>Overall Data Completeness</strong>");
        sb.AppendLine($"    <strong class=\"{barClass}\">{completeness}%</strong>");
        sb.AppendLine("  </div>");
        sb.AppendLine("  <div class=\"progress-bar-container\">");
        sb.AppendLine($"    <div class=\"progress-bar-fill {barClass}\" style=\"width: {completeness}%\">{completeness}%</div>");
        sb.AppendLine("  </div>");
        sb.AppendLine($"  <div style=\"color:var(--text-secondary);font-size:0.85rem;margin-top:6px;\">{(completeness >= 90 ? "Meets CRA quality requirements." : completeness >= 70 ? "Close to target &mdash; address the gaps below to reach 90%." : "Significant gaps &mdash; review which fields are missing below.")}</div>");
        sb.AppendLine("</div>");

        // Per-field breakdown
        sb.AppendLine("<h3>Field-by-Field Breakdown</h3>");
        sb.AppendLine("<p style=\"color:var(--text-secondary);margin-bottom:16px;\">Each card shows how many of your packages have that field populated. Hover for details on what each field means.</p>");
        sb.AppendLine("<div class=\"field-grid\">");

        // Document-level fields
        AppendFieldCard(sb, "Timestamp", v.HasTimestamp ? "Present" : "Missing", v.HasTimestamp,
            "When the SBOM was generated. Needed to know if your inventory is current.");
        AppendFieldCard(sb, "Creator Tool", v.HasCreator ? "Present" : "Missing", v.HasCreator,
            "Which tool generated the SBOM. Helps verify the data source is trustworthy.");

        // Package-level fields
        if (v.TotalPackages > 0)
        {
            AppendFieldCardWithBar(sb, "Supplier", v.WithSupplier, v.TotalPackages,
                "Who published the package. Needed to contact maintainers about vulnerabilities.",
                v.MissingSupplier, "supplier");
            AppendFieldCardWithBar(sb, "License", v.WithLicense, v.TotalPackages,
                "The license under which the package is distributed. Required for legal compliance.",
                v.MissingLicense, "license");
            AppendFieldCardWithBar(sb, "Package URL (PURL)", v.WithPurl, v.TotalPackages,
                "A universal identifier (like pkg:nuget/Newtonsoft.Json@13.0.1) that uniquely identifies the exact package version across all registries.",
                v.MissingPurl, "purl");
            AppendFieldCardWithBar(sb, "Checksum", v.WithChecksum, v.TotalPackages,
                "A cryptographic hash verifying the package hasn't been tampered with since download.",
                v.MissingChecksum, "checksum");
        }

        sb.AppendLine("</div>");
    }

    private static void AppendFieldCard(StringBuilder sb, string label, string value, bool ok, string tooltip)
    {
        sb.AppendLine($"  <div class=\"field-card\" title=\"{EscapeHtml(tooltip)}\">");
        sb.AppendLine($"    <div class=\"field-label\">{EscapeHtml(label)}</div>");
        sb.AppendLine($"    <div class=\"field-value\"><span class=\"status-pill {(ok ? "signed" : "unsigned")}\">{EscapeHtml(value)}</span></div>");
        sb.AppendLine("  </div>");
    }

    private static void AppendFieldCardWithBar(StringBuilder sb, string label, int count, int total, string tooltip, List<string> missing, string fieldKey)
    {
        var pct = total > 0 ? (int)Math.Round(100.0 * count / total) : 0;
        var barClass = pct >= 90 ? "high" : pct >= 70 ? "medium" : "low";
        var hasMissing = missing.Count > 0;
        var cardClass = hasMissing ? "field-card field-card-clickable" : "field-card";
        sb.AppendLine($"  <div class=\"{cardClass}\" title=\"{EscapeHtml(tooltip)}{(hasMissing ? " \u2014 click to see missing packages" : "")}\">");
        sb.AppendLine($"    <div class=\"field-label\">{EscapeHtml(label)}{(hasMissing ? "<span class=\"field-toggle\">&#9660;</span>" : "")}</div>");
        sb.AppendLine($"    <div style=\"display:flex;justify-content:space-between;margin-bottom:4px;\"><span>{count}/{total} packages</span><span>{pct}%</span></div>");
        sb.AppendLine($"    <div class=\"progress-bar-container\"><div class=\"progress-bar-fill {barClass}\" style=\"width:{pct}%\"></div></div>");
        if (hasMissing)
        {
            sb.AppendLine($"    <div class=\"field-missing-list\" data-field=\"{fieldKey}\" style=\"display:none;\">");
            sb.AppendLine($"      <div class=\"field-missing-header\">Missing ({missing.Count})</div>");
            sb.AppendLine("    </div>");
        }
        sb.AppendLine("  </div>");
    }

    private void GenerateProvenanceSection(StringBuilder sb)
    {
        sb.AppendLine("<div class=\"section-header\">");
        sb.AppendLine("  <h2>Package Provenance</h2>");
        sb.AppendLine("</div>");

        sb.AppendLine("<div class=\"info-box\">");
        sb.AppendLine("  <div class=\"info-box-title\">What is this?</div>");
        sb.AppendLine("  <p><strong>Provenance</strong> means verifying that a package actually came from its claimed source. Package registries sign packages with cryptographic proofs &mdash; NuGet uses repository signatures, while npm uses ECDSA registry signatures and Sigstore attestations.</p>");
        sb.AppendLine("  <p style=\"margin-top:8px;\"><strong>Why it matters:</strong> Supply chain attacks work by injecting malicious code into packages. Signed packages are harder to tamper with. Unsigned packages aren't necessarily dangerous, but they lack this verification layer.</p>");
        sb.AppendLine("</div>");

        // Single pass to partition verified/unverified
        var unsigned = new List<ProvenanceResult>();
        var signed = new List<ProvenanceResult>();
        foreach (var r in _provenanceResults)
            (r.IsVerified ? signed : unsigned).Add(r);
        unsigned.Sort((a, b) => string.Compare(a.PackageId, b.PackageId, StringComparison.OrdinalIgnoreCase));
        signed.Sort((a, b) => string.Compare(a.PackageId, b.PackageId, StringComparison.OrdinalIgnoreCase));

        var verified = signed.Count;
        var total = _provenanceResults.Count;
        var pct = total > 0 ? (int)Math.Round(100.0 * verified / total) : 0;

        // Summary bar
        var barClass = pct >= 90 ? "high" : pct >= 50 ? "medium" : "low";
        sb.AppendLine("<div style=\"margin: 15px 0;\">");
        sb.AppendLine("  <div style=\"display: flex; justify-content: space-between; margin-bottom: 6px;\">");
        sb.AppendLine($"    <strong>{verified} of {total} packages verified</strong>");
        sb.AppendLine($"    <strong class=\"{barClass}\">{pct}%</strong>");
        sb.AppendLine("  </div>");
        sb.AppendLine("  <div class=\"progress-bar-container\">");
        sb.AppendLine($"    <div class=\"progress-bar-fill {barClass}\" style=\"width: {pct}%\">{pct}% signed</div>");
        sb.AppendLine("  </div>");
        sb.AppendLine("</div>");

        if (unsigned.Count > 0)
        {
            sb.AppendLine("<h3>Unsigned Packages</h3>");
            sb.AppendLine("<p style=\"color:var(--text-secondary);margin-bottom:12px;\">These packages could not be verified through registry signatures. This can happen with older npm packages published before registry signing, or smaller NuGet packages. It doesn't mean they're malicious &mdash; but extra review may be warranted.</p>");
            sb.AppendLine("<table class=\"detail-table\">");
            sb.AppendLine("  <thead><tr>");
            sb.AppendLine("    <th title=\"The package that couldn't be verified\">Package</th>");
            sb.AppendLine("    <th>Version</th>");
            sb.AppendLine("    <th title=\"NuGet or npm\">Ecosystem</th>");
            sb.AppendLine("    <th>Status</th>");
            sb.AppendLine("  </tr></thead>");
            sb.AppendLine("  <tbody>");
            foreach (var p in unsigned)
            {
                sb.AppendLine("    <tr>");
                sb.AppendLine($"      <td><strong>{EscapeHtml(p.PackageId)}</strong></td>");
                sb.AppendLine($"      <td>{EscapeHtml(p.Version)}</td>");
                sb.AppendLine($"      <td>{p.Ecosystem}</td>");
                sb.AppendLine("      <td><span class=\"status-pill unsigned\">Unsigned</span></td>");
                sb.AppendLine("    </tr>");
            }
            sb.AppendLine("  </tbody></table>");
        }

        if (signed.Count > 0)
        {
            sb.AppendLine($"<details style=\"margin-top:16px;\"><summary><strong>Signed Packages ({signed.Count})</strong> &mdash; click to expand</summary>");
            sb.AppendLine("<p style=\"color:var(--text-secondary);margin:8px 0;\">These packages have verified signatures, meaning they were published through official channels and haven't been modified in transit.</p>");
            sb.AppendLine("<table class=\"detail-table\">");
            sb.AppendLine("  <thead><tr><th>Package</th><th>Version</th><th>Ecosystem</th><th>Signature Type</th></tr></thead>");
            sb.AppendLine("  <tbody>");
            foreach (var p in signed)
            {
                var signType = p.HasAuthorSignature ? "Author + Repository" : "Repository";
                var signHint = p.HasAuthorSignature ? "Signed by both the author and the registry" : "Signed by the package registry";
                sb.AppendLine("    <tr>");
                sb.AppendLine($"      <td><strong>{EscapeHtml(p.PackageId)}</strong></td>");
                sb.AppendLine($"      <td>{EscapeHtml(p.Version)}</td>");
                sb.AppendLine($"      <td>{p.Ecosystem}</td>");
                sb.AppendLine($"      <td><span class=\"status-pill signed\" title=\"{signHint}\">{signType}</span></td>");
                sb.AppendLine("    </tr>");
            }
            sb.AppendLine("  </tbody></table>");
            sb.AppendLine("</details>");
        }
    }

    private void GenerateMaintenanceSection(StringBuilder sb)
    {
        sb.AppendLine("<div class=\"section-header\">");
        sb.AppendLine("  <h2>Maintenance Status</h2>");
        sb.AppendLine("</div>");

        sb.AppendLine("<div class=\"info-box\">");
        sb.AppendLine("  <div class=\"info-box-title\">What is this?</div>");
        sb.AppendLine("  <p>This checks whether the open-source projects behind your dependencies are still being actively developed. If a project's GitHub repository is <strong>archived</strong> (read-only) or has had <strong>no commits for a long time</strong>, security patches won't be available when vulnerabilities are discovered.</p>");
        sb.AppendLine("  <p style=\"margin-top:8px;\"><strong>What to do:</strong> Archived and unmaintained packages should be replaced with actively maintained alternatives. Stale packages may still be fine (some libraries are \"done\"), but keep an eye on them.</p>");
        sb.AppendLine("</div>");

        // Summary metrics
        var activeCount = _totalWithRepoData - _archivedPackageNames.Count - _stalePackageNames.Count;
        sb.AppendLine("<div class=\"surface-metrics\">");
        sb.AppendLine($"  <div class=\"surface-metric\" title=\"How many of your packages we could find GitHub repository data for. Packages without repo data are not shown here.\">");
        sb.AppendLine($"    <div class=\"metric-big\">{_totalWithRepoData}</div>");
        sb.AppendLine("    <div class=\"metric-label\">Packages Checked</div>");
        sb.AppendLine("    <div class=\"metric-hint\">With GitHub repo data</div>");
        sb.AppendLine("  </div>");
        sb.AppendLine($"  <div class=\"surface-metric\" title=\"Repositories marked as archived (read-only) by their owner. No further updates, bug fixes, or security patches will be released.\">");
        sb.AppendLine($"    <div class=\"metric-big days-overdue {(_archivedPackageNames.Count > 0 ? "critical" : "ok")}\">{_archivedPackageNames.Count}</div>");
        sb.AppendLine("    <div class=\"metric-label\">Archived</div>");
        sb.AppendLine("    <div class=\"metric-hint\">No future updates possible</div>");
        sb.AppendLine("  </div>");
        sb.AppendLine($"  <div class=\"surface-metric\" title=\"Packages whose GitHub repository has had no commits in over 1 year. May still be fine for stable libraries, but monitor closely.\">");
        sb.AppendLine($"    <div class=\"metric-big days-overdue {(_stalePackageNames.Count > 0 ? "warning" : "ok")}\">{_stalePackageNames.Count}</div>");
        sb.AppendLine("    <div class=\"metric-label\">Stale</div>");
        sb.AppendLine("    <div class=\"metric-hint\">No commits in 1+ year</div>");
        sb.AppendLine("  </div>");
        sb.AppendLine($"  <div class=\"surface-metric\" title=\"Packages with no commits in over 2 years. High risk of not receiving security patches. Strongly consider replacing.\">");
        sb.AppendLine($"    <div class=\"metric-big days-overdue {(_unmaintainedPackageNames.Count > 0 ? "critical" : "ok")}\">{_unmaintainedPackageNames.Count}</div>");
        sb.AppendLine("    <div class=\"metric-label\">Unmaintained</div>");
        sb.AppendLine("    <div class=\"metric-hint\">No commits in 2+ years</div>");
        sb.AppendLine("  </div>");
        sb.AppendLine("</div>");

        if (_archivedPackageNames.Count > 0)
        {
            sb.AppendLine("<div class=\"maintenance-group\">");
            sb.AppendLine("  <h4>Archived Repositories</h4>");
            sb.AppendLine("  <p style=\"margin:0 0 8px;color:var(--text-secondary);font-size:0.9rem;\">The owner has made these repositories read-only. No bug fixes or security patches will be released. You should find replacement packages.</p>");
            sb.AppendLine("  <div class=\"maintenance-list\">");
            foreach (var pkg in _archivedPackageNames)
            {
                sb.AppendLine($"    <span class=\"maintenance-pkg\"><span class=\"status-pill archived\">Archived</span> {EscapeHtml(pkg)}</span>");
            }
            sb.AppendLine("  </div>");
            sb.AppendLine("</div>");
        }

        if (_stalePackageNames.Count > 0)
        {
            sb.AppendLine("<div class=\"maintenance-group\">");
            sb.AppendLine("  <h4>Stale Packages</h4>");
            sb.AppendLine("  <p style=\"margin:0 0 8px;color:var(--text-secondary);font-size:0.9rem;\">No commits in over a year. Some libraries are stable and \"done\" (e.g., math utilities), but others may simply be abandoned. Check if alternatives exist.</p>");
            sb.AppendLine("  <div class=\"maintenance-list\">");
            foreach (var pkg in _stalePackageNames)
            {
                var alsoUnmaintained = _unmaintainedPackageNames.Contains(pkg);
                var pillClass = alsoUnmaintained ? "unmaintained" : "stale";
                var pillLabel = alsoUnmaintained ? "2+ years" : "1+ year";
                sb.AppendLine($"    <span class=\"maintenance-pkg\"><span class=\"status-pill {pillClass}\">{pillLabel}</span> {EscapeHtml(pkg)}</span>");
            }
            sb.AppendLine("  </div>");
            sb.AppendLine("</div>");
        }

        // Show healthy count
        if (activeCount > 0)
        {
            sb.AppendLine("<div class=\"maintenance-group\">");
            sb.AppendLine($"  <h4>Actively Maintained ({activeCount} packages)</h4>");
            sb.AppendLine("  <p style=\"margin:0;color:var(--text-secondary);font-size:0.9rem;\">These packages have commits within the last year &mdash; they're likely to receive security patches when needed.</p>");
            sb.AppendLine("</div>");
        }
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

    private void GenerateSupplyChainSection(StringBuilder sb)
    {
        sb.AppendLine("<div class=\"section-header\">");
        sb.AppendLine("  <h2>Supply Chain Analysis</h2>");
        sb.AppendLine("</div>");

        if (_typosquatResults.Count == 0)
        {
            sb.AppendLine("<div class=\"card typosquat-success\">");
            sb.AppendLine("  <div class=\"empty-icon\">&#9989;</div>");
            sb.AppendLine("  <h3>No Typosquatting Issues Detected</h3>");
            sb.AppendLine("  <p>All dependency names were verified against known popular packages. No suspicious name similarities were found.</p>");
            sb.AppendLine("</div>");
            return;
        }

        // Summary stats (single pass)
        int criticalCount = 0, highCount = 0, mediumCount = 0, lowCount = 0;
        foreach (var r in _typosquatResults)
        {
            switch (r.RiskLevel)
            {
                case TyposquatRiskLevel.Critical: criticalCount++; break;
                case TyposquatRiskLevel.High: highCount++; break;
                case TyposquatRiskLevel.Medium: mediumCount++; break;
                case TyposquatRiskLevel.Low: lowCount++; break;
            }
        }

        sb.AppendLine("<div class=\"typosquat-summary\">");
        sb.AppendLine($"  <div class=\"typosquat-stat-card\"><span class=\"typosquat-stat-count\">{_typosquatResults.Count}</span><span class=\"typosquat-stat-label\">Total Warnings</span></div>");
        if (criticalCount > 0)
            sb.AppendLine($"  <div class=\"typosquat-stat-card critical\"><span class=\"typosquat-stat-count\">{criticalCount}</span><span class=\"typosquat-stat-label\">Critical</span></div>");
        if (highCount > 0)
            sb.AppendLine($"  <div class=\"typosquat-stat-card high\"><span class=\"typosquat-stat-count\">{highCount}</span><span class=\"typosquat-stat-label\">High</span></div>");
        if (mediumCount > 0)
            sb.AppendLine($"  <div class=\"typosquat-stat-card medium\"><span class=\"typosquat-stat-count\">{mediumCount}</span><span class=\"typosquat-stat-label\">Medium</span></div>");
        if (lowCount > 0)
            sb.AppendLine($"  <div class=\"typosquat-stat-card low\"><span class=\"typosquat-stat-count\">{lowCount}</span><span class=\"typosquat-stat-label\">Low</span></div>");
        sb.AppendLine("</div>");

        // Results table
        sb.AppendLine("<div class=\"card\">");
        sb.AppendLine("<table class=\"data-table typosquat-table\">");
        sb.AppendLine("  <thead>");
        sb.AppendLine("    <tr>");
        sb.AppendLine("      <th>Risk</th>");
        sb.AppendLine("      <th>Package</th>");
        sb.AppendLine("      <th>Similar To</th>");
        sb.AppendLine("      <th>Detection Method</th>");
        sb.AppendLine("      <th>Confidence</th>");
        sb.AppendLine("      <th>Detail</th>");
        sb.AppendLine("    </tr>");
        sb.AppendLine("  </thead>");
        sb.AppendLine("  <tbody>");

        foreach (var result in _typosquatResults.OrderByDescending(r => r.RiskLevel).ThenByDescending(r => r.Confidence))
        {
            var riskClass = result.RiskLevel switch
            {
                TyposquatRiskLevel.Critical => "typosquat-critical",
                TyposquatRiskLevel.High => "typosquat-high",
                TyposquatRiskLevel.Medium => "typosquat-medium",
                _ => "typosquat-low"
            };

            var methodLabel = result.Method switch
            {
                TyposquatDetectionMethod.EditDistance => "Edit Distance",
                TyposquatDetectionMethod.Homoglyph => "Homoglyph",
                TyposquatDetectionMethod.SeparatorSwap => "Separator Swap",
                TyposquatDetectionMethod.PrefixSuffix => "Prefix/Suffix",
                TyposquatDetectionMethod.ScopeConfusion => "Scope Confusion",
                _ => result.Method.ToString()
            };

            sb.AppendLine("    <tr>");
            sb.AppendLine($"      <td><span class=\"typosquat-risk {riskClass}\">{result.RiskLevel}</span></td>");
            sb.AppendLine($"      <td><code>{EscapeHtml(result.PackageName)}</code></td>");
            sb.AppendLine($"      <td><code>{EscapeHtml(result.SimilarTo)}</code></td>");
            sb.AppendLine($"      <td>{EscapeHtml(methodLabel)}</td>");
            sb.AppendLine($"      <td><span class=\"confidence-bar\"><span class=\"confidence-fill\" style=\"width:{result.Confidence}%\"></span><span class=\"confidence-text\">{result.Confidence}%</span></span></td>");
            sb.AppendLine($"      <td>{EscapeHtml(result.Detail)}</td>");
            sb.AppendLine("    </tr>");
        }

        sb.AppendLine("  </tbody>");
        sb.AppendLine("</table>");
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
            sb.AppendLine($"  <span class=\"tree-stat vulnerable\" title=\"Packages with vulnerable sub-dependencies\"><strong>Has Vuln Deps:</strong> {vulnerableCount}</span>");
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
                var ecosystemIcon = tree.ProjectType == ProjectType.Npm ? "\U0001F4E6" : "\U0001F537";
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
        var indentStr = indent < IndentStrings.Length ? IndentStrings[indent] : new string(' ', indent * 2);

        var nodeClasses = new List<string> { "tree-node" };
        if (node.IsDuplicate) nodeClasses.Add("duplicate");
        if (node.HasVulnerabilities) nodeClasses.Add("has-vuln");
        if (node.HasVulnerableDescendant) nodeClasses.Add("has-vuln-descendant");
        var hasKev = _kevPackageIds.Contains(node.PackageId);
        if (hasKev) nodeClasses.Add("has-kev");

        var scoreClass = node.HealthScore.HasValue ? GetScoreClass(node.HealthScore.Value) : "";
        var nodeNameLower = node.PackageId.ToLowerInvariant();

        sb.AppendLine($"{indentStr}<li class=\"{string.Join(" ", nodeClasses)}\" data-name=\"{EscapeHtml(nodeNameLower)}\">");

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
        var healthData = _healthLookup.GetValueOrDefault(node.PackageId);

        if (healthData is not null)
        {
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
                dupTooltip = $"Required by: {string.Join(", ", parents.Take(5))}";
                if (parents.Count > 5)
                    dupTooltip += $" (+{parents.Count - 5} more)";
            }
            sb.AppendLine($"{indentStr}  <span class=\"node-badge duplicate\" title=\"{EscapeHtml(dupTooltip)}\">dup</span>");
        }

        if (node.HasVulnerabilities)
        {
            var vulnUrl = node.VulnerabilityUrl ?? $"https://osv.dev/list?ecosystem={(node.Ecosystem == PackageEcosystem.Npm ? "npm" : "NuGet")}&q={Uri.EscapeDataString(node.PackageId)}";
            var vulnTooltip = EscapeHtml(node.VulnerabilitySummary ?? "Click for vulnerability details");
            if (hasKev && healthData?.KevCves.Count > 0)
            {
                var kevCve = healthData.KevCves[0];
                var kevUrl = $"https://osv.dev/vulnerability/{Uri.EscapeDataString(kevCve)}";
                sb.AppendLine($"{indentStr}  <a href=\"{EscapeHtml(kevUrl)}\" target=\"_blank\" class=\"node-badge kev\" title=\"{EscapeHtml(kevCve)} - CISA KEV (click for details)\">{EscapeHtml(kevCve)}</a>");
            }
            else if (hasKev)
            {
                sb.AppendLine($"{indentStr}  <a href=\"{EscapeHtml(vulnUrl)}\" target=\"_blank\" class=\"node-badge kev\" title=\"CISA KEV: {vulnTooltip}\">KEV</a>");
            }
            else
            {
                sb.AppendLine($"{indentStr}  <a href=\"{EscapeHtml(vulnUrl)}\" target=\"_blank\" class=\"node-badge vuln\" title=\"{vulnTooltip}\">VULN</a>");
            }
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
            sb.AppendLine($"    <span class=\"versions-label\">Found in tree:</span>");
            foreach (var version in issue.Versions.OrderByDescending(v => v))
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

    private void GenerateReleaseReadinessSection(StringBuilder sb)
    {
        sb.AppendLine("<div class=\"section-header\">");
        sb.AppendLine("  <h2>Release Readiness</h2>");
        sb.AppendLine("</div>");

        sb.AppendLine("<div class=\"info-box\">");
        sb.AppendLine("  <div class=\"info-box-title\">\u2139 What is this?</div>");
        sb.AppendLine("  <p>This section checks whether your software meets the minimum requirements for a safe release under the EU Cyber Resilience Act. Blocking issues must be resolved before release. Advisory items should be addressed but do not prevent release.</p>");
        sb.AppendLine("</div>");

        if (_releaseReadiness is null)
        {
            sb.AppendLine("<div class=\"card empty-state\">");
            sb.AppendLine("  <div class=\"empty-icon\">\u2014</div>");
            sb.AppendLine("  <p>Release readiness data not available.</p>");
            sb.AppendLine("</div>");
            return;
        }

        if (_releaseReadiness.IsReady)
        {
            sb.AppendLine("<div class=\"release-gate-go\">");
            sb.AppendLine("  <div class=\"gate-icon\">\u2713</div>");
            sb.AppendLine("  <div class=\"gate-label\">GO</div>");
            sb.AppendLine("  <div class=\"gate-detail\">All compliance checks passed. No blocking issues found.</div>");
            sb.AppendLine("</div>");
        }
        else
        {
            sb.AppendLine("<div class=\"release-gate-nogo\">");
            sb.AppendLine("  <div class=\"gate-header\">");
            sb.AppendLine("    <div class=\"gate-icon\">\u2716</div>");
            sb.AppendLine($"    <div class=\"gate-label\">NO-GO \u2014 {_releaseReadiness.BlockingItems.Count} Blocker{(_releaseReadiness.BlockingItems.Count != 1 ? "s" : "")}</div>");
            sb.AppendLine("  </div>");
            sb.AppendLine("  <div class=\"gate-detail\">The following issues must be resolved before this software can be released.</div>");
            sb.AppendLine("  <table class=\"blocker-table\">");
            sb.AppendLine("    <thead><tr><th>What</th><th>Why</th><th>What To Do</th></tr></thead>");
            sb.AppendLine("    <tbody>");
            foreach (var blocker in _releaseReadiness.BlockingItems)
            {
                sb.AppendLine("      <tr>");
                sb.AppendLine($"        <td><strong>{EscapeHtml(blocker.Requirement)}</strong></td>");
                sb.AppendLine($"        <td>{EscapeHtml(blocker.Reason)}</td>");
                sb.AppendLine($"        <td>Resolve this compliance requirement to unblock release.</td>");
                sb.AppendLine("      </tr>");
            }
            sb.AppendLine("    </tbody>");
            sb.AppendLine("  </table>");
            sb.AppendLine("</div>");
        }

        if (_releaseReadiness.AdvisoryItems.Count > 0)
        {
            sb.AppendLine("<div class=\"card\">");
            sb.AppendLine($"  <h3>Advisory Items ({_releaseReadiness.AdvisoryItems.Count})</h3>");
            sb.AppendLine("  <p style=\"color: var(--text-muted); margin-bottom: 12px;\">These items should be addressed but do not block release.</p>");
            sb.AppendLine("  <ul class=\"advisory-list\">");
            foreach (var advisory in _releaseReadiness.AdvisoryItems)
            {
                sb.AppendLine($"    <li>{EscapeHtml(advisory)}</li>");
            }
            sb.AppendLine("  </ul>");
            sb.AppendLine("</div>");
        }
    }

    private void GenerateSecurityBudgetSection(StringBuilder sb)
    {
        sb.AppendLine("<div class=\"section-header\">");
        sb.AppendLine("  <h2>Security Budget</h2>");
        sb.AppendLine("</div>");

        sb.AppendLine("<div class=\"info-box\">");
        sb.AppendLine("  <div class=\"info-box-title\">\u2139 What is this?</div>");
        sb.AppendLine("  <p>Not all fixes are equally important. This section ranks remediation items by return on investment (ROI) \u2014 how much security risk each fix removes relative to the effort required. Focus on High-ROI items first to get the most impact from your security budget.</p>");
        sb.AppendLine("</div>");

        if (_securityBudget is null || _securityBudget.Items.Count == 0)
        {
            sb.AppendLine("<div class=\"card empty-state success\">");
            sb.AppendLine("  <div class=\"empty-icon\">\u2713</div>");
            sb.AppendLine("  <p>No remediation items to prioritize. Your dependencies look good!</p>");
            sb.AppendLine("</div>");
            return;
        }

        var highRoi = _securityBudget.Items.Where(i => i.Tier == RemediationTier.HighROI).ToList();
        var lowRoi = _securityBudget.Items.Where(i => i.Tier == RemediationTier.LowROI).ToList();

        // Summary card
        sb.AppendLine("<div class=\"budget-summary\">");
        sb.AppendLine("  <div class=\"budget-text\">");
        sb.AppendLine($"    <div class=\"budget-headline\">Fix {highRoi.Count} item{(highRoi.Count != 1 ? "s" : "")} to remove {_securityBudget.HighROIPercentage:F0}% of your security risk</div>");
        sb.AppendLine($"    <div class=\"budget-detail\">Out of {_securityBudget.Items.Count} total items, {highRoi.Count} deliver the highest return on investment.</div>");
        sb.AppendLine("  </div>");
        sb.AppendLine("  <div class=\"budget-bar-container\">");
        sb.AppendLine($"    <div class=\"budget-bar-fill\" style=\"width: {_securityBudget.HighROIPercentage:F0}%\">{_securityBudget.HighROIPercentage:F0}%</div>");
        sb.AppendLine("  </div>");
        sb.AppendLine("</div>");

        // High-ROI table
        if (highRoi.Count > 0)
        {
            sb.AppendLine("<div class=\"card\">");
            sb.AppendLine("  <h3>High ROI \u2014 Fix These First</h3>");
            sb.AppendLine("  <table class=\"detail-table\">");
            sb.AppendLine("    <thead><tr><th>Package</th><th>What To Do</th><th>CVEs Fixed</th><th>Effort</th><th>Risk Removed</th></tr></thead>");
            sb.AppendLine("    <tbody>");
            foreach (var item in highRoi)
            {
                sb.AppendLine("      <tr class=\"tier-high\">");
                sb.AppendLine($"        <td><strong>{EscapeHtml(item.Item.PackageId)}</strong></td>");
                sb.AppendLine($"        <td>{EscapeHtml(item.Item.ActionText ?? $"Upgrade {item.Item.CurrentVersion} \u2192 {item.Item.RecommendedVersion}")}</td>");
                sb.AppendLine($"        <td>{(item.Item.CveCount > 0 ? item.Item.CveCount.ToString() : "\u2014")}</td>");
                sb.AppendLine($"        <td><span class=\"upgrade-effort {item.Item.Effort.ToString().ToLowerInvariant()}\">{item.Item.Effort}</span></td>");
                sb.AppendLine($"        <td><span class=\"tier-badge high\">{item.CumulativeRiskReductionPercent:F0}%</span></td>");
                sb.AppendLine("      </tr>");
            }
            sb.AppendLine("    </tbody>");
            sb.AppendLine("  </table>");
            sb.AppendLine("</div>");
        }

        // Low-ROI table
        if (lowRoi.Count > 0)
        {
            sb.AppendLine("<div class=\"card\">");
            sb.AppendLine("  <h3>Lower Priority</h3>");
            sb.AppendLine("  <table class=\"detail-table\">");
            sb.AppendLine("    <thead><tr><th>Package</th><th>What To Do</th><th>CVEs Fixed</th><th>Effort</th><th>Risk Removed</th></tr></thead>");
            sb.AppendLine("    <tbody>");
            foreach (var item in lowRoi)
            {
                sb.AppendLine("      <tr class=\"tier-low\">");
                sb.AppendLine($"        <td>{EscapeHtml(item.Item.PackageId)}</td>");
                sb.AppendLine($"        <td>{EscapeHtml(item.Item.ActionText ?? $"Upgrade {item.Item.CurrentVersion} \u2192 {item.Item.RecommendedVersion}")}</td>");
                sb.AppendLine($"        <td>{(item.Item.CveCount > 0 ? item.Item.CveCount.ToString() : "\u2014")}</td>");
                sb.AppendLine($"        <td><span class=\"upgrade-effort {item.Item.Effort.ToString().ToLowerInvariant()}\">{item.Item.Effort}</span></td>");
                sb.AppendLine($"        <td><span class=\"tier-badge low\">{item.CumulativeRiskReductionPercent:F0}%</span></td>");
                sb.AppendLine("      </tr>");
            }
            sb.AppendLine("    </tbody>");
            sb.AppendLine("  </table>");
            sb.AppendLine("</div>");
        }
    }

    private void GeneratePolicyViolationsSection(StringBuilder sb)
    {
        sb.AppendLine("<div class=\"section-header\">");
        sb.AppendLine("  <h2>Policy Violations</h2>");
        sb.AppendLine("</div>");

        sb.AppendLine("<div class=\"info-box\">");
        sb.AppendLine("  <div class=\"info-box-title\">\u2139 What is this?</div>");
        sb.AppendLine("  <p>Your team has configured policy rules in .cra-config.json. This section shows which rules were violated. These are custom policies \u2014 not CRA legal requirements \u2014 but they represent your organization's standards.</p>");
        sb.AppendLine("</div>");

        // Excluded packages card
        if (_excludedPackages.Count > 0)
        {
            sb.AppendLine("<div class=\"card info-card\" style=\"margin-bottom: 16px;\">");
            sb.AppendLine($"  <h4>\u2139 {_excludedPackages.Count} package(s) excluded from analysis</h4>");
            sb.AppendLine("  <table class=\"policy-table\">");
            sb.AppendLine("    <thead><tr><th>Package</th><th>Justification</th></tr></thead>");
            sb.AppendLine("    <tbody>");
            foreach (var pkg in _excludedPackages)
            {
                var justification = _complianceNotes.TryGetValue(pkg, out var note)
                    ? EscapeHtml(note)
                    : "<em>No justification provided</em>";
                sb.AppendLine("      <tr>");
                sb.AppendLine($"        <td><strong>{EscapeHtml(pkg)}</strong></td>");
                sb.AppendLine($"        <td>{justification}</td>");
                sb.AppendLine("      </tr>");
            }
            sb.AppendLine("    </tbody>");
            sb.AppendLine("  </table>");
            sb.AppendLine("</div>");
        }

        if (_policyEvaluation is null || _policyEvaluation.Violations.Count == 0)
        {
            sb.AppendLine("<div class=\"card empty-state success\">");
            sb.AppendLine("  <div class=\"empty-icon\">\u2713</div>");
            sb.AppendLine("  <p>No policy violations found. All packages meet your configured rules.</p>");
            sb.AppendLine("</div>");
            return;
        }

        // Violations table
        sb.AppendLine("<div class=\"card\">");
        sb.AppendLine("  <table class=\"policy-table\">");
        sb.AppendLine("    <thead><tr><th>Rule</th><th>Severity</th><th>Details</th><th>CRA Article</th><th>Remediation</th></tr></thead>");
        sb.AppendLine("    <tbody>");
        foreach (var v in _policyEvaluation.Violations)
        {
            var sevClass = v.Severity == PolicySeverity.Block ? "risk-critical" : "risk-medium";
            var sevLabel = v.Severity == PolicySeverity.Block ? "BLOCK" : "WARN";
            sb.AppendLine($"      <tr class=\"{sevClass}\">");
            sb.AppendLine($"        <td><strong>{EscapeHtml(v.Rule)}</strong></td>");
            sb.AppendLine($"        <td>{sevLabel}</td>");
            sb.AppendLine($"        <td>{EscapeHtml(v.Message)}</td>");
            sb.AppendLine($"        <td>{EscapeHtml(v.CraArticle ?? "\u2014")}</td>");
            sb.AppendLine($"        <td>{EscapeHtml(v.Remediation ?? "\u2014")}</td>");
            sb.AppendLine("      </tr>");
            if (v.Justification is not null)
            {
                sb.AppendLine("      <tr>");
                sb.AppendLine($"        <td colspan=\"5\" style=\"color: var(--text-muted); font-style: italic; padding-left: 24px;\">Justification: {EscapeHtml(v.Justification)}</td>");
                sb.AppendLine("      </tr>");
            }
        }
        sb.AppendLine("    </tbody>");
        sb.AppendLine("  </table>");
        sb.AppendLine("</div>");
    }

    private void GenerateAuditSimulationSection(StringBuilder sb)
    {
        sb.AppendLine("<div class=\"section-header\">");
        sb.AppendLine("  <h2>Audit Simulation</h2>");
        sb.AppendLine("</div>");

        sb.AppendLine("<div class=\"info-box\">");
        sb.AppendLine("  <div class=\"info-box-title\">\u2139 What is this?</div>");
        sb.AppendLine("  <p>This simulates what a CRA conformity assessment body would likely flag about your dependency management. Findings are grounded in CRA Annex I, II, and VII requirements with zero-tolerance interpretation. This is separate from the compliance items above, which use developer-friendly thresholds.</p>");
        sb.AppendLine("</div>");

        if (_auditSimulation is null || _auditSimulation.Findings.Count == 0)
        {
            sb.AppendLine("<div class=\"card empty-state success\">");
            sb.AppendLine("  <div class=\"empty-icon\">\u2713</div>");
            sb.AppendLine("  <h3>No Audit Findings</h3>");
            sb.AppendLine("  <p>No issues detected that a conformity assessment body would likely flag.</p>");
            sb.AppendLine("</div>");
            return;
        }

        // Summary banner
        var worstSeverity = _auditSimulation.CriticalCount > 0 ? "critical"
            : _auditSimulation.HighCount > 0 ? "high"
            : _auditSimulation.MediumCount > 0 ? "medium" : "low";

        var articleCount = _auditSimulation.Findings.Select(f => f.ArticleReference).Distinct().Count();

        sb.AppendLine($"<div class=\"audit-summary {worstSeverity}\">");
        sb.AppendLine("  <div class=\"audit-summary-text\">");
        sb.AppendLine($"    <h3>{_auditSimulation.Findings.Count} finding{(_auditSimulation.Findings.Count != 1 ? "s" : "")} across {articleCount} CRA article{(articleCount != 1 ? "s" : "")}</h3>");
        sb.AppendLine("    <p>These are findings a conformity assessment body would likely raise about your dependency management.</p>");
        sb.AppendLine("  </div>");
        sb.AppendLine("  <div class=\"audit-summary-counts\">");

        if (_auditSimulation.CriticalCount > 0)
        {
            sb.AppendLine("    <div class=\"audit-count\">");
            sb.AppendLine($"      <span class=\"audit-count-value\" style=\"color: var(--danger)\">{_auditSimulation.CriticalCount}</span>");
            sb.AppendLine("      <span class=\"audit-count-label\">Critical</span>");
            sb.AppendLine("    </div>");
        }
        if (_auditSimulation.HighCount > 0)
        {
            sb.AppendLine("    <div class=\"audit-count\">");
            sb.AppendLine($"      <span class=\"audit-count-value\" style=\"color: #e67e22\">{_auditSimulation.HighCount}</span>");
            sb.AppendLine("      <span class=\"audit-count-label\">High</span>");
            sb.AppendLine("    </div>");
        }
        if (_auditSimulation.MediumCount > 0)
        {
            sb.AppendLine("    <div class=\"audit-count\">");
            sb.AppendLine($"      <span class=\"audit-count-value\" style=\"color: var(--warning-text, #856404)\">{_auditSimulation.MediumCount}</span>");
            sb.AppendLine("      <span class=\"audit-count-label\">Medium</span>");
            sb.AppendLine("    </div>");
        }
        if (_auditSimulation.LowCount > 0)
        {
            sb.AppendLine("    <div class=\"audit-count\">");
            sb.AppendLine($"      <span class=\"audit-count-value\" style=\"color: var(--text-muted)\">{_auditSimulation.LowCount}</span>");
            sb.AppendLine("      <span class=\"audit-count-label\">Low</span>");
            sb.AppendLine("    </div>");
        }

        sb.AppendLine("  </div>");
        sb.AppendLine("</div>");

        // Findings table
        sb.AppendLine("<div class=\"card\">");
        sb.AppendLine("<table class=\"audit-findings-table\">");
        sb.AppendLine("  <thead><tr><th>Severity</th><th>CRA Article</th><th>Requirement</th><th>Finding</th><th>Affected</th></tr></thead>");
        sb.AppendLine("  <tbody>");

        foreach (var finding in _auditSimulation.Findings)
        {
            var severityClass = finding.Severity.ToString().ToLowerInvariant();
            sb.AppendLine("    <tr>");
            sb.AppendLine($"      <td><span class=\"audit-severity-badge {severityClass}\">{finding.Severity}</span></td>");
            sb.AppendLine($"      <td>{EscapeHtml(finding.ArticleReference)}</td>");
            sb.AppendLine($"      <td>{EscapeHtml(finding.Requirement)}</td>");
            sb.AppendLine($"      <td>{EscapeHtml(finding.Finding)}</td>");

            sb.AppendLine("      <td>");
            if (finding.AffectedPackages.Count > 0)
            {
                sb.AppendLine("        <ul class=\"audit-affected-list\">");
                var shown = finding.AffectedPackages.Take(5);
                foreach (var pkg in shown)
                    sb.AppendLine($"          <li>{EscapeHtml(pkg)}</li>");
                if (finding.AffectedPackages.Count > 5)
                    sb.AppendLine($"          <li class=\"audit-affected-overflow\">+{finding.AffectedPackages.Count - 5} more</li>");
                sb.AppendLine("        </ul>");
            }
            else
            {
                sb.AppendLine("        <span style=\"color: var(--text-muted)\">Project-level</span>");
            }
            sb.AppendLine("      </td>");
            sb.AppendLine("    </tr>");
        }

        sb.AppendLine("  </tbody>");
        sb.AppendLine("</table>");
        sb.AppendLine("</div>");
    }

    private void GenerateMaintainerTrustSection(StringBuilder sb)
    {
        sb.AppendLine("<div class=\"section-header\">");
        sb.AppendLine("  <h2>Maintainer Trust</h2>");
        sb.AppendLine("</div>");

        if (_maintainerTrustPackages is null) return;

        var packagesWithTrust = _maintainerTrustPackages
            .Where(p => p.MaintainerTrust is not null)
            .OrderBy(p => p.MaintainerTrust!.Score)
            .ToList();

        if (packagesWithTrust.Count == 0)
        {
            sb.AppendLine("<div class=\"card empty-state\">");
            sb.AppendLine("  <div class=\"empty-icon\">\u2139</div>");
            sb.AppendLine("  <h3>No Maintainer Data</h3>");
            sb.AppendLine("  <p>Trust scores require GitHub repository data. Run without --skip-github to enable.</p>");
            sb.AppendLine("</div>");
            return;
        }

        int highCount = packagesWithTrust.Count(p => p.MaintainerTrust!.Tier == MaintainerTrustTier.High);
        int moderateCount = packagesWithTrust.Count(p => p.MaintainerTrust!.Tier == MaintainerTrustTier.Moderate);
        int lowCount = packagesWithTrust.Count(p => p.MaintainerTrust!.Tier == MaintainerTrustTier.Low);
        int criticalCount = packagesWithTrust.Count(p => p.MaintainerTrust!.Tier == MaintainerTrustTier.Critical);
        int avgScore = (int)Math.Round(packagesWithTrust.Average(p => (double)p.MaintainerTrust!.Score));

        sb.AppendLine("<div class=\"card trust-summary\">");
        sb.AppendLine("  <div class=\"trust-distribution\">");
        sb.AppendLine($"    <div class=\"trust-avg\">Average Trust Score: <strong>{avgScore}</strong></div>");
        sb.AppendLine("    <div class=\"trust-counts\">");
        sb.AppendLine($"      <span class=\"trust-count high\">{highCount} High</span>");
        sb.AppendLine($"      <span class=\"trust-count moderate\">{moderateCount} Moderate</span>");
        sb.AppendLine($"      <span class=\"trust-count low\">{lowCount} Low</span>");
        sb.AppendLine($"      <span class=\"trust-count critical\">{criticalCount} Critical</span>");
        sb.AppendLine("    </div>");
        sb.AppendLine("  </div>");
        sb.AppendLine("</div>");

        // Bottom 5 lowest-trust packages
        var bottom5 = packagesWithTrust.Take(5).ToList();
        sb.AppendLine("<div class=\"card\">");
        sb.AppendLine("  <h3>Lowest Trust Packages</h3>");
        sb.AppendLine("  <table class=\"trust-table\">");
        sb.AppendLine("    <thead><tr>");
        sb.AppendLine("      <th>Package</th><th>Score</th><th>Tier</th><th>Contributors</th><th>Releases</th><th>Release Authors</th>");
        sb.AppendLine("    </tr></thead>");
        sb.AppendLine("    <tbody>");
        foreach (var pkg in bottom5)
        {
            var trust = pkg.MaintainerTrust!;
            var tierClass = trust.Tier.ToString().ToLowerInvariant();
            sb.AppendLine("    <tr>");
            sb.AppendLine($"      <td>{EscapeHtml(pkg.PackageId)}</td>");
            sb.AppendLine($"      <td><span class=\"trust-badge {tierClass}\">{trust.Score}</span></td>");
            sb.AppendLine($"      <td>{trust.Tier}</td>");
            sb.AppendLine($"      <td>{trust.ContributorCount}</td>");
            sb.AppendLine($"      <td>{trust.TotalReleases}</td>");
            sb.AppendLine($"      <td>{trust.ReleaseAuthorCount}{(trust.TopReleaseAuthor is not null ? $" ({EscapeHtml(trust.TopReleaseAuthor)})" : "")}</td>");
            sb.AppendLine("    </tr>");
        }
        sb.AppendLine("    </tbody>");
        sb.AppendLine("  </table>");
        sb.AppendLine("</div>");
    }

    private void GenerateTrendSection(StringBuilder sb)
    {
        if (_trendSummary is null) return;

        sb.AppendLine("<div class=\"section-header\">");
        sb.AppendLine("  <h2>Security Debt Trend</h2>");
        sb.AppendLine("</div>");

        // Summary card
        var (dirIcon, dirClass) = _trendSummary.OverallDirection switch
        {
            TrendDirection.Improving => ("\u25b2", "trend-improving"),
            TrendDirection.Degrading => ("\u25bc", "trend-degrading"),
            _ => ("\u25cf", "trend-stable")
        };
        var since = _trendSummary.FirstSnapshot?.ToString("MMM d, yyyy") ?? "unknown";

        sb.AppendLine($"<div class=\"trend-card {dirClass}\">");
        sb.AppendLine($"  <span class=\"trend-direction-icon\">{dirIcon}</span>");
        sb.AppendLine($"  <span>Security posture is <strong>{_trendSummary.OverallDirection.ToString().ToLowerInvariant()}</strong> over {_trendSummary.SnapshotCount} snapshots since {EscapeHtml(since)}.</span>");
        sb.AppendLine("</div>");

        // Sparkline chart rows
        sb.AppendLine("<div class=\"trend-metrics\">");
        foreach (var metric in _trendSummary.Metrics)
        {
            var sparklineData = GetSparklineData(metric.Name);
            var (metricIcon, metricClass) = metric.Direction switch
            {
                TrendDirection.Improving => ("\u25b2", "trend-improving"),
                TrendDirection.Degrading => ("\u25bc", "trend-degrading"),
                _ => ("\u25cf", "trend-stable")
            };
            var deltaStr = metric.Delta.HasValue
                ? (metric.Delta.Value > 0 ? $"+{metric.Delta.Value}" : metric.Delta.Value.ToString())
                : "\u2014";
            var suffix = metric.Name == "SBOM Completeness" ? "%" : "";

            sb.AppendLine("  <div class=\"trend-metric-row\">");
            sb.AppendLine($"    <div class=\"trend-metric-name\">{EscapeHtml(metric.Name)}</div>");
            sb.AppendLine($"    <div class=\"trend-sparkline\">{GenerateSparklineSvg(sparklineData)}</div>");
            sb.AppendLine($"    <div class=\"trend-metric-value\">{metric.CurrentValue}{suffix}</div>");
            sb.AppendLine($"    <div class=\"trend-delta {metricClass}\">{metricIcon} {deltaStr}</div>");
            sb.AppendLine("  </div>");
        }
        sb.AppendLine("</div>");

        // History table (collapsible)
        if (_trendSnapshots is not null && _trendSnapshots.Count > 1)
        {
            sb.AppendLine("<details class=\"trend-history\">");
            sb.AppendLine("<summary>Snapshot History</summary>");
            sb.AppendLine("<table class=\"detail-table\">");
            sb.AppendLine("  <thead><tr>");
            sb.AppendLine("    <th>Date</th><th>Health</th><th>CRA</th><th>Vulns</th><th>Critical</th><th>Reportable</th><th>SBOM %</th><th>Unpatched Days</th>");
            sb.AppendLine("  </tr></thead>");
            sb.AppendLine("  <tbody>");

            // Most recent first
            for (var i = _trendSnapshots.Count - 1; i >= 0 && i >= _trendSnapshots.Count - 10; i--)
            {
                var s = _trendSnapshots[i];
                sb.AppendLine("    <tr>");
                sb.AppendLine($"      <td>{s.CapturedAt:yyyy-MM-dd HH:mm}</td>");
                sb.AppendLine($"      <td>{s.HealthScore}</td>");
                sb.AppendLine($"      <td>{s.CraReadinessScore}</td>");
                sb.AppendLine($"      <td>{s.VulnerabilityCount}</td>");
                sb.AppendLine($"      <td>{s.CriticalPackageCount}</td>");
                sb.AppendLine($"      <td>{s.ReportableVulnerabilityCount}</td>");
                sb.AppendLine($"      <td>{s.SbomCompletenessPercentage?.ToString() ?? "\u2014"}</td>");
                sb.AppendLine($"      <td>{s.MaxUnpatchedVulnerabilityDays?.ToString() ?? "\u2014"}</td>");
                sb.AppendLine("    </tr>");
            }

            sb.AppendLine("  </tbody>");
            sb.AppendLine("</table>");
            sb.AppendLine("</details>");
        }
    }

    private List<int> GetSparklineData(string metricName)
    {
        if (_trendSnapshots is null || _trendSnapshots.Count == 0)
            return [];

        var start = Math.Max(0, _trendSnapshots.Count - 10);
        var data = new List<int>();
        for (var i = start; i < _trendSnapshots.Count; i++)
        {
            var s = _trendSnapshots[i];
            var value = metricName switch
            {
                "Health Score" => s.HealthScore,
                "CRA Readiness Score" => s.CraReadinessScore,
                "Vulnerability Count" => s.VulnerabilityCount,
                "Critical Packages" => s.CriticalPackageCount,
                "Reportable Vulnerabilities" => s.ReportableVulnerabilityCount,
                "SBOM Completeness" => s.SbomCompletenessPercentage ?? 0,
                "Max Unpatched Days" => s.MaxUnpatchedVulnerabilityDays ?? 0,
                _ => 0
            };
            data.Add(value);
        }
        return data;
    }

    private static string GenerateSparklineSvg(List<int> data)
    {
        if (data.Count < 2)
            return "<svg width=\"80\" height=\"24\"></svg>";

        var min = data.Min();
        var max = data.Max();
        var range = max - min;
        if (range == 0) range = 1; // avoid division by zero

        var width = 80;
        var height = 24;
        var padding = 2;
        var usableWidth = width - 2 * padding;
        var usableHeight = height - 2 * padding;

        var points = new List<string>();
        for (var i = 0; i < data.Count; i++)
        {
            var x = padding + (int)((double)i / (data.Count - 1) * usableWidth);
            var y = padding + usableHeight - (int)((double)(data[i] - min) / range * usableHeight);
            points.Add($"{x},{y}");
        }

        return $"<svg width=\"{width}\" height=\"{height}\" viewBox=\"0 0 {width} {height}\"><polyline points=\"{string.Join(" ", points)}\" fill=\"none\" stroke=\"var(--accent)\" stroke-width=\"1.5\" stroke-linecap=\"round\" stroke-linejoin=\"round\"/></svg>";
    }

}
