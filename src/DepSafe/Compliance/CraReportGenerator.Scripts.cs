using System.Text.Json;
using DepSafe.Models;

namespace DepSafe.Compliance;

public sealed partial class CraReportGenerator
{
    private static string GetHtmlStyles() => _htmlStyles.Value;

    private string GetHtmlScripts(CraReport report, bool darkMode)
    {
        // Serialize without indentation to minimize HTML report size (saves 1-3MB for large projects)
        var sbomJson = JsonSerializer.Serialize(report.Sbom);

        // Generate centralized package data for lazy loading (reduces DOM size by 80%+)
        var packageDataJson = GeneratePackageDataJson();
        var sbomMissingJson = GenerateSbomMissingDataJson();

        return $@"
<script id=""sbom-json"" type=""application/json"">{sbomJson}</script>
<script>
var _hasSbomData = true;
const packageData = {packageDataJson};
const sbomMissingData = {sbomMissingJson};

function toggleTheme() {{
  const toggle = document.getElementById('themeToggle');
  toggle.classList.toggle('active');
  if (toggle.classList.contains('active')) {{
    document.documentElement.setAttribute('data-theme', 'dark');
  }} else {{
    document.documentElement.removeAttribute('data-theme');
  }}
}}

function showSection(sectionId) {{
  document.querySelectorAll('.section').forEach(s => s.classList.remove('active'));
  document.querySelectorAll('.nav-links a').forEach(a => a.classList.remove('active'));
  document.getElementById(sectionId).classList.add('active');
  document.querySelector(`[data-section='${{sectionId}}']`).classList.add('active');
}}

function togglePackage(header) {{
  const card = header.parentElement;
  const details = card.querySelector('.package-details');

  // Lazy load details on first expand
  if (details && !details.dataset.loaded) {{
    const pkgId = card.id.replace('pkg-', '');
    const pkg = packageData[pkgId] || packageData[pkgId.toLowerCase()];
    if (pkg) {{
      details.innerHTML = renderPackageDetails(pkg);
      details.dataset.loaded = 'true';
    }}
  }}

  card.classList.toggle('expanded');
}}

function renderPackageDetails(pkg) {{
  var html = '';

  // Detail grid
  if (pkg.hasData) {{
    html += '<div class=""detail-grid"">';
    html += '<div class=""detail-item""><span class=""label"">License</span><span class=""value"">' + formatLicense(pkg.license) + '</span></div>';
    if (pkg.daysSinceLastRelease !== null) {{
      html += '<div class=""detail-item""><span class=""label"">Last Release</span><span class=""value"">' + formatDaysSince(pkg.daysSinceLastRelease) + '</span></div>';
    }}
    // Version status - show if newer version available
    if (pkg.latestVersion) {{
      var versionStatus = compareVersions(pkg.version, pkg.latestVersion);
      if (versionStatus.isLatest) {{
        html += '<div class=""detail-item""><span class=""label"">Version Status</span><span class=""value""><span class=""version-current"">&#10003; Latest</span></span></div>';
      }} else {{
        var urgencyClass = versionStatus.urgency;
        html += '<div class=""detail-item""><span class=""label"">Latest Available</span><span class=""value""><span class=""version-upgrade ' + urgencyClass + '"">&#8593; ' + escapeHtml(pkg.latestVersion) + '</span></span></div>';
      }}
    }}
    if (pkg.releasesPerYear > 0) {{
      html += '<div class=""detail-item""><span class=""label"">Releases/Year</span><span class=""value"">' + pkg.releasesPerYear.toFixed(1) + '</span></div>';
    }}
    if (pkg.downloads > 0) {{
      html += '<div class=""detail-item""><span class=""label"">Downloads</span><span class=""value"">' + formatNumber(pkg.downloads) + '</span></div>';
    }}
    if (pkg.stars) {{
      html += '<div class=""detail-item""><span class=""label"">GitHub Stars</span><span class=""value"">' + formatNumber(pkg.stars) + '</span></div>';
    }}
    if (pkg.daysSinceLastCommit !== null) {{
      html += '<div class=""detail-item""><span class=""label"">Last Commit</span><span class=""value"">' + pkg.daysSinceLastCommit + ' days ago</span></div>';
    }}
    html += '</div>';
  }}

  // Recommendations
  if (pkg.recommendations && pkg.recommendations.length > 0) {{
    html += '<div class=""recommendations""><h4>Recommendations</h4><ul>';
    pkg.recommendations.forEach(function(r) {{ html += '<li>' + escapeHtml(r) + '</li>'; }});
    html += '</ul></div>';
  }}

  // Vulnerabilities
  if (pkg.vulnCount > 0) {{
    html += '<div class=""vulnerabilities-badge""><span class=""vuln-count"">' + pkg.vulnCount + ' vulnerabilities</span></div>';
  }}

  // Peer dependencies (npm only)
  if (pkg.peerDependencies && pkg.peerDependencies.length > 0) {{
    html += '<div class=""package-dependencies peer-deps""><h4>Peer Dependencies (' + pkg.peerDependencies.length + ')</h4><div class=""dep-list"">';
    pkg.peerDependencies.forEach(function(dep) {{
      var url = 'https://www.npmjs.com/package/' + encodeURIComponent(dep.id);
      html += '<a href=""' + url + '"" target=""_blank"" class=""dep-item dep-peer"" title=""Required: ' + escapeHtml(dep.range || 'any') + '"">' + escapeHtml(dep.id) + ' <span class=""peer-range"">' + escapeHtml(dep.range || '') + '</span></a>';
    }});
    html += '</div></div>';
  }}

  // Dependencies
  if (pkg.dependencies && pkg.dependencies.length > 0) {{
    html += '<div class=""package-dependencies""><h4>Dependencies (' + pkg.dependencies.length + ')</h4><div class=""dep-list"">';
    var deps = pkg.dependencies.slice(0, 10);
    deps.forEach(function(dep) {{
      if (packageData[dep.id] || packageData[dep.id.toLowerCase()]) {{
        html += '<a href=""#pkg-' + escapeHtml(dep.id) + '"" class=""dep-item dep-internal"" title=""' + escapeHtml(dep.range || 'any') + ' - Click to jump to package"" onclick=""navigateToPackage(\'' + escapeJs(dep.id) + '\'); return false;"">' + escapeHtml(dep.id) + '</a>';
      }} else {{
        var url = pkg.ecosystem === 'npm' ? 'https://www.npmjs.com/package/' + encodeURIComponent(dep.id) : 'https://www.nuget.org/packages/' + encodeURIComponent(dep.id);
        html += '<a href=""' + url + '"" target=""_blank"" class=""dep-item dep-external"" title=""' + escapeHtml(dep.range || 'any') + ' - External dependency"">' + escapeHtml(dep.id) + '</a>';
      }}
    }});
    if (pkg.dependencies.length > 10) {{
      html += '<span class=""dep-more"">+' + (pkg.dependencies.length - 10) + ' more</span>';
    }}
    html += '</div></div>';
  }}

  // Parent packages (required by)
  if (pkg.parents && pkg.parents.length > 0) {{
    html += '<div class=""required-by""><h4>Required By</h4><div class=""parent-packages"">';
    var parents = pkg.parents.slice(0, 5);
    parents.forEach(function(parentId) {{
      var isDirect = packageData[parentId] && packageData[parentId].isDirect;
      var cls = isDirect ? 'parent-badge direct' : 'parent-badge';
      html += '<a href=""#"" class=""' + cls + '"" onclick=""navigateToPackage(\'' + escapeHtml(parentId.toLowerCase()) + '\'); return false;"" title=""' + (isDirect ? 'Direct dependency' : 'Transitive dependency') + '"">' + escapeHtml(parentId) + '</a>';
    }});
    if (pkg.parents.length > 5) {{
      html += '<span class=""more-parents"">+' + (pkg.parents.length - 5) + ' more</span>';
    }}
    html += '</div></div>';
  }}

  // Links
  html += '<div class=""package-links"">';
  html += '<a href=""' + pkg.registryUrl + '"" target=""_blank"">' + (pkg.ecosystem === 'npm' ? 'npm' : 'NuGet') + '</a>';
  if (pkg.repoUrl) {{
    html += '<a href=""' + escapeHtml(pkg.repoUrl) + '"" target=""_blank"">Repository</a>';
  }}
  html += '</div>';

  return html;
}}

function formatLicense(license) {{
  if (!license) return '<span class=""unknown"">Unknown</span>';
  return '<span class=""license-badge"">' + escapeHtml(license) + '</span>';
}}

function formatDaysSince(days) {{
  if (days === null || days === undefined) return 'Unknown';
  if (days === 0) return 'Today';
  if (days === 1) return 'Yesterday';
  if (days < 30) return days + ' days ago';
  if (days < 365) return Math.floor(days / 30) + ' months ago';
  return (days / 365).toFixed(1) + ' years ago';
}}

function formatNumber(n) {{
  if (n >= 1000000000) return (n / 1000000000).toFixed(1) + 'B';
  if (n >= 1000000) return (n / 1000000).toFixed(1) + 'M';
  if (n >= 1000) return (n / 1000).toFixed(1) + 'K';
  return n.toString();
}}

function escapeHtml(str) {{
  if (!str) return '';
  var div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}}

function escapeJs(str) {{
  if (!str) return '';
  return str.replace(/\\/g, '\\\\').replace(/'/g, ""\\'"");
}}

function compareVersions(current, latest) {{
  if (!current || !latest) return {{ isLatest: true, urgency: """" }};

  // Normalize versions - remove leading v, handle pre-release
  var normCurrent = current.replace(/^v/, """").split(""-"")[0];
  var normLatest = latest.replace(/^v/, """").split(""-"")[0];

  if (normCurrent === normLatest) return {{ isLatest: true, urgency: """" }};

  // Parse semver parts
  var currParts = normCurrent.split(""."").map(function(p) {{ return parseInt(p, 10) || 0; }});
  var lateParts = normLatest.split(""."").map(function(p) {{ return parseInt(p, 10) || 0; }});

  // Pad arrays to same length
  while (currParts.length < 3) currParts.push(0);
  while (lateParts.length < 3) lateParts.push(0);

  // Compare major.minor.patch
  var majorDiff = lateParts[0] - currParts[0];
  var minorDiff = lateParts[1] - currParts[1];
  var patchDiff = lateParts[2] - currParts[2];

  // Determine urgency based on version difference
  var urgency = ""upgrade-patch"";
  if (majorDiff > 0) {{
    urgency = ""upgrade-major"";
  }} else if (majorDiff === 0 && minorDiff > 0) {{
    urgency = ""upgrade-minor"";
  }} else if (majorDiff < 0 || (majorDiff === 0 && minorDiff < 0)) {{
    // Current is actually newer than latest
    return {{ isLatest: true, urgency: """" }};
  }}

  return {{ isLatest: false, urgency: urgency }};
}}

function navigateToPackage(packageIdOrName) {{
  // Normalize to lowercase for data-name lookup
  var nameLower = packageIdOrName.toLowerCase();

  // Try to find by ID first (case-preserved), then by data-name (lowercase)
  var target = document.getElementById('pkg-' + packageIdOrName) ||
               document.querySelector("".package-card[data-name='"" + nameLower + ""']"");

  if (target) {{
    showSection('packages');

    // If it's transitive, expand the transitive section
    if (target.classList.contains('transitive')) {{
      const list = document.getElementById('transitive-list');
      const toggle = document.getElementById('transitive-toggle');
      if (list && list.style.display === 'none') {{
        list.style.display = '';
        if (toggle) toggle.textContent = 'Hide';
      }}
    }}

    // Clear search/filter that might be hiding the package
    const searchInput = document.getElementById('package-search');
    if (searchInput && searchInput.value) {{
      searchInput.value = '';
      filterPackages();
    }}

    // Reset filters to show all packages
    currentStatusFilter = 'all';
    currentEcosystemFilter = 'all';
    document.querySelectorAll('.filter-btn').forEach(btn => {{
      btn.classList.remove('active');
      if (btn.textContent.toLowerCase() === 'all') btn.classList.add('active');
    }});
    document.querySelectorAll('.package-card').forEach(card => card.style.display = '');

    // Expand and highlight the package
    target.classList.add('expanded');
    setTimeout(() => {{
      target.scrollIntoView({{ behavior: 'smooth', block: 'center' }});
      target.classList.add('highlight-flash');
      setTimeout(() => target.classList.remove('highlight-flash'), 2000);
    }}, 100);
    return;
  }}

  // Try dependency tree
  const treeNode = document.querySelector(`.tree-node[data-name='${{nameLower}}']`);
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
    return;
  }}

  // Package not found - open external link (NuGet for .NET, npm for JS)
  const ecosystem = document.querySelector('.package-card')?.dataset.ecosystem || 'nuget';
  if (ecosystem === 'npm') {{
    window.open('https://www.npmjs.com/package/' + encodeURIComponent(packageIdOrName), '_blank');
  }} else {{
    window.open('https://www.nuget.org/packages/' + encodeURIComponent(packageIdOrName), '_blank');
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

function sortPackages(sortBy, isInitial) {{
  if (!isInitial) {{
    document.querySelectorAll('.filter-btn.sort-btn').forEach(btn => btn.classList.remove('active'));
    event.target.classList.add('active');
  }}

  // Sort comparator with name as tiebreaker
  const compare = (a, b) => {{
    let result = 0;
    if (sortBy === 'name') {{
      result = a.dataset.name.localeCompare(b.dataset.name);
    }} else if (sortBy === 'health') {{
      result = parseInt(a.dataset.health || 50) - parseInt(b.dataset.health || 50);
      if (result === 0) result = a.dataset.name.localeCompare(b.dataset.name);
    }} else if (sortBy === 'cra') {{
      result = parseInt(a.dataset.cra || 50) - parseInt(b.dataset.cra || 50);
      if (result === 0) result = a.dataset.name.localeCompare(b.dataset.name);
    }}
    return result;
  }};

  // Sort direct packages
  const directList = document.getElementById('packages-list');
  const directCards = Array.from(directList.querySelectorAll('.package-card:not(.transitive)'));
  directCards.sort(compare);
  directCards.forEach(card => directList.appendChild(card));

  // Sort transitive packages
  const transitiveList = document.getElementById('transitive-list');
  if (transitiveList) {{
    const transitiveCards = Array.from(transitiveList.querySelectorAll('.package-card.transitive'));
    transitiveCards.sort(compare);
    transitiveCards.forEach(card => transitiveList.appendChild(card));
  }}

  // Sort sub-dependency packages
  const subdepsList = document.getElementById('subdeps-list');
  if (subdepsList) {{
    const subdepsCards = Array.from(subdepsList.querySelectorAll('.package-card.transitive'));
    subdepsCards.sort(compare);
    subdepsCards.forEach(card => subdepsList.appendChild(card));
  }}
}}

// Apply default sort on page load
document.addEventListener('DOMContentLoaded', () => sortPackages('health', true));

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

function toggleSubDeps() {{
  const list = document.getElementById('subdeps-list');
  const toggle = document.getElementById('subdeps-toggle');
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

function exportSbom(format) {{
  if (!_hasSbomData) return;
  var raw = document.getElementById('sbom-json').textContent;
  var data = JSON.stringify(JSON.parse(raw), null, 2);
  var filename = format === 'spdx' ? 'sbom.spdx.json' : 'sbom.cyclonedx.json';
  var type = 'application/json';

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

// CRA Score Breakdown Popover
var _activePopover = null;

function renderCraBreakdown(pkg) {{
  var wVuln=15, wKev=15, wPatch=8, wEpss=7, wMaint=11, wProv=4, wLic=2, wIdent=2;
  var total = wVuln+wKev+wPatch+wEpss+wMaint+wProv+wLic+wIdent;

  // 1. Vulnerabilities
  var vulnPts = pkg.vulnCount === 0 ? wVuln : pkg.vulnCount === 1 ? wVuln*0.3 : pkg.vulnCount === 2 ? wVuln*0.1 : 0;

  // 2. KEV
  var kevPts = pkg.hasKev ? 0 : wKev;

  // 3. Patch timeliness
  var patchPts = wPatch;
  if (pkg.patchPendingCount > 0) {{
    var d = pkg.oldestUnpatchedDays || 0;
    patchPts = d <= 7 ? wPatch*0.7 : d <= 30 ? wPatch*0.4 : d <= 90 ? wPatch*0.15 : 0;
  }}

  // 4. EPSS
  var epss = pkg.maxEpss || 0;
  var epssPts = epss === 0 ? wEpss : epss < 0.01 ? wEpss*0.8 : epss < 0.1 ? wEpss*0.4 : epss < 0.5 ? wEpss*0.15 : 0;

  // 5. Maintenance
  var actDays = pkg.daysSinceLastCommit != null ? pkg.daysSinceLastCommit : pkg.daysSinceLastRelease;
  var maintPts;
  if (actDays != null) {{
    maintPts = actDays <= 90 ? wMaint : actDays <= 180 ? wMaint*0.8 : actDays <= 365 ? wMaint*0.6 : actDays <= 730 ? wMaint*0.3 : 0;
  }} else {{
    maintPts = wMaint * 0.4;
  }}

  // 6. Provenance
  var provPts = 0;
  if (pkg.hasIntegrity) provPts += wProv * 0.6;
  if (pkg.authorCount > 0) provPts += wProv * 0.4;

  // 7. License
  var licPts = 0;
  if (pkg.license && pkg.license.trim()) {{
    licPts = wLic * 0.6;
    var upper = pkg.license.trim().toUpperCase();
    var spdx = ['MIT','APACHE-2.0','ISC','BSD-2-CLAUSE','BSD-3-CLAUSE','GPL-2.0','GPL-3.0','LGPL-2.1','LGPL-3.0','MPL-2.0','0BSD','UNLICENSE','CC0-1.0','WTFPL','ZLIB','ARTISTIC-2.0','CDDL-1.0','EPL-2.0','EUPL-1.2','AFL-3.0','BSL-1.0','POSTGRESQL','BLUEOAK-1.0.0','MIT-0'];
    for (var s = 0; s < spdx.length; s++) {{
      if (upper === spdx[s] || upper.indexOf(spdx[s]) >= 0) {{ licPts = wLic; break; }}
    }}
  }}

  // Provenance fix text based on what's actually missing
  var provFix = [];
  if (!pkg.hasIntegrity) provFix.push('No content checksum available');
  if (pkg.authorCount === 0) provFix.push('No supplier/author info');
  var provFixText = provFix.length > 0 ? provFix.join('; ') : 'Verify package source';

  var criteria = [
    {{ name: 'Vulnerabilities', pts: vulnPts, max: wVuln, ref: 'Art. 11', tip: 'Known security vulnerabilities in this package version. Update to patched versions to resolve.', fix: 'Update to patched versions' }},
    {{ name: 'Known Exploits (KEV)', pts: kevPts, max: wKev, ref: 'Art. 10(4)', tip: 'Whether this package has CVEs listed in CISA Known Exploited Vulnerabilities catalog. These are actively exploited in the wild.', fix: 'Replace or patch immediately' }},
    {{ name: 'Patch Timeliness', pts: patchPts, max: wPatch, ref: 'Art. 11(4)', tip: 'How quickly available security patches have been applied. Measures days since patch became available.', fix: 'Apply available patches' }},
    {{ name: 'Exploit Probability', pts: epssPts, max: wEpss, ref: 'Art. 10(4)', tip: 'EPSS score \u2014 the probability this package\u2019s vulnerabilities will be exploited within 30 days. Lower is better.', fix: 'Prioritize high-EPSS packages' }},
    {{ name: 'Maintenance', pts: maintPts, max: wMaint, ref: 'Art. 13(8)', tip: 'How recently the package was maintained, based on last commit or release. Stale packages may not receive security fixes.', fix: 'Consider alternatives if stale' }},
    {{ name: 'Provenance', pts: provPts, max: wProv, ref: 'Art. 13(5)', tip: 'Supply chain integrity \u2014 whether the package has a content checksum (integrity hash) and identified supplier/author.', fix: provFixText }},
    {{ name: 'License', pts: licPts, max: wLic, ref: 'Art. 10(9)', tip: 'Whether the package declares a recognized SPDX license. Needed for legal compliance and CRA documentation.', fix: 'Add license info' }}
  ];

  var html = '<div class=""score-popover-title"">CRA Readiness Breakdown &mdash; ' + pkg.craScore + '/100</div>';
  for (var i = 0; i < criteria.length; i++) {{
    var c = criteria[i];
    var pct = c.max > 0 ? Math.round(c.pts / c.max * 100) : 0;
    var full = pct >= 95;
    var icon = full ? '<span style=""color:#28a745"">&#10003;</span>' : '<span style=""color:#ffc107"">&#9888;</span>';
    var ptsStr = c.pts % 1 === 0 ? c.pts.toString() : c.pts.toFixed(1);
    html += '<div class=""score-popover-criterion"" title=""' + (c.tip || '') + '"">';
    html += '<div class=""score-popover-row"">';
    html += '<span class=""score-popover-row-icon"">' + icon + '</span>';
    html += '<span class=""score-popover-row-name"">' + c.name + '</span>';
    html += '<span class=""score-popover-row-pts"">' + ptsStr + '/' + c.max + '</span>';
    html += '<span class=""score-popover-row-ref"">' + c.ref + '</span>';
    html += '</div>';
    if (!full) {{
      html += '<div class=""score-popover-row-fix"">' + c.fix + '</div>';
    }}
    html += '</div>';
  }}
  return html;
}}

function renderHealthBreakdown(pkg) {{
  var wFresh=25, wCadence=15, wTrend=20, wActivity=25, wVuln=15;

  // 1. Freshness (daysSinceLastRelease)
  var freshRaw;
  if (pkg.daysSinceLastRelease == null) {{ freshRaw = 60; }}
  else if (pkg.daysSinceLastRelease <= 30) {{ freshRaw = 100; }}
  else if (pkg.daysSinceLastRelease <= 90) {{ freshRaw = 90; }}
  else if (pkg.daysSinceLastRelease <= 180) {{ freshRaw = 80; }}
  else if (pkg.daysSinceLastRelease <= 365) {{ freshRaw = 70; }}
  else if (pkg.daysSinceLastRelease <= 730) {{ freshRaw = 50; }}
  else if (pkg.daysSinceLastRelease <= 1095) {{ freshRaw = 30; }}
  else {{ freshRaw = 10; }}
  var freshPts = freshRaw / 100 * wFresh;

  // 2. Release Cadence (releasesPerYear)
  var cadRaw;
  var rpy = pkg.releasesPerYear || 0;
  if (rpy >= 2 && rpy <= 12) {{ cadRaw = 100; }}
  else if (rpy >= 1 && rpy < 2) {{ cadRaw = 70; }}
  else if (rpy > 12 && rpy <= 24) {{ cadRaw = 80; }}
  else if (rpy > 24) {{ cadRaw = 60; }}
  else {{ cadRaw = 40; }}
  var cadPts = cadRaw / 100 * wCadence;

  // 3. Download Trend
  var trend = pkg.downloadTrend || 0;
  var trendRaw = (trend + 1.0) * 50.0;
  var trendPts = Math.min(Math.max(trendRaw, 0), 100) / 100 * wTrend;

  // 4. Repository Activity (daysSinceLastCommit, stars, openIssues)
  var actRaw;
  if (pkg.daysSinceLastCommit == null) {{ actRaw = 50; }}
  else {{
    var dsc = pkg.daysSinceLastCommit;
    if (dsc <= 7) {{ actRaw = 100; }}
    else if (dsc <= 30) {{ actRaw = 90; }}
    else if (dsc <= 90) {{ actRaw = 80; }}
    else if (dsc <= 180) {{ actRaw = 60; }}
    else if (dsc <= 365) {{ actRaw = 40; }}
    else {{ actRaw = 20; }}
    var starBonus = (pkg.stars || 0) >= 10000 ? 10 : (pkg.stars || 0) >= 1000 ? 5 : (pkg.stars || 0) >= 100 ? 2 : 0;
    var issuePenalty = 0;
    if ((pkg.stars || 0) > 0 && (pkg.openIssues || 0) > 0) {{
      var ratio = pkg.openIssues / pkg.stars;
      issuePenalty = ratio > 0.5 ? 10 : ratio > 0.2 ? 5 : 0;
    }}
    actRaw = Math.min(Math.max(actRaw + starBonus - issuePenalty, 0), 100);
  }}
  var actPts = actRaw / 100 * wActivity;

  // 5. Vulnerabilities
  var vulnRaw = pkg.vulnCount === 0 ? 100 : pkg.vulnCount === 1 ? 50 : pkg.vulnCount === 2 ? 25 : 0;
  var vulnPts = vulnRaw / 100 * wVuln;

  var criteria = [
    {{ name: 'Freshness', pts: freshPts, max: wFresh, weight: '25%', tip: 'How recently the package was released. Packages not updated in years may lack security fixes.', fix: 'Update to latest version' }},
    {{ name: 'Release Cadence', pts: cadPts, max: wCadence, weight: '15%', tip: 'How often new versions are published. Ideal: 2\u201312 releases/year. Too few suggests abandonment, too many may indicate instability.', fix: 'Consider more active alternatives' }},
    {{ name: 'Download Trend', pts: trendPts, max: wTrend, weight: '20%', tip: 'Whether download volume is growing, stable, or declining. Declining adoption may signal the community is moving away.', fix: 'Check for declining adoption' }},
    {{ name: 'Repository Activity', pts: actPts, max: wActivity, weight: '25%', tip: 'Recent commits, star count, and issue-to-star ratio. Active repos are more likely to receive timely security patches.', fix: 'Check repository status' }},
    {{ name: 'Vulnerabilities', pts: vulnPts, max: wVuln, weight: '15%', tip: 'Known security vulnerabilities (CVEs) in this package version. Zero is ideal.', fix: 'Update to patched versions' }}
  ];

  var html = '<div class=""score-popover-title"">Health Score Breakdown &mdash; ' + pkg.score + '/100</div>';
  for (var i = 0; i < criteria.length; i++) {{
    var c = criteria[i];
    var pct = c.max > 0 ? Math.round(c.pts / c.max * 100) : 0;
    var full = pct >= 95;
    var icon = full ? '<span style=""color:#28a745"">&#10003;</span>' : '<span style=""color:#ffc107"">&#9888;</span>';
    var ptsStr = c.pts % 1 === 0 ? c.pts.toString() : c.pts.toFixed(1);
    html += '<div class=""score-popover-criterion"" title=""' + (c.tip || '') + '"">';
    html += '<div class=""score-popover-row"">';
    html += '<span class=""score-popover-row-icon"">' + icon + '</span>';
    html += '<span class=""score-popover-row-name"">' + c.name + '</span>';
    html += '<span class=""score-popover-row-pts"">' + ptsStr + '/' + c.max + '</span>';
    html += '<span class=""score-popover-row-ref"">' + c.weight + '</span>';
    html += '</div>';
    if (!full) {{
      html += '<div class=""score-popover-row-fix"">' + c.fix + '</div>';
    }}
    html += '</div>';
  }}
  return html;
}}

function showScorePopover(event, pkgId, type) {{
  event.stopPropagation();
  event.preventDefault();

  // Close existing popover
  if (_activePopover) {{
    _activePopover.remove();
    var wasSame = _activePopover.dataset.pkgId === pkgId && _activePopover.dataset.popType === type;
    _activePopover = null;
    if (wasSame) return;
  }}

  var pkg = packageData[pkgId] || packageData[pkgId.toLowerCase()];
  if (!pkg) return;

  var el = event.currentTarget;
  var rect = el.getBoundingClientRect();
  var popover = document.createElement('div');
  popover.className = 'score-popover';
  popover.dataset.pkgId = pkgId;
  popover.dataset.popType = type;
  popover.innerHTML = type === 'health' ? renderHealthBreakdown(pkg) : renderCraBreakdown(pkg);
  popover.addEventListener('click', function(e) {{ e.stopPropagation(); }});
  document.body.appendChild(popover);

  // Position below the badge, right-aligned
  var popW = 360;
  var left = rect.right - popW;
  if (left < 8) left = 8;
  var top = rect.bottom + 6;
  // If it would go off the bottom, show above instead
  if (top + popover.offsetHeight > window.innerHeight - 8) {{
    top = rect.top - popover.offsetHeight - 6;
  }}
  popover.style.left = left + 'px';
  popover.style.top = top + 'px';

  _activePopover = popover;
}}

document.addEventListener('click', function() {{
  if (_activePopover) {{
    _activePopover.remove();
    _activePopover = null;
  }}
}});

// SBOM field card click-to-expand (lazy-populated from sbomMissingData)
document.querySelectorAll('.field-card-clickable').forEach(function(card) {{
  card.addEventListener('click', function() {{
    var list = card.querySelector('.field-missing-list');
    if (!list) return;
    // Lazy populate on first click
    if (!list.dataset.loaded && sbomMissingData) {{
      var field = list.dataset.field;
      var items = sbomMissingData[field] || [];
      items.forEach(function(pkg) {{
        var div = document.createElement('div');
        div.className = 'field-missing-item';
        div.textContent = pkg;
        list.appendChild(div);
      }});
      list.dataset.loaded = 'true';
    }}
    var isOpen = list.style.display !== 'none';
    list.style.display = isOpen ? 'none' : 'block';
    card.classList.toggle('expanded', !isOpen);
  }});
}});
</script>";
    }
}
