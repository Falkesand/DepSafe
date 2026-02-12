using System.Collections.Frozen;
using System.Text;
using DepSafe.Models;

namespace DepSafe.Compliance;

public sealed partial class CraReportGenerator
{
    internal static string GetScoreClass(int score) => score switch
    {
        >= 80 => "healthy",
        >= 60 => "watch",
        >= 40 => "warning",
        _ => "critical"
    };

    internal static string GetCraScoreClass(int score) => score switch
    {
        >= 90 => "healthy",
        >= 70 => "watch",
        >= 50 => "warning",
        _ => "critical"
    };

    internal static string GetTrustScoreClass(int score) => score switch
    {
        >= 80 => "healthy",
        >= 60 => "watch",
        >= 40 => "warning",
        _ => "critical"
    };

    private static string GetCraBadgeTooltip(PackageHealth? pkg)
    {
        if (pkg is null) return "CRA Readiness Score";
        var status = pkg.CraStatus switch
        {
            CraComplianceStatus.Compliant => "Compliant",
            CraComplianceStatus.Review => "Review needed",
            CraComplianceStatus.ActionRequired => "Action required",
            CraComplianceStatus.NonCompliant => "Non-compliant",
            _ => "Unknown"
        };
        return $"CRA Readiness: {pkg.CraScore}/100 - {status}";
    }

    private static string GetEpssBadgeClass(double probability) => probability switch
    {
        >= 0.5 => "epss-critical",
        >= 0.1 => "epss-high",
        >= 0.01 => "epss-medium",
        _ => "epss-low"
    };

    private static readonly string[] LicenseSeparators = [" OR ", " AND ", " WITH "];

    private static readonly FrozenSet<string> s_knownSpdxLicenses = FrozenSet.ToFrozenSet(
    [
        "MIT", "MIT-0",
        "APACHE-2.0", "APACHE 2.0", "APACHE2",
        "BSD-2-CLAUSE", "BSD-3-CLAUSE", "0BSD",
        "ISC",
        "GPL-2.0", "GPL-3.0", "GPL-2.0-ONLY", "GPL-3.0-ONLY", "GPL-2.0-OR-LATER", "GPL-3.0-OR-LATER",
        "LGPL-2.1", "LGPL-3.0", "LGPL-2.1-ONLY", "LGPL-3.0-ONLY", "LGPL-2.1-OR-LATER", "LGPL-3.0-OR-LATER",
        "MPL-2.0",
        "UNLICENSE", "UNLICENSED",
        "CC0-1.0", "CC-BY-4.0",
        "BSL-1.0",
        "WTFPL",
        "ZLIB",
        "MS-PL", "MS-RL",
        "CLASSPATH-EXCEPTION-2.0", "LLVM-EXCEPTION"
    ], StringComparer.OrdinalIgnoreCase);

    private static bool IsKnownSpdxLicense(string license)
    {
        var normalized = license.Trim().TrimStart('(').TrimEnd(')').Trim();
        var parts = normalized.Split(LicenseSeparators, StringSplitOptions.RemoveEmptyEntries);

        if (parts.Length > 1)
        {
            return parts.All(p => s_knownSpdxLicenses.Contains(p.Trim().TrimStart('(').TrimEnd(')').Trim()));
        }

        return s_knownSpdxLicenses.Contains(normalized);
    }

    internal static string FormatNumber(long number) => number switch
    {
        >= 1_000_000_000 => $"{number / 1_000_000_000.0:F1}B",
        >= 1_000_000 => $"{number / 1_000_000.0:F1}M",
        >= 1_000 => $"{number / 1_000.0:F1}K",
        _ => number.ToString()
    };

    internal static string FormatDownloads(long downloads) =>
        downloads == 0 ? "N/A" : FormatNumber(downloads);

    internal static string FormatDuration(TimeSpan duration) => duration.TotalSeconds switch
    {
        < 1 => $"{duration.TotalMilliseconds:F0}ms",
        < 60 => $"{duration.TotalSeconds:F1}s",
        < 3600 => $"{duration.Minutes}m {duration.Seconds}s",
        _ => $"{duration.Hours}h {duration.Minutes}m"
    };

    // Known SPDX license URLs
    private static readonly FrozenDictionary<string, string> LicenseUrls = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
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
    }.ToFrozenDictionary(StringComparer.OrdinalIgnoreCase);

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
            catch (FormatException) { /* Use default display name */ }

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
            return $"<span class=\"unresolved-version\" title=\"MSBuild variable not resolved: {EscapeHtml(version)}\">Not resolved \u2139</span>";
        }

        return EscapeHtml(version);
    }

    private static string FormatPurlForSbom(string? purl)
    {
        if (string.IsNullOrEmpty(purl))
            return "<span class=\"text-muted\">-</span>";

        if (purl.Contains("$("))
        {
            // Extract the package name from the purl using compiled regex
            var match = PurlRegex().Match(purl);
            if (match.Success)
            {
                return $"<span class=\"unresolved-version\" title=\"Full PURL: {EscapeHtml(purl)}\">pkg:nuget/{EscapeHtml(match.Groups[1].Value)}@? \u2139</span>";
            }
            return $"<span class=\"unresolved-version\" title=\"{EscapeHtml(purl)}\">Not resolved \u2139</span>";
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
            return $"<span class=\"unresolved-version\" title=\"{EscapeHtml(tooltip)}\">Version not resolved <span class=\"version-hint\">\u2139</span></span>";
        }

        return EscapeHtml(version);
    }

    private static readonly FrozenDictionary<string, string> s_licenseUrlMap = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
    {
        ["MIT"] = "https://spdx.org/licenses/MIT.html",
        ["APACHE-2.0"] = "https://spdx.org/licenses/Apache-2.0.html",
        ["APACHE 2.0"] = "https://spdx.org/licenses/Apache-2.0.html",
        ["APACHE2"] = "https://spdx.org/licenses/Apache-2.0.html",
        ["BSD-2-CLAUSE"] = "https://spdx.org/licenses/BSD-2-Clause.html",
        ["BSD 2-CLAUSE"] = "https://spdx.org/licenses/BSD-2-Clause.html",
        ["BSD-3-CLAUSE"] = "https://spdx.org/licenses/BSD-3-Clause.html",
        ["BSD 3-CLAUSE"] = "https://spdx.org/licenses/BSD-3-Clause.html",
        ["GPL-2.0"] = "https://spdx.org/licenses/GPL-2.0-only.html",
        ["GPL-2.0-ONLY"] = "https://spdx.org/licenses/GPL-2.0-only.html",
        ["GPL2"] = "https://spdx.org/licenses/GPL-2.0-only.html",
        ["GPL-3.0"] = "https://spdx.org/licenses/GPL-3.0-only.html",
        ["GPL-3.0-ONLY"] = "https://spdx.org/licenses/GPL-3.0-only.html",
        ["GPL3"] = "https://spdx.org/licenses/GPL-3.0-only.html",
        ["GPL-3.0-OR-LATER"] = "https://spdx.org/licenses/GPL-3.0-or-later.html",
        ["LGPL-2.1"] = "https://spdx.org/licenses/LGPL-2.1-only.html",
        ["LGPL-2.1-ONLY"] = "https://spdx.org/licenses/LGPL-2.1-only.html",
        ["LGPL-3.0"] = "https://spdx.org/licenses/LGPL-3.0-only.html",
        ["LGPL-3.0-ONLY"] = "https://spdx.org/licenses/LGPL-3.0-only.html",
        ["ISC"] = "https://spdx.org/licenses/ISC.html",
        ["MPL-2.0"] = "https://spdx.org/licenses/MPL-2.0.html",
        ["UNLICENSE"] = "https://spdx.org/licenses/Unlicense.html",
        ["UNLICENSED"] = "https://spdx.org/licenses/Unlicense.html",
        ["CC0-1.0"] = "https://spdx.org/licenses/CC0-1.0.html",
        ["CC0"] = "https://spdx.org/licenses/CC0-1.0.html",
        ["WTFPL"] = "https://spdx.org/licenses/WTFPL.html",
        ["0BSD"] = "https://spdx.org/licenses/0BSD.html",
        ["MS-PL"] = "https://spdx.org/licenses/MS-PL.html",
        ["MS-RL"] = "https://spdx.org/licenses/MS-RL.html",
        ["ZLIB"] = "https://spdx.org/licenses/Zlib.html",
    }.ToFrozenDictionary(StringComparer.OrdinalIgnoreCase);

    private static string? GetLicenseUrl(string license)
    {
        var normalized = license.Trim();

        if (s_licenseUrlMap.TryGetValue(normalized, out var url))
            return url;

        return normalized.StartsWith("HTTP", StringComparison.OrdinalIgnoreCase)
            ? normalized
            : $"https://spdx.org/licenses/{Uri.EscapeDataString(normalized)}.html";
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
            var parts = text.Split(" OR ", StringSplitOptions.RemoveEmptyEntries);
            var linkedParts = parts.Select(p => FormatSingleLicenseLink(p.Trim()));
            return "(" + string.Join(" OR ", linkedParts) + ")";
        }

        if (text.Contains(" AND ", StringComparison.OrdinalIgnoreCase))
        {
            var parts = text.Split(" AND ", StringSplitOptions.RemoveEmptyEntries);
            var linkedParts = parts.Select(p => FormatSingleLicenseLink(p.Trim()));
            return "(" + string.Join(" AND ", linkedParts) + ")";
        }

        if (text.Contains(" WITH ", StringComparison.OrdinalIgnoreCase))
        {
            var parts = text.Split(" WITH ", StringSplitOptions.RemoveEmptyEntries);
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

    private static readonly char[] HtmlSpecialChars = ['&', '<', '>', '"', '\''];

    internal static string EscapeHtml(string input)
    {
        if (string.IsNullOrEmpty(input)) return input;

        // Fast path: if no special chars, return input directly (avoids ~90% of allocations)
        if (input.IndexOfAny(HtmlSpecialChars) < 0) return input;

        var sb = new StringBuilder(input.Length + 16);
        foreach (var c in input)
        {
            switch (c)
            {
                case '&': sb.Append("&amp;"); break;
                case '<': sb.Append("&lt;"); break;
                case '>': sb.Append("&gt;"); break;
                case '"': sb.Append("&quot;"); break;
                case '\'': sb.Append("&#39;"); break;
                default: sb.Append(c); break;
            }
        }
        return sb.ToString();
    }

    private static readonly char[] JsSpecialChars = ['\\', '\'', '"', '\n', '\r'];

    internal static string EscapeJs(string input)
    {
        if (string.IsNullOrEmpty(input)) return input;

        // Fast path: if no special chars, return input directly
        if (input.IndexOfAny(JsSpecialChars) < 0) return input;

        var sb = new StringBuilder(input.Length + 16);
        foreach (var c in input)
        {
            switch (c)
            {
                case '\\': sb.Append("\\\\"); break;
                case '\'': sb.Append("\\'"); break;
                case '"': sb.Append("\\\""); break;
                case '\n': sb.Append("\\n"); break;
                case '\r': sb.Append("\\r"); break;
                default: sb.Append(c); break;
            }
        }
        return sb.ToString();
    }

    internal static string MinifyCss(string css)
    {
        var sb = new StringBuilder(css.Length);
        var inComment = false;
        var i = 0;

        while (i < css.Length)
        {
            // Strip CSS comments
            if (!inComment && i + 1 < css.Length && css[i] == '/' && css[i + 1] == '*')
            {
                inComment = true;
                i += 2;
                continue;
            }
            if (inComment)
            {
                if (i + 1 < css.Length && css[i] == '*' && css[i + 1] == '/')
                {
                    inComment = false;
                    i += 2;
                }
                else
                {
                    i++;
                }
                continue;
            }

            var c = css[i];

            // Collapse newlines and carriage returns
            if (c == '\n' || c == '\r')
            {
                i++;
                continue;
            }

            // Collapse runs of whitespace to a single space
            if (c == ' ' || c == '\t')
            {
                // Skip whitespace after structural characters
                if (sb.Length > 0)
                {
                    var prev = sb[sb.Length - 1];
                    if (prev == '{' || prev == '}' || prev == ';' || prev == ':' || prev == ',')
                    {
                        i++;
                        continue;
                    }
                }

                // Collapse to single space, skip trailing whitespace
                sb.Append(' ');
                i++;
                while (i < css.Length && (css[i] == ' ' || css[i] == '\t' || css[i] == '\n' || css[i] == '\r'))
                    i++;
                continue;
            }

            // Skip whitespace before structural characters
            if ((c == '{' || c == '}' || c == ';' || c == ':' || c == ',') && sb.Length > 0 && sb[sb.Length - 1] == ' ')
            {
                sb[sb.Length - 1] = c;
                i++;
                continue;
            }

            sb.Append(c);
            i++;
        }

        return sb.ToString();
    }
}
