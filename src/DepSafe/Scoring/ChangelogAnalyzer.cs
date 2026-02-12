using DepSafe.Models;
using NuGet.Versioning;

namespace DepSafe.Scoring;

/// <summary>
/// Analyzes GitHub release note bodies for breaking change and deprecation signals.
/// </summary>
public static class ChangelogAnalyzer
{
    private static readonly string[] s_breakingPatterns =
        ["breaking", "removed", "renamed", "incompatible", "migration required", "no longer supports"];

    private static readonly string[] s_deprecationPatterns =
        ["deprecated", "obsolete", "will be removed", "end of life"];

    private const int MaxSnippetLength = 50;

    /// <summary>
    /// Analyze release notes between two versions for breaking/deprecation signals.
    /// </summary>
    public static ChangelogSignals Analyze(
        IReadOnlyList<ReleaseNote> releases,
        string fromVersion,
        string toVersion)
    {
        var breakingCount = 0;
        var deprecationCount = 0;
        var breakingSnippets = new List<string>();
        var deprecationSnippets = new List<string>();
        var releaseCount = 0;

        if (!NuGetVersion.TryParse(fromVersion, out var from) ||
            !NuGetVersion.TryParse(toVersion, out var to))
        {
            return new ChangelogSignals(0, 0, [], [], 0);
        }

        foreach (var release in releases)
        {
            // Parse tag name, stripping optional 'v' prefix
            var tag = release.TagName.StartsWith('v') || release.TagName.StartsWith('V')
                ? release.TagName[1..]
                : release.TagName;

            if (!NuGetVersion.TryParse(tag, out var version))
                continue;

            // Filter to versions between from (exclusive) and to (inclusive)
            if (version <= from || version > to)
                continue;

            releaseCount++;

            if (string.IsNullOrWhiteSpace(release.Body))
                continue;

            var body = release.Body;

            foreach (var pattern in s_breakingPatterns)
            {
                if (body.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                {
                    breakingCount++;
                    breakingSnippets.Add(ExtractSnippet(body, pattern));
                }
            }

            foreach (var pattern in s_deprecationPatterns)
            {
                if (body.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                {
                    deprecationCount++;
                    deprecationSnippets.Add(ExtractSnippet(body, pattern));
                }
            }
        }

        return new ChangelogSignals(
            breakingCount,
            deprecationCount,
            breakingSnippets,
            deprecationSnippets,
            releaseCount);
    }

    private static string ExtractSnippet(string body, string keyword)
    {
        var idx = body.IndexOf(keyword, StringComparison.OrdinalIgnoreCase);
        if (idx < 0) return "";

        // Take context around the keyword
        var start = Math.Max(0, idx - 10);
        var end = Math.Min(body.Length, idx + keyword.Length + 30);
        var snippet = body[start..end].ReplaceLineEndings(" ").Trim();

        return snippet.Length > MaxSnippetLength
            ? string.Concat(snippet.AsSpan(0, MaxSnippetLength), "...")
            : snippet;
    }
}
