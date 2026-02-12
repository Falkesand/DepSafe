using DepSafe.Models;
using DepSafe.Scoring;

namespace DepSafe.Tests;

public class ChangelogAnalyzerTests
{
    private static ReleaseNote MakeRelease(string tag, string? body, string date = "2024-06-15")
        => new(tag, body, DateTime.Parse(date));

    [Fact]
    public void Analyze_BreakingKeywords_CountsCorrectly()
    {
        var releases = new List<ReleaseNote>
        {
            MakeRelease("v2.0.0", "This release has BREAKING changes. Removed old API."),
            MakeRelease("v2.1.0", "Renamed configuration option."),
        };

        var result = ChangelogAnalyzer.Analyze(releases, "1.0.0", "3.0.0");

        Assert.Equal(3, result.BreakingChangeCount); // breaking, removed, renamed
        Assert.Equal(3, result.BreakingSnippets.Count);
    }

    [Fact]
    public void Analyze_NoSignals_ReturnsZeroCounts()
    {
        var releases = new List<ReleaseNote>
        {
            MakeRelease("v1.1.0", "Bug fixes and performance improvements."),
        };

        var result = ChangelogAnalyzer.Analyze(releases, "1.0.0", "2.0.0");

        Assert.Equal(0, result.BreakingChangeCount);
        Assert.Equal(0, result.DeprecationCount);
        Assert.Empty(result.BreakingSnippets);
        Assert.Empty(result.DeprecationSnippets);
    }

    [Fact]
    public void Analyze_FiltersReleasesOutsideVersionRange()
    {
        var releases = new List<ReleaseNote>
        {
            MakeRelease("v0.9.0", "BREAKING: total rewrite"),
            MakeRelease("v1.5.0", "Deprecated old endpoint."),
            MakeRelease("v3.0.0", "BREAKING: new architecture"),
        };

        // Only v1.5.0 is between 1.0.0 and 2.0.0
        var result = ChangelogAnalyzer.Analyze(releases, "1.0.0", "2.0.0");

        Assert.Equal(0, result.BreakingChangeCount);
        Assert.Equal(1, result.DeprecationCount);
        Assert.Equal(1, result.ReleaseCount);
    }

    [Fact]
    public void Analyze_CaseInsensitiveMatching()
    {
        var releases = new List<ReleaseNote>
        {
            MakeRelease("v1.1.0", "BREAKING change. Deprecated method. OBSOLETE class."),
        };

        var result = ChangelogAnalyzer.Analyze(releases, "1.0.0", "2.0.0");

        Assert.Equal(1, result.BreakingChangeCount);
        Assert.Equal(2, result.DeprecationCount); // deprecated + obsolete
    }

    [Fact]
    public void Analyze_EmptyReleaseBody_Skipped()
    {
        var releases = new List<ReleaseNote>
        {
            MakeRelease("v1.1.0", null),
            MakeRelease("v1.2.0", ""),
            MakeRelease("v1.3.0", "   "),
        };

        var result = ChangelogAnalyzer.Analyze(releases, "1.0.0", "2.0.0");

        Assert.Equal(0, result.BreakingChangeCount);
        Assert.Equal(0, result.DeprecationCount);
        Assert.Equal(3, result.ReleaseCount); // all 3 in range, even with empty body
    }
}
