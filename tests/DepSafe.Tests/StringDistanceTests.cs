using DepSafe.Typosquatting;

namespace DepSafe.Tests;

public class StringDistanceTests
{
    // --- Damerau-Levenshtein ---

    [Theory]
    [InlineData("lodash", "lodash", 0)]     // Exact match
    [InlineData("lodahs", "lodash", 1)]     // Transposition
    [InlineData("lodas", "lodash", 1)]      // Deletion
    [InlineData("lodashe", "lodash", 1)]    // Insertion
    [InlineData("lodush", "lodash", 1)]     // Substitution
    [InlineData("lodaahsh", "lodash", 2)]   // Two edits
    [InlineData("abc", "xyz", 3)]           // Completely different (distance 3)
    public void DamerauLevenshtein_ComputesCorrectDistance(string source, string target, int expected)
    {
        var result = StringDistance.DamerauLevenshtein(source, target, maxDistance: 3);
        Assert.Equal(expected, result);
    }

    [Fact]
    public void DamerauLevenshtein_EarlyExit_ReturnsExceededDistance()
    {
        // "abc" vs "xyz" has distance 3, with maxDistance 2 should return > 2
        var result = StringDistance.DamerauLevenshtein("abc", "xyz", maxDistance: 2);
        Assert.True(result > 2);
    }

    [Fact]
    public void DamerauLevenshtein_EmptyStrings()
    {
        Assert.Equal(0, StringDistance.DamerauLevenshtein("", ""));
        Assert.Equal(3, StringDistance.DamerauLevenshtein("abc", ""));
        Assert.Equal(3, StringDistance.DamerauLevenshtein("", "abc"));
    }

    [Fact]
    public void DamerauLevenshtein_LengthDifferencePruning()
    {
        // Length difference > maxDistance should short-circuit
        var result = StringDistance.DamerauLevenshtein("ab", "abcde", maxDistance: 2);
        Assert.True(result > 2);
    }

    // --- Homoglyph Normalization ---

    [Theory]
    [InlineData("c0lors", "colors")]        // 0 → o
    [InlineData("co1ors", "colors")]        // 1 → l (then colors)
    [InlineData("5tring", "string")]        // 5 → s
    [InlineData("exarnple", "example")]     // rn → m
    [InlineData("nevv", "new")]             // vv → w
    public void NormalizeHomoglyphs_ReplacesCommonHomoglyphs(string input, string expected)
    {
        Assert.Equal(expected, StringDistance.NormalizeHomoglyphs(input));
    }

    [Fact]
    public void IsHomoglyphMatch_DetectsHomoglyphSubstitution()
    {
        Assert.True(StringDistance.IsHomoglyphMatch("col0rs", "colors"));
        Assert.True(StringDistance.IsHomoglyphMatch("exarnple", "example"));
    }

    [Fact]
    public void IsHomoglyphMatch_RejectsSameString()
    {
        Assert.False(StringDistance.IsHomoglyphMatch("colors", "colors"));
    }

    // --- Separator Normalization ---

    [Theory]
    [InlineData("my-package", "my-package")]
    [InlineData("my.package", "my-package")]
    [InlineData("my_package", "my-package")]
    public void NormalizeSeparators_NormalizesToHyphen(string input, string expected)
    {
        Assert.Equal(expected, StringDistance.NormalizeSeparators(input));
    }

    [Fact]
    public void IsSeparatorMatch_DetectsSeparatorSwap()
    {
        Assert.True(StringDistance.IsSeparatorMatch("my_package", "my-package"));
        Assert.True(StringDistance.IsSeparatorMatch("my.package", "my-package"));
    }

    [Fact]
    public void IsSeparatorMatch_RejectsSameString()
    {
        Assert.False(StringDistance.IsSeparatorMatch("my-package", "my-package"));
    }

    // --- Prefix/Suffix Detection ---

    [Theory]
    [InlineData("node-lodash", "lodash", true)]
    [InlineData("lodash-js", "lodash", true)]
    [InlineData("lodash.core", "lodash", true)]
    [InlineData("express", "express", false)]       // Same name
    [InlineData("node-ab", "ab", false)]            // Too short (< 4)
    public void IsPrefixSuffixMatch_DetectsVariants(string candidate, string popular, bool expected)
    {
        Assert.Equal(expected, StringDistance.IsPrefixSuffixMatch(candidate, popular));
    }

    // --- Scope Confusion ---

    [Fact]
    public void IsScopeConfusion_DetectsSimilarScopes()
    {
        Assert.True(StringDistance.IsScopeConfusion("@typos/node", "@types/node"));
    }

    [Fact]
    public void IsScopeConfusion_RejectsNonScopedPackages()
    {
        Assert.False(StringDistance.IsScopeConfusion("lodash", "express"));
    }

    [Fact]
    public void IsScopeConfusion_RejectsDifferentPackageNames()
    {
        Assert.False(StringDistance.IsScopeConfusion("@types/node", "@types/express"));
    }
}
