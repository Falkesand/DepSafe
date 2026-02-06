using DepSafe.Models;
using DepSafe.Typosquatting;

namespace DepSafe.Tests;

public class TyposquatDetectorTests
{
    private static PopularPackageIndex CreateIndex(params string[] names)
    {
        var index = new PopularPackageIndex();
        foreach (var name in names)
        {
            index.Add(new PopularPackageEntry
            {
                Name = name,
                Downloads = 1_000_000,
                Ecosystem = PackageEcosystem.NuGet
            });
        }
        return index;
    }

    [Fact]
    public void Check_ExactMatch_ReturnsNoResults()
    {
        var index = CreateIndex("Newtonsoft.Json");
        var detector = new TyposquatDetector(index);

        var results = detector.Check("Newtonsoft.Json");

        Assert.Empty(results);
    }

    [Fact]
    public void Check_EditDistance1_DetectsTyposquat()
    {
        var index = CreateIndex("express");
        var detector = new TyposquatDetector(index);

        var results = detector.Check("expresss");

        Assert.Contains(results, r =>
            r.SimilarTo == "express" &&
            r.Method == TyposquatDetectionMethod.EditDistance);
    }

    [Fact]
    public void Check_EditDistance2_DetectsTyposquat()
    {
        var index = CreateIndex("lodash");
        var detector = new TyposquatDetector(index);

        var results = detector.Check("lodahs");

        Assert.Contains(results, r =>
            r.SimilarTo == "lodash" &&
            r.Method == TyposquatDetectionMethod.EditDistance);
    }

    [Fact]
    public void Check_Homoglyph_DetectsSubstitution()
    {
        var index = CreateIndex("colors");
        var detector = new TyposquatDetector(index);

        var results = detector.Check("col0rs");

        Assert.Contains(results, r =>
            r.SimilarTo == "colors" &&
            r.Method == TyposquatDetectionMethod.Homoglyph &&
            r.RiskLevel == TyposquatRiskLevel.Critical);
    }

    [Fact]
    public void Check_SeparatorSwap_DetectsVariant()
    {
        var index = CreateIndex("my-package");
        var detector = new TyposquatDetector(index);

        var results = detector.Check("my_package");

        // May be detected as edit distance (confidence 92) or separator swap (confidence 70);
        // dedup keeps highest confidence, so edit distance wins
        Assert.Contains(results, r => r.SimilarTo == "my-package");
    }

    [Fact]
    public void Check_PrefixSuffix_DetectsVariant()
    {
        var index = CreateIndex("lodash");
        var detector = new TyposquatDetector(index);

        var results = detector.Check("node-lodash");

        Assert.Contains(results, r =>
            r.SimilarTo == "lodash" &&
            r.Method == TyposquatDetectionMethod.PrefixSuffix);
    }

    [Fact]
    public void Check_ScopeConfusion_DetectsNpmScopes()
    {
        var index = new PopularPackageIndex();
        index.Add(new PopularPackageEntry
        {
            Name = "@types/node",
            Downloads = 50_000_000,
            Ecosystem = PackageEcosystem.Npm
        });

        var detector = new TyposquatDetector(index);

        var results = detector.Check("@typos/node", PackageEcosystem.Npm);

        // May be detected as edit distance or scope confusion; dedup keeps highest confidence
        Assert.Contains(results, r => r.SimilarTo == "@types/node");
    }

    [Fact]
    public void Check_ScopeConfusion_IgnoredForNuGet()
    {
        var index = CreateIndex("@types/node");
        var detector = new TyposquatDetector(index);

        // Scope confusion only applies to npm
        var results = detector.Check("@typos/node", PackageEcosystem.NuGet);

        Assert.DoesNotContain(results, r => r.Method == TyposquatDetectionMethod.ScopeConfusion);
    }

    [Fact]
    public void Check_CompletelyDifferentName_ReturnsNoResults()
    {
        var index = CreateIndex("lodash", "express", "react");
        var detector = new TyposquatDetector(index);

        var results = detector.Check("my-custom-package");

        // Should not find edit distance matches for completely different names
        Assert.DoesNotContain(results, r => r.Method == TyposquatDetectionMethod.EditDistance);
    }

    [Fact]
    public void Check_DeduplicatesByPopularPackage()
    {
        // A name might trigger both edit distance and separator normalization
        var index = CreateIndex("my-lib");
        var detector = new TyposquatDetector(index);

        var results = detector.Check("my_lib");

        // Should have at most one result per popular package (highest confidence wins)
        var groupedResults = results.GroupBy(r => r.SimilarTo, StringComparer.OrdinalIgnoreCase);
        Assert.All(groupedResults, g => Assert.Single(g));
    }

    [Fact]
    public void CheckAll_MultipleDeps_ReturnsAggregatedResults()
    {
        var index = CreateIndex("express", "lodash");
        var detector = new TyposquatDetector(index);

        var results = detector.CheckAll(["expresss", "lodahs"]);

        Assert.True(results.Count >= 2);
    }

    [Fact]
    public void Check_EditDistance1_HasHighConfidence()
    {
        var index = CreateIndex("express");
        var detector = new TyposquatDetector(index);

        var results = detector.Check("expresss");

        var match = results.FirstOrDefault(r => r.Method == TyposquatDetectionMethod.EditDistance);
        Assert.NotNull(match);
        Assert.True(match.Confidence >= 90);
        Assert.Equal(TyposquatRiskLevel.High, match.RiskLevel);
    }
}
