using DepSafe.Models;

namespace DepSafe.Typosquatting;

/// <summary>
/// Multi-layer typosquatting detection orchestrator.
/// Compares dependency names against popular package index using multiple detection strategies.
/// </summary>
public sealed class TyposquatDetector
{
    private readonly PopularPackageIndex _index;

    public TyposquatDetector(PopularPackageIndex index)
    {
        _index = index;
    }

    /// <summary>
    /// Check a single dependency name for potential typosquatting.
    /// Returns all matches found across detection layers.
    /// </summary>
    public List<TyposquatResult> Check(string packageName, PackageEcosystem ecosystem = PackageEcosystem.NuGet)
    {
        var results = new List<TyposquatResult>();

        // If the package IS a popular package, no typosquatting
        if (_index.Contains(packageName))
            return results;

        var lowerName = packageName.ToLowerInvariant();
        var normalizedCandidateHomoglyph = StringDistance.NormalizeHomoglyphs(lowerName);

        // Layers 1-3: Single pass over length-bucketed candidates
        foreach (var candidate in _index.FindCandidates(packageName))
        {
            if (string.Equals(packageName, candidate.Name, StringComparison.OrdinalIgnoreCase))
                continue;

            // Layer 1: Damerau-Levenshtein distance
            var distance = StringDistance.DamerauLevenshtein(
                lowerName.AsSpan(),
                candidate.NormalizedName.AsSpan(),
                maxDistance: 2);

            if (distance <= 2)
            {
                var confidence = distance == 1 ? 92 : 75;
                var riskLevel = distance == 1 ? TyposquatRiskLevel.High : TyposquatRiskLevel.Medium;

                results.Add(new TyposquatResult
                {
                    PackageName = packageName,
                    SimilarTo = candidate.Name,
                    Method = TyposquatDetectionMethod.EditDistance,
                    RiskLevel = riskLevel,
                    Confidence = confidence,
                    Detail = $"edit distance: {distance}",
                    Ecosystem = ecosystem
                });
            }

            // Layer 2: Homoglyph normalization (using pre-computed values to avoid per-candidate allocations)
            if (normalizedCandidateHomoglyph == candidate.HomoglyphNormalizedName &&
                !string.Equals(packageName, candidate.Name, StringComparison.OrdinalIgnoreCase))
            {
                var detail = DetectHomoglyphDetail(lowerName, candidate.NormalizedName);

                results.Add(new TyposquatResult
                {
                    PackageName = packageName,
                    SimilarTo = candidate.Name,
                    Method = TyposquatDetectionMethod.Homoglyph,
                    RiskLevel = TyposquatRiskLevel.Critical,
                    Confidence = 98,
                    Detail = detail,
                    Ecosystem = ecosystem
                });
            }

            // Layer 3: Separator normalization
            if (StringDistance.IsSeparatorMatchCore(lowerName, candidate.NormalizedName))
            {
                results.Add(new TyposquatResult
                {
                    PackageName = packageName,
                    SimilarTo = candidate.Name,
                    Method = TyposquatDetectionMethod.SeparatorSwap,
                    RiskLevel = TyposquatRiskLevel.Medium,
                    Confidence = 70,
                    Detail = "separator swap",
                    Ecosystem = ecosystem
                });
            }
        }

        // Layers 4 & 5: Single pass over all entries
        var checkScopeConfusion = ecosystem == PackageEcosystem.Npm && packageName.StartsWith('@');
        foreach (var candidate in GetAllEntries())
        {
            // Layer 4: Prefix/suffix detection (check broader range since lengths can differ more)
            if (StringDistance.IsPrefixSuffixMatchCore(lowerName, candidate.NormalizedName))
            {
                results.Add(new TyposquatResult
                {
                    PackageName = packageName,
                    SimilarTo = candidate.Name,
                    Method = TyposquatDetectionMethod.PrefixSuffix,
                    RiskLevel = TyposquatRiskLevel.Low,
                    Confidence = 50,
                    Detail = "prefix/suffix of popular package",
                    Ecosystem = ecosystem
                });
            }

            // Layer 5: Scope confusion (npm only)
            if (checkScopeConfusion && StringDistance.IsScopeConfusion(packageName, candidate.Name))
            {
                results.Add(new TyposquatResult
                {
                    PackageName = packageName,
                    SimilarTo = candidate.Name,
                    Method = TyposquatDetectionMethod.ScopeConfusion,
                    RiskLevel = TyposquatRiskLevel.High,
                    Confidence = 90,
                    Detail = "scope confusion with popular scoped package",
                    Ecosystem = ecosystem
                });
            }
        }

        // Deduplicate: keep highest confidence per popular package
        var deduped = new Dictionary<string, TyposquatResult>(StringComparer.OrdinalIgnoreCase);
        foreach (var r in results)
        {
            if (!deduped.TryGetValue(r.SimilarTo, out var existing) || r.Confidence > existing.Confidence)
                deduped[r.SimilarTo] = r;
        }
        var final = deduped.Values.ToList();
        final.Sort((a, b) => b.Confidence.CompareTo(a.Confidence));
        return final;
    }

    /// <summary>
    /// Check multiple dependencies at once.
    /// </summary>
    public List<TyposquatResult> CheckAll(
        IEnumerable<string> packageNames,
        PackageEcosystem ecosystem = PackageEcosystem.NuGet)
    {
        return packageNames
            .SelectMany(name => Check(name, ecosystem))
            .OrderByDescending(r => r.Confidence)
            .ToList();
    }

    private IEnumerable<PopularPackageEntry> GetAllEntries()
    {
        return _index.AllEntries;
    }

    private static string DetectHomoglyphDetail(string lowerCandidate, string lowerPopular)
    {

        // Check each known homoglyph pair
        if (lowerCandidate.Contains('0') && lowerPopular.Contains('o'))
            return "homoglyph: 0\u2192o";
        if (lowerCandidate.Contains('1') && (lowerPopular.Contains('l') || lowerPopular.Contains('i')))
            return "homoglyph: 1\u2192l/i";
        if (lowerCandidate.Contains('5') && lowerPopular.Contains('s'))
            return "homoglyph: 5\u2192s";
        if (lowerCandidate.Contains("rn") && lowerPopular.Contains('m'))
            return "homoglyph: rn\u2192m";
        if (lowerCandidate.Contains("vv") && lowerPopular.Contains('w'))
            return "homoglyph: vv\u2192w";

        return "homoglyph substitution";
    }
}
