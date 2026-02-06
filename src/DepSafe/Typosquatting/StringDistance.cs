namespace DepSafe.Typosquatting;

/// <summary>
/// String distance and normalization algorithms for typosquatting detection.
/// </summary>
public static class StringDistance
{
    /// <summary>
    /// Compute Damerau-Levenshtein distance with early exit when distance exceeds maxDistance.
    /// Handles transpositions in addition to insertions, deletions, and substitutions.
    /// </summary>
    public static int DamerauLevenshtein(ReadOnlySpan<char> source, ReadOnlySpan<char> target, int maxDistance = 2)
    {
        var sLen = source.Length;
        var tLen = target.Length;

        // Quick length check - if lengths differ by more than maxDistance, skip
        if (Math.Abs(sLen - tLen) > maxDistance)
            return maxDistance + 1;

        if (sLen == 0) return tLen;
        if (tLen == 0) return sLen;

        // Use stackalloc for small strings to avoid heap allocation
        var matrixSize = (sLen + 1) * (tLen + 1);
        Span<int> matrix = matrixSize <= 512
            ? stackalloc int[matrixSize]
            : new int[matrixSize];

        int Idx(int i, int j) => i * (tLen + 1) + j;

        for (var i = 0; i <= sLen; i++) matrix[Idx(i, 0)] = i;
        for (var j = 0; j <= tLen; j++) matrix[Idx(0, j)] = j;

        for (var i = 1; i <= sLen; i++)
        {
            var rowMin = int.MaxValue;
            for (var j = 1; j <= tLen; j++)
            {
                var cost = source[i - 1] == target[j - 1] ? 0 : 1;

                var deletion = matrix[Idx(i - 1, j)] + 1;
                var insertion = matrix[Idx(i, j - 1)] + 1;
                var substitution = matrix[Idx(i - 1, j - 1)] + cost;

                var min = Math.Min(Math.Min(deletion, insertion), substitution);

                // Transposition
                if (i > 1 && j > 1 &&
                    source[i - 1] == target[j - 2] &&
                    source[i - 2] == target[j - 1])
                {
                    min = Math.Min(min, matrix[Idx(i - 2, j - 2)] + cost);
                }

                matrix[Idx(i, j)] = min;
                rowMin = Math.Min(rowMin, min);
            }

            // Early exit: if no cell in this row is <= maxDistance, we can't do better
            if (rowMin > maxDistance)
                return maxDistance + 1;
        }

        return matrix[Idx(sLen, tLen)];
    }

    // Homoglyph mappings: visually similar character substitutions
    private static readonly (string From, string To)[] HomoglyphPairs =
    [
        ("0", "o"),
        ("1", "l"),
        ("1", "i"),
        ("5", "s"),
        ("rn", "m"),
        ("vv", "w"),
        ("cl", "d"),
        ("nn", "m"),
    ];

    /// <summary>
    /// Normalize a string by replacing homoglyphs with canonical forms.
    /// Returns the normalized lowercase string.
    /// </summary>
    public static string NormalizeHomoglyphs(string input)
    {
        var result = input.ToLowerInvariant();

        foreach (var (from, to) in HomoglyphPairs)
        {
            result = result.Replace(from, to);
        }

        return result;
    }

    /// <summary>
    /// Normalize separators (-, ., _) to a canonical form (hyphen).
    /// Returns the normalized lowercase string.
    /// </summary>
    public static string NormalizeSeparators(string input)
    {
        return input.ToLowerInvariant()
            .Replace('.', '-')
            .Replace('_', '-');
    }

    /// <summary>
    /// Check if two package names match after homoglyph normalization.
    /// </summary>
    public static bool IsHomoglyphMatch(string candidate, string popular)
    {
        var normalizedCandidate = NormalizeHomoglyphs(candidate);
        var normalizedPopular = NormalizeHomoglyphs(popular);

        return normalizedCandidate == normalizedPopular &&
               !string.Equals(candidate, popular, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Check if two package names match after separator normalization.
    /// </summary>
    public static bool IsSeparatorMatch(string candidate, string popular)
    {
        var normalizedCandidate = NormalizeSeparators(candidate);
        var normalizedPopular = NormalizeSeparators(popular);

        return normalizedCandidate == normalizedPopular &&
               !string.Equals(candidate, popular, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Check if candidate is a prefix/suffix variant of a popular package.
    /// e.g., "node-lodash" or "lodash-js" when "lodash" is the popular package.
    /// Only triggers for popular packages with names >= 4 chars.
    /// Excludes namespace children (e.g., Serilog.Enrichers.Thread is a sub-package of Serilog, not a typosquat).
    /// </summary>
    public static bool IsPrefixSuffixMatch(string candidate, string popular)
    {
        if (popular.Length < 4)
            return false;

        var lowerCandidate = candidate.ToLowerInvariant();
        var lowerPopular = popular.ToLowerInvariant();

        if (lowerCandidate == lowerPopular)
            return false;

        // Sub-package in dotted namespace convention is not typosquatting
        // e.g., Microsoft.EntityFrameworkCore.Design extends Microsoft.EntityFrameworkCore
        if (lowerCandidate.StartsWith($"{lowerPopular}."))
            return false;

        // Check common prefixes/suffixes with separators
        char[] separators = ['-', '.', '_'];

        foreach (var sep in separators)
        {
            // "node-lodash" contains "lodash" after separator
            if (lowerCandidate.Contains($"{sep}{lowerPopular}") ||
                lowerCandidate.Contains($"{lowerPopular}{sep}"))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// Check for npm scope confusion (e.g., @typos/node vs @types/node).
    /// Only applies to scoped npm packages.
    /// </summary>
    public static bool IsScopeConfusion(string candidate, string popular)
    {
        if (!candidate.StartsWith('@') || !popular.StartsWith('@'))
            return false;

        var candidateParts = ParseScope(candidate);
        var popularParts = ParseScope(popular);

        if (candidateParts is null || popularParts is null)
            return false;

        // Same package name but different (similar) scopes
        if (string.Equals(candidateParts.Value.Name, popularParts.Value.Name, StringComparison.OrdinalIgnoreCase) &&
            !string.Equals(candidateParts.Value.Scope, popularParts.Value.Scope, StringComparison.OrdinalIgnoreCase))
        {
            var scopeDistance = DamerauLevenshtein(
                candidateParts.Value.Scope.AsSpan(),
                popularParts.Value.Scope.AsSpan(),
                2);

            return scopeDistance <= 2;
        }

        return false;
    }

    private static (string Scope, string Name)? ParseScope(string packageName)
    {
        var slashIndex = packageName.IndexOf('/');
        if (slashIndex <= 1) return null;

        return (packageName[1..slashIndex], packageName[(slashIndex + 1)..]);
    }
}
