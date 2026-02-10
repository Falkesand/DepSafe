using DepSafe.Models;

namespace DepSafe.Compliance;

/// <summary>
/// Evaluates packages against license allowlist/blocklist policy from CraConfig.
/// </summary>
public static class LicensePolicyEvaluator
{
    private static readonly string[] s_orSeparators = [" OR ", " or ", " Or "];

    /// <summary>
    /// Evaluate license policy for all packages.
    /// AllowedLicenses takes precedence when both allowed and blocked lists are configured.
    /// </summary>
    public static LicensePolicyResult Evaluate(IReadOnlyList<PackageHealth> packages, CraConfig config)
    {
        var violations = new List<LicensePolicyViolation>();

        bool hasAllowedList = config.AllowedLicenses.Count > 0;
        bool hasBlockedList = config.BlockedLicenses.Count > 0;

        if (!hasAllowedList && !hasBlockedList)
            return new LicensePolicyResult();

        // Build case-insensitive sets for fast lookup
        var allowedSet = hasAllowedList
            ? new HashSet<string>(config.AllowedLicenses, StringComparer.OrdinalIgnoreCase)
            : null;
        var blockedSet = hasBlockedList
            ? new HashSet<string>(config.BlockedLicenses, StringComparer.OrdinalIgnoreCase)
            : null;

        foreach (var pkg in packages)
        {
            // When AllowedLicenses is set, it takes precedence (blocklist is ignored)
            if (allowedSet is not null)
            {
                if (!IsLicenseAllowed(pkg.License, allowedSet))
                {
                    violations.Add(new LicensePolicyViolation
                    {
                        PackageId = pkg.PackageId,
                        License = pkg.License ?? "unknown",
                        Reason = pkg.License is null
                            ? "License is unknown \u2014 not in allowed list"
                            : $"License '{pkg.License}' is not in allowed list",
                    });
                }
            }
            else if (blockedSet is not null)
            {
                if (IsLicenseBlocked(pkg.License, blockedSet))
                {
                    violations.Add(new LicensePolicyViolation
                    {
                        PackageId = pkg.PackageId,
                        License = pkg.License ?? "unknown",
                        Reason = $"License '{pkg.License}' is blocked by policy",
                    });
                }
            }
        }

        return new LicensePolicyResult { Violations = violations };
    }

    /// <summary>
    /// Check if a license is in the allowed set. For SPDX OR expressions,
    /// the package passes if any constituent license is allowed.
    /// </summary>
    private static bool IsLicenseAllowed(string? license, HashSet<string> allowedSet)
    {
        if (string.IsNullOrWhiteSpace(license))
            return false;

        // Try direct match first (case-insensitive via set)
        var normalized = NormalizeLicense(license);
        if (normalized is not null && allowedSet.Contains(normalized))
            return true;

        // Try raw license text
        if (allowedSet.Contains(license))
            return true;

        // Handle SPDX OR expressions: pass if ANY constituent is allowed
        var constituents = ParseOrConstituents(license);
        if (constituents is not null)
        {
            foreach (var constituent in constituents)
            {
                var normalizedConstituent = NormalizeLicense(constituent);
                if (normalizedConstituent is not null && allowedSet.Contains(normalizedConstituent))
                    return true;
                if (allowedSet.Contains(constituent))
                    return true;
            }
        }

        return false;
    }

    /// <summary>
    /// Check if a license is in the blocked set.
    /// For SPDX OR expressions, the package is NOT blocked as long as the composite
    /// license (or its normalized form) is not in the blocked set, because OR expressions
    /// allow the licensee to choose any constituent.
    /// </summary>
    private static bool IsLicenseBlocked(string? license, HashSet<string> blockedSet)
    {
        if (string.IsNullOrWhiteSpace(license))
            return false;

        var normalized = NormalizeLicense(license);
        if (normalized is not null && blockedSet.Contains(normalized))
            return true;

        if (blockedSet.Contains(license))
            return true;

        return false;
    }

    /// <summary>
    /// Normalize a license string to its SPDX identifier using LicenseCompatibility.
    /// </summary>
    private static string? NormalizeLicense(string? license)
    {
        if (string.IsNullOrWhiteSpace(license))
            return null;

        var info = LicenseCompatibility.GetLicenseInfo(license);
        return info?.Identifier ?? license;
    }

    /// <summary>
    /// Parse SPDX OR expression constituents. Returns null if not an OR expression.
    /// Handles case-insensitive OR separators.
    /// </summary>
    private static string[]? ParseOrConstituents(string license)
    {
        var text = license.Trim();
        if (text.StartsWith('(') && text.EndsWith(')'))
            text = text[1..^1].Trim();

        if (!text.Contains(" OR ", StringComparison.OrdinalIgnoreCase))
            return null;

        return text.Split(s_orSeparators, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
    }
}
