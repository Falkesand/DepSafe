namespace NuGetHealthAnalyzer.Compliance;

/// <summary>
/// License compatibility checking for dependency analysis.
/// Identifies potential license conflicts in the dependency tree.
/// </summary>
public static class LicenseCompatibility
{
    /// <summary>
    /// License categories based on restrictions and copyleft requirements.
    /// </summary>
    public enum LicenseCategory
    {
        /// <summary>Very permissive, no copyleft (MIT, BSD, Apache, ISC, Unlicense)</summary>
        Permissive,
        /// <summary>Weak copyleft, allows linking (LGPL, MPL, EPL)</summary>
        WeakCopyleft,
        /// <summary>Strong copyleft, requires source disclosure (GPL, AGPL)</summary>
        StrongCopyleft,
        /// <summary>Proprietary or commercial license</summary>
        Proprietary,
        /// <summary>Public domain or equivalent (CC0, WTFPL)</summary>
        PublicDomain,
        /// <summary>Unknown or unrecognized license</summary>
        Unknown
    }

    /// <summary>
    /// Categorized license information.
    /// </summary>
    public sealed class LicenseInfo
    {
        public required string Identifier { get; init; }
        public required string Name { get; init; }
        public required LicenseCategory Category { get; init; }
        public required bool RequiresAttribution { get; init; }
        public required bool RequiresSourceDisclosure { get; init; }
        public required bool AllowsCommercialUse { get; init; }
        public string? SpdxId { get; init; }
    }

    /// <summary>
    /// Result of a license compatibility check.
    /// </summary>
    public sealed class CompatibilityResult
    {
        public required bool IsCompatible { get; init; }
        public required string Severity { get; init; } // "Error", "Warning", "Info"
        public required string Message { get; init; }
        public string? Recommendation { get; init; }
    }

    private static readonly Dictionary<string, LicenseInfo> KnownLicenses = new(StringComparer.OrdinalIgnoreCase)
    {
        // Permissive licenses
        ["MIT"] = new LicenseInfo { Identifier = "MIT", Name = "MIT License", Category = LicenseCategory.Permissive, RequiresAttribution = true, RequiresSourceDisclosure = false, AllowsCommercialUse = true, SpdxId = "MIT" },
        ["Apache-2.0"] = new LicenseInfo { Identifier = "Apache-2.0", Name = "Apache License 2.0", Category = LicenseCategory.Permissive, RequiresAttribution = true, RequiresSourceDisclosure = false, AllowsCommercialUse = true, SpdxId = "Apache-2.0" },
        ["BSD-2-Clause"] = new LicenseInfo { Identifier = "BSD-2-Clause", Name = "BSD 2-Clause License", Category = LicenseCategory.Permissive, RequiresAttribution = true, RequiresSourceDisclosure = false, AllowsCommercialUse = true, SpdxId = "BSD-2-Clause" },
        ["BSD-3-Clause"] = new LicenseInfo { Identifier = "BSD-3-Clause", Name = "BSD 3-Clause License", Category = LicenseCategory.Permissive, RequiresAttribution = true, RequiresSourceDisclosure = false, AllowsCommercialUse = true, SpdxId = "BSD-3-Clause" },
        ["ISC"] = new LicenseInfo { Identifier = "ISC", Name = "ISC License", Category = LicenseCategory.Permissive, RequiresAttribution = true, RequiresSourceDisclosure = false, AllowsCommercialUse = true, SpdxId = "ISC" },
        ["Unlicense"] = new LicenseInfo { Identifier = "Unlicense", Name = "The Unlicense", Category = LicenseCategory.PublicDomain, RequiresAttribution = false, RequiresSourceDisclosure = false, AllowsCommercialUse = true, SpdxId = "Unlicense" },
        ["MS-PL"] = new LicenseInfo { Identifier = "MS-PL", Name = "Microsoft Public License", Category = LicenseCategory.Permissive, RequiresAttribution = true, RequiresSourceDisclosure = false, AllowsCommercialUse = true, SpdxId = "MS-PL" },
        ["Zlib"] = new LicenseInfo { Identifier = "Zlib", Name = "zlib License", Category = LicenseCategory.Permissive, RequiresAttribution = false, RequiresSourceDisclosure = false, AllowsCommercialUse = true, SpdxId = "Zlib" },

        // Public domain
        ["CC0-1.0"] = new LicenseInfo { Identifier = "CC0-1.0", Name = "CC0 1.0 Universal", Category = LicenseCategory.PublicDomain, RequiresAttribution = false, RequiresSourceDisclosure = false, AllowsCommercialUse = true, SpdxId = "CC0-1.0" },
        ["WTFPL"] = new LicenseInfo { Identifier = "WTFPL", Name = "Do What The F*ck You Want To Public License", Category = LicenseCategory.PublicDomain, RequiresAttribution = false, RequiresSourceDisclosure = false, AllowsCommercialUse = true, SpdxId = "WTFPL" },

        // Weak copyleft
        ["LGPL-2.1"] = new LicenseInfo { Identifier = "LGPL-2.1", Name = "GNU Lesser GPL v2.1", Category = LicenseCategory.WeakCopyleft, RequiresAttribution = true, RequiresSourceDisclosure = true, AllowsCommercialUse = true, SpdxId = "LGPL-2.1-only" },
        ["LGPL-3.0"] = new LicenseInfo { Identifier = "LGPL-3.0", Name = "GNU Lesser GPL v3.0", Category = LicenseCategory.WeakCopyleft, RequiresAttribution = true, RequiresSourceDisclosure = true, AllowsCommercialUse = true, SpdxId = "LGPL-3.0-only" },
        ["MPL-2.0"] = new LicenseInfo { Identifier = "MPL-2.0", Name = "Mozilla Public License 2.0", Category = LicenseCategory.WeakCopyleft, RequiresAttribution = true, RequiresSourceDisclosure = true, AllowsCommercialUse = true, SpdxId = "MPL-2.0" },
        ["EPL-1.0"] = new LicenseInfo { Identifier = "EPL-1.0", Name = "Eclipse Public License 1.0", Category = LicenseCategory.WeakCopyleft, RequiresAttribution = true, RequiresSourceDisclosure = true, AllowsCommercialUse = true, SpdxId = "EPL-1.0" },
        ["EPL-2.0"] = new LicenseInfo { Identifier = "EPL-2.0", Name = "Eclipse Public License 2.0", Category = LicenseCategory.WeakCopyleft, RequiresAttribution = true, RequiresSourceDisclosure = true, AllowsCommercialUse = true, SpdxId = "EPL-2.0" },
        ["MS-RL"] = new LicenseInfo { Identifier = "MS-RL", Name = "Microsoft Reciprocal License", Category = LicenseCategory.WeakCopyleft, RequiresAttribution = true, RequiresSourceDisclosure = true, AllowsCommercialUse = true, SpdxId = "MS-RL" },

        // Strong copyleft
        ["GPL-2.0"] = new LicenseInfo { Identifier = "GPL-2.0", Name = "GNU GPL v2.0", Category = LicenseCategory.StrongCopyleft, RequiresAttribution = true, RequiresSourceDisclosure = true, AllowsCommercialUse = true, SpdxId = "GPL-2.0-only" },
        ["GPL-3.0"] = new LicenseInfo { Identifier = "GPL-3.0", Name = "GNU GPL v3.0", Category = LicenseCategory.StrongCopyleft, RequiresAttribution = true, RequiresSourceDisclosure = true, AllowsCommercialUse = true, SpdxId = "GPL-3.0-only" },
        ["AGPL-3.0"] = new LicenseInfo { Identifier = "AGPL-3.0", Name = "GNU Affero GPL v3.0", Category = LicenseCategory.StrongCopyleft, RequiresAttribution = true, RequiresSourceDisclosure = true, AllowsCommercialUse = true, SpdxId = "AGPL-3.0-only" },
    };

    // Aliases for common license variations
    private static readonly Dictionary<string, string> LicenseAliases = new(StringComparer.OrdinalIgnoreCase)
    {
        ["MIT License"] = "MIT",
        ["The MIT License"] = "MIT",
        ["Apache 2.0"] = "Apache-2.0",
        ["Apache License, Version 2.0"] = "Apache-2.0",
        ["Apache License Version 2.0"] = "Apache-2.0",
        ["BSD"] = "BSD-3-Clause",
        ["BSD License"] = "BSD-3-Clause",
        ["BSD-2"] = "BSD-2-Clause",
        ["BSD-3"] = "BSD-3-Clause",
        ["GPL"] = "GPL-3.0",
        ["GPLv2"] = "GPL-2.0",
        ["GPLv3"] = "GPL-3.0",
        ["LGPL"] = "LGPL-3.0",
        ["LGPLv2"] = "LGPL-2.1",
        ["LGPLv3"] = "LGPL-3.0",
        ["MPL"] = "MPL-2.0",
        ["EPL"] = "EPL-2.0",
        ["MS-PL License"] = "MS-PL",
        ["Microsoft Public License (Ms-PL)"] = "MS-PL",
    };

    /// <summary>
    /// Get license information by identifier or name.
    /// </summary>
    public static LicenseInfo? GetLicenseInfo(string? licenseText)
    {
        if (string.IsNullOrWhiteSpace(licenseText))
            return null;

        // Try direct lookup
        if (KnownLicenses.TryGetValue(licenseText, out var info))
            return info;

        // Try alias lookup
        if (LicenseAliases.TryGetValue(licenseText, out var normalized) &&
            KnownLicenses.TryGetValue(normalized, out info))
            return info;

        // Try partial matching for common patterns
        var lower = licenseText.ToLowerInvariant();

        if (lower.Contains("mit"))
            return KnownLicenses["MIT"];
        if (lower.Contains("apache") && (lower.Contains("2") || lower.Contains("2.0")))
            return KnownLicenses["Apache-2.0"];
        if (lower.Contains("bsd") && lower.Contains("2"))
            return KnownLicenses["BSD-2-Clause"];
        if (lower.Contains("bsd") && lower.Contains("3"))
            return KnownLicenses["BSD-3-Clause"];
        if (lower.Contains("bsd"))
            return KnownLicenses["BSD-3-Clause"];
        if (lower.Contains("gpl") && lower.Contains("lesser"))
            return KnownLicenses["LGPL-3.0"];
        if (lower.Contains("lgpl"))
            return KnownLicenses["LGPL-3.0"];
        if (lower.Contains("agpl"))
            return KnownLicenses["AGPL-3.0"];
        if (lower.Contains("gpl") && lower.Contains("3"))
            return KnownLicenses["GPL-3.0"];
        if (lower.Contains("gpl") && lower.Contains("2"))
            return KnownLicenses["GPL-2.0"];
        if (lower.Contains("gpl"))
            return KnownLicenses["GPL-3.0"];
        if (lower.Contains("mpl") || lower.Contains("mozilla"))
            return KnownLicenses["MPL-2.0"];
        if (lower.Contains("ms-pl") || lower.Contains("microsoft public"))
            return KnownLicenses["MS-PL"];
        if (lower.Contains("unlicense"))
            return KnownLicenses["Unlicense"];
        if (lower.Contains("cc0") || lower.Contains("public domain"))
            return KnownLicenses["CC0-1.0"];

        return null;
    }

    /// <summary>
    /// Check compatibility between a project license and a dependency license.
    /// </summary>
    public static CompatibilityResult CheckCompatibility(string? projectLicense, string? dependencyLicense, string packageName)
    {
        var projectInfo = GetLicenseInfo(projectLicense);
        var depInfo = GetLicenseInfo(dependencyLicense);

        // Unknown dependency license
        if (depInfo == null)
        {
            return new CompatibilityResult
            {
                IsCompatible = true, // Assume compatible but warn
                Severity = "Warning",
                Message = $"{packageName}: Unknown license '{dependencyLicense ?? "not specified"}'",
                Recommendation = "Review the package license manually before commercial use"
            };
        }

        // Strong copyleft in dependency
        if (depInfo.Category == LicenseCategory.StrongCopyleft)
        {
            if (projectInfo?.Category == LicenseCategory.StrongCopyleft)
            {
                // GPL project can use GPL dependencies
                return new CompatibilityResult
                {
                    IsCompatible = true,
                    Severity = "Info",
                    Message = $"{packageName}: {depInfo.Name} (compatible with project license)"
                };
            }

            return new CompatibilityResult
            {
                IsCompatible = false,
                Severity = "Error",
                Message = $"{packageName}: {depInfo.Name} requires your project to be open source under a compatible copyleft license",
                Recommendation = "Either relicense your project under GPL, find an alternative package, or obtain a commercial license if available"
            };
        }

        // AGPL special case - even stricter
        if (depInfo.Identifier.StartsWith("AGPL"))
        {
            return new CompatibilityResult
            {
                IsCompatible = false,
                Severity = "Error",
                Message = $"{packageName}: AGPL requires source disclosure even for network services",
                Recommendation = "AGPL is very restrictive. Find an alternative or ensure full compliance"
            };
        }

        // Weak copyleft
        if (depInfo.Category == LicenseCategory.WeakCopyleft)
        {
            return new CompatibilityResult
            {
                IsCompatible = true,
                Severity = "Warning",
                Message = $"{packageName}: {depInfo.Name} (weak copyleft - modifications must be shared)",
                Recommendation = "Modifications to this package must be released under the same license"
            };
        }

        // Permissive or public domain - generally compatible
        return new CompatibilityResult
        {
            IsCompatible = true,
            Severity = "Info",
            Message = $"{packageName}: {depInfo.Name}",
            Recommendation = depInfo.RequiresAttribution ? "Attribution required in documentation/notices" : null
        };
    }

    /// <summary>
    /// Analyze all dependencies for license compatibility.
    /// </summary>
    public static LicenseReport AnalyzeLicenses(IEnumerable<(string PackageId, string? License)> packages, string? projectLicense = "MIT")
    {
        var results = new List<CompatibilityResult>();
        var licenseDistribution = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        var categoryDistribution = new Dictionary<LicenseCategory, int>();
        var unknownLicenses = new List<string>();

        foreach (var (packageId, license) in packages)
        {
            var result = CheckCompatibility(projectLicense, license, packageId);
            results.Add(result);

            var info = GetLicenseInfo(license);
            if (info != null)
            {
                var key = info.Identifier;
                licenseDistribution[key] = licenseDistribution.GetValueOrDefault(key) + 1;
                categoryDistribution[info.Category] = categoryDistribution.GetValueOrDefault(info.Category) + 1;
            }
            else
            {
                unknownLicenses.Add($"{packageId}: {license ?? "not specified"}");
                categoryDistribution[LicenseCategory.Unknown] = categoryDistribution.GetValueOrDefault(LicenseCategory.Unknown) + 1;
            }
        }

        var hasErrors = results.Any(r => r.Severity == "Error");
        var hasWarnings = results.Any(r => r.Severity == "Warning");

        return new LicenseReport
        {
            ProjectLicense = projectLicense,
            TotalPackages = results.Count,
            CompatibilityResults = results,
            LicenseDistribution = licenseDistribution,
            CategoryDistribution = categoryDistribution,
            UnknownLicenses = unknownLicenses,
            OverallStatus = hasErrors ? "Incompatible" : hasWarnings ? "Review Required" : "Compatible",
            ErrorCount = results.Count(r => r.Severity == "Error"),
            WarningCount = results.Count(r => r.Severity == "Warning")
        };
    }
}

/// <summary>
/// Complete license analysis report.
/// </summary>
public sealed class LicenseReport
{
    public string? ProjectLicense { get; init; }
    public int TotalPackages { get; init; }
    public required List<LicenseCompatibility.CompatibilityResult> CompatibilityResults { get; init; }
    public required Dictionary<string, int> LicenseDistribution { get; init; }
    public required Dictionary<LicenseCompatibility.LicenseCategory, int> CategoryDistribution { get; init; }
    public required List<string> UnknownLicenses { get; init; }
    public required string OverallStatus { get; init; }
    public int ErrorCount { get; init; }
    public int WarningCount { get; init; }
}
