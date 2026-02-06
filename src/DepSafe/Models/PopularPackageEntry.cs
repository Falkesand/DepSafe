namespace DepSafe.Models;

/// <summary>
/// Entry representing a popular/well-known package for typosquatting comparison.
/// </summary>
public sealed class PopularPackageEntry
{
    /// <summary>Package name (case-preserved).</summary>
    public required string Name { get; init; }

    /// <summary>Pre-normalized (lowercased) name for comparison without per-call allocations.</summary>
    public string NormalizedName { get; init; } = "";

    /// <summary>Weekly/monthly download count (approximate).</summary>
    public long Downloads { get; init; }

    /// <summary>Package ecosystem.</summary>
    public PackageEcosystem Ecosystem { get; init; }
}
