namespace DepSafe.Models;

/// <summary>
/// Result of SBOM completeness validation per BSI TR-03183-2.
/// </summary>
public sealed class SbomValidationResult
{
    /// <summary>Total number of packages validated.</summary>
    public required int TotalPackages { get; init; }

    /// <summary>Number of packages with a creator/supplier identified.</summary>
    public required int WithSupplier { get; init; }

    /// <summary>Number of packages with a license declared.</summary>
    public required int WithLicense { get; init; }

    /// <summary>Number of packages with a PURL (Package URL) reference.</summary>
    public required int WithPurl { get; init; }

    /// <summary>Number of packages with at least one checksum.</summary>
    public required int WithChecksum { get; init; }

    /// <summary>Whether the SBOM has a timestamp.</summary>
    public required bool HasTimestamp { get; init; }

    /// <summary>Whether the SBOM has creator information.</summary>
    public required bool HasCreator { get; init; }

    /// <summary>Package names missing supplier info.</summary>
    public List<string> MissingSupplier { get; init; } = [];

    /// <summary>Package names missing license info.</summary>
    public List<string> MissingLicense { get; init; } = [];

    /// <summary>Package names missing PURL reference.</summary>
    public List<string> MissingPurl { get; init; } = [];

    /// <summary>Package names missing checksum.</summary>
    public List<string> MissingChecksum { get; init; } = [];

    /// <summary>Overall field completeness percentage (0-100).</summary>
    public int CompletenessPercent
    {
        get
        {
            if (TotalPackages == 0) return HasTimestamp && HasCreator ? 100 : 0;

            // 6 fields: Timestamp, Creator, Supplier, License, PURL, Checksum
            // Timestamp and Creator are document-level (count as full if present)
            // Package-level fields are averaged
            var docScore = ((HasTimestamp ? 1.0 : 0) + (HasCreator ? 1.0 : 0)) / 2.0;
            var pkgScore = ((double)WithSupplier + WithLicense + WithPurl + WithChecksum) / (TotalPackages * 4.0);
            return (int)Math.Round((docScore * 0.3 + pkgScore * 0.7) * 100);
        }
    }
}
