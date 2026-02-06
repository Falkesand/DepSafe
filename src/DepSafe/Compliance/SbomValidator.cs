using DepSafe.Models;

namespace DepSafe.Compliance;

/// <summary>
/// Validates SBOM completeness per BSI TR-03183-2 requirements.
/// Required fields: Creator, Timestamp, Name, Version, Supplier, License, Checksum, PURL.
/// </summary>
public static class SbomValidator
{
    /// <summary>
    /// Validate an SBOM document against BSI TR-03183-2 field requirements.
    /// </summary>
    public static SbomValidationResult Validate(SbomDocument sbom)
    {
        var hasTimestamp = !string.IsNullOrEmpty(sbom.CreationInfo.Created);
        var hasCreator = sbom.CreationInfo.Creators.Count > 0 &&
                         sbom.CreationInfo.Creators.Any(c => !string.IsNullOrWhiteSpace(c));

        int withSupplier = 0, withLicense = 0, withPurl = 0, withChecksum = 0;
        var missingSupplier = new List<string>();
        var missingLicense = new List<string>();
        var missingPurl = new List<string>();
        var missingChecksum = new List<string>();

        foreach (var pkg in sbom.Packages)
        {
            var name = $"{pkg.Name}@{pkg.VersionInfo}";

            if (!string.IsNullOrEmpty(pkg.Supplier) && pkg.Supplier != "NOASSERTION")
                withSupplier++;
            else
                missingSupplier.Add(name);

            if (!string.IsNullOrEmpty(pkg.LicenseConcluded) && pkg.LicenseConcluded != "NOASSERTION")
                withLicense++;
            else
                missingLicense.Add(name);

            if (pkg.ExternalRefs?.Any(r =>
                    r.ReferenceType == "purl" ||
                    r.ReferenceLocator.StartsWith("pkg:", StringComparison.OrdinalIgnoreCase)) == true)
                withPurl++;
            else
                missingPurl.Add(name);

            if (pkg.Checksums?.Count > 0)
                withChecksum++;
            else
                missingChecksum.Add(name);
        }

        return new SbomValidationResult
        {
            TotalPackages = sbom.Packages.Count,
            WithSupplier = withSupplier,
            WithLicense = withLicense,
            WithPurl = withPurl,
            WithChecksum = withChecksum,
            HasTimestamp = hasTimestamp,
            HasCreator = hasCreator,
            MissingSupplier = missingSupplier,
            MissingLicense = missingLicense,
            MissingPurl = missingPurl,
            MissingChecksum = missingChecksum
        };
    }
}
