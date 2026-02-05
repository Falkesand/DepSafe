namespace DepSafe.Models;

/// <summary>
/// Result of package provenance/signing verification per CRA Art. 13(5).
/// </summary>
public sealed class ProvenanceResult
{
    /// <summary>Package identifier.</summary>
    public required string PackageId { get; init; }

    /// <summary>Package version.</summary>
    public required string Version { get; init; }

    /// <summary>Whether the package has a repository signature.</summary>
    public bool HasRepositorySignature { get; init; }

    /// <summary>Whether the package has an author signature.</summary>
    public bool HasAuthorSignature { get; init; }

    /// <summary>Whether provenance could be verified at all.</summary>
    public bool IsVerified => HasRepositorySignature || HasAuthorSignature;

    /// <summary>Package ecosystem.</summary>
    public PackageEcosystem Ecosystem { get; init; } = PackageEcosystem.NuGet;

    /// <summary>Package content hash (e.g., SHA-512) from the registry.</summary>
    public string? ContentHash { get; init; }

    /// <summary>Hash algorithm used for ContentHash (e.g., "SHA512").</summary>
    public string? ContentHashAlgorithm { get; init; }
}
