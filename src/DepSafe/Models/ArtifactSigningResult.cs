namespace DepSafe.Models;

/// <summary>
/// Per-artifact signing and verification status for CRA report display.
/// </summary>
public sealed class ArtifactSigningResult
{
    /// <summary>Path to the artifact file.</summary>
    public required string ArtifactPath { get; init; }

    /// <summary>Type of artifact (e.g., "CRA Report", "SBOM", "VEX", "License Attribution").</summary>
    public required string ArtifactType { get; init; }

    /// <summary>Whether a .sig.json envelope exists for this artifact.</summary>
    public bool IsSigned { get; init; }

    /// <summary>Whether the signature was cryptographically verified.</summary>
    public bool IsVerified { get; init; }

    /// <summary>Signing algorithm (e.g., Ed25519).</summary>
    public string? Algorithm { get; init; }

    /// <summary>Key fingerprint of the signing key.</summary>
    public string? Fingerprint { get; init; }

    /// <summary>When the artifact was signed.</summary>
    public DateTime? SignedAt { get; init; }

    /// <summary>Error message if signing or verification failed.</summary>
    public string? Error { get; init; }
}
