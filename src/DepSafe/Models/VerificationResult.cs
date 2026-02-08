namespace DepSafe.Models;

/// <summary>
/// Result of verifying a Sigil .sig.json signature envelope against its artifact.
/// </summary>
public sealed class VerificationResult
{
    /// <summary>Whether the signature is cryptographically valid.</summary>
    public required bool IsValid { get; init; }

    /// <summary>The parsed envelope that was verified.</summary>
    public SignatureEnvelope? Envelope { get; init; }

    /// <summary>Signing algorithm used (e.g., Ed25519, RSA-PSS).</summary>
    public string? Algorithm { get; init; }

    /// <summary>Key fingerprint of the signing key.</summary>
    public string? Fingerprint { get; init; }

    /// <summary>When the artifact was signed.</summary>
    public DateTime? SignedAt { get; init; }

    /// <summary>Error message if verification failed.</summary>
    public string? Error { get; init; }
}
