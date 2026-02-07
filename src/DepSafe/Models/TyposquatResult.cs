namespace DepSafe.Models;

/// <summary>
/// Result of a typosquatting check for a single dependency.
/// </summary>
public sealed class TyposquatResult
{
    /// <summary>The dependency package name being checked.</summary>
    public required string PackageName { get; init; }

    /// <summary>The popular package name it resembles.</summary>
    public required string SimilarTo { get; init; }

    /// <summary>Detection method that triggered the match.</summary>
    public required TyposquatDetectionMethod Method { get; init; }

    /// <summary>Risk level based on detection confidence.</summary>
    public required TyposquatRiskLevel RiskLevel { get; init; }

    /// <summary>Confidence percentage (0-100).</summary>
    public required int Confidence { get; init; }

    /// <summary>Human-readable detail about the match.</summary>
    public required string Detail { get; init; }

    /// <summary>Package ecosystem (NuGet or npm).</summary>
    public PackageEcosystem Ecosystem { get; init; } = PackageEcosystem.NuGet;
}
