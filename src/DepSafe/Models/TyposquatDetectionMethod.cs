namespace DepSafe.Models;

/// <summary>
/// Detection method that identified the typosquatting candidate.
/// </summary>
public enum TyposquatDetectionMethod
{
    EditDistance,
    Homoglyph,
    SeparatorSwap,
    PrefixSuffix,
    ScopeConfusion
}
