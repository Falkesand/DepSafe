namespace DepSafe.Compliance;

/// <summary>
/// Result of evaluating license policy against packages.
/// </summary>
public sealed class LicensePolicyResult
{
    public List<LicensePolicyViolation> Violations { get; init; } = [];
    public bool HasViolations => Violations.Count > 0;
}
