namespace DepSafe.Compliance;

/// <summary>
/// A single license policy violation for a package.
/// </summary>
public sealed class LicensePolicyViolation
{
    public required string PackageId { get; init; }
    public required string License { get; init; }
    public required string Reason { get; init; }
}
