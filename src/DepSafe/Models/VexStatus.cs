namespace DepSafe.Models;

/// <summary>
/// VEX status values per the OpenVEX specification.
/// </summary>
public static class VexStatus
{
    public const string NotAffected = "not_affected";
    public const string Affected = "affected";
    public const string Fixed = "fixed";
    public const string UnderInvestigation = "under_investigation";
}
