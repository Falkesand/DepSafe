namespace DepSafe.Compliance;

/// <summary>
/// Categorized license information.
/// </summary>
public sealed class LicenseInfo
{
    public required string Identifier { get; init; }
    public required string Name { get; init; }
    public required LicenseCategory Category { get; init; }
    public required bool RequiresAttribution { get; init; }
    public required bool RequiresSourceDisclosure { get; init; }
    public required bool AllowsCommercialUse { get; init; }
    public string? SpdxId { get; init; }
}
