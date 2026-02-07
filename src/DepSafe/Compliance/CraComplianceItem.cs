using DepSafe.Models;

namespace DepSafe.Compliance;

public sealed class CraComplianceItem
{
    public required string Requirement { get; init; }
    public required string Description { get; init; }
    public required CraComplianceStatus Status { get; init; }
    public string? Evidence { get; init; }
    public string? Recommendation { get; init; }
}
