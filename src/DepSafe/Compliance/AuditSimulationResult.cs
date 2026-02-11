namespace DepSafe.Compliance;

public sealed record AuditSimulationResult(
    List<AuditFinding> Findings,
    int CriticalCount,
    int HighCount,
    int MediumCount,
    int LowCount);
