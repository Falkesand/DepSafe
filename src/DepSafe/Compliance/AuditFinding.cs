namespace DepSafe.Compliance;

public sealed record AuditFinding(
    string ArticleReference,
    string Requirement,
    string Finding,
    AuditSeverity Severity,
    List<string> AffectedPackages);
