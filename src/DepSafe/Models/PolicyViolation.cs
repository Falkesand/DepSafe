namespace DepSafe.Models;

public sealed record PolicyViolation(
    string Rule,
    string Message,
    string? CraArticle,
    string? Remediation,
    string? Justification,
    PolicySeverity Severity);
