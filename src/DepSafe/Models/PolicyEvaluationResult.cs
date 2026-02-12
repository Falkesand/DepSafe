namespace DepSafe.Models;

public sealed record PolicyEvaluationResult(
    List<PolicyViolation> Violations,
    int ExitCode);
