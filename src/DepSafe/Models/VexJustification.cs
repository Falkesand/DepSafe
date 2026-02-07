namespace DepSafe.Models;

/// <summary>
/// VEX justification values per the OpenVEX specification.
/// </summary>
public static class VexJustification
{
    public const string ComponentNotPresent = "component_not_present";
    public const string VulnerableCodeNotPresent = "vulnerable_code_not_present";
    public const string VulnerableCodeNotInExecutePath = "vulnerable_code_not_in_execute_path";
    public const string VulnerableCodeCannotBeControlledByAdversary = "vulnerable_code_cannot_be_controlled_by_adversary";
    public const string InlineMitigationsAlreadyExist = "inline_mitigations_already_exist";
}
