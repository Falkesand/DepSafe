namespace DepSafe.Commands;

public sealed record CraReportOptions(
    string? Path,
    CraOutputFormat Format,
    string? Output,
    bool SkipGitHub,
    bool Deep,
    LicenseOutputFormat? Licenses,
    SbomFormat? Sbom,
    bool CheckTyposquat,
    bool Sign,
    string? SignKey);
