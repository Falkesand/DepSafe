namespace DepSafe.Models;

/// <summary>
/// Type of project detected.
/// </summary>
public enum ProjectType
{
    /// <summary>.NET project (csproj, fsproj, vbproj, sln)</summary>
    DotNet,
    /// <summary>Node.js/npm project (package.json)</summary>
    Npm,
    /// <summary>Mixed project containing both .NET and npm</summary>
    Mixed
}
