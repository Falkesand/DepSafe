using System.Xml.Linq;
using DepSafe.Models;

namespace DepSafe.Compliance;

/// <summary>
/// Extracts project identity (name and version) from project metadata files.
/// </summary>
public static class ProjectIdentityExtractor
{
    /// <summary>
    /// Extracts project identity from a .csproj file, optionally walking up to Directory.Build.props for version.
    /// </summary>
    public static async Task<Result<ProjectIdentity>> ExtractDotNetIdentityAsync(string projectFilePath, CancellationToken ct = default)
    {
        if (!File.Exists(projectFilePath))
            return Result<ProjectIdentity>.Fail($"Project file not found: {projectFilePath}", ErrorKind.NotFound);

        XDocument doc;
        try
        {
            using var stream = File.OpenRead(projectFilePath);
            doc = await XDocument.LoadAsync(stream, LoadOptions.None, ct).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return Result<ProjectIdentity>.Fail($"Failed to parse project file: {ex.Message}", ErrorKind.ParseError);
        }

        var name = GetMsBuildProperty(doc, "PackageId")
                   ?? GetMsBuildProperty(doc, "AssemblyName")
                   ?? Path.GetFileNameWithoutExtension(projectFilePath);

        var version = GetMsBuildProperty(doc, "Version");

        if (version is null)
        {
            version = await FindVersionInDirectoryBuildPropsAsync(Path.GetDirectoryName(projectFilePath)!, ct).ConfigureAwait(false);
        }

        version ??= "0.0.0";

        return Result<ProjectIdentity>.Ok(new ProjectIdentity(name, version));
    }

    /// <summary>
    /// Extracts project identity from a parsed package.json.
    /// </summary>
    public static ProjectIdentity ExtractNpmIdentity(PackageJson packageJson, string fallbackPath)
    {
        var name = packageJson.Name ?? Path.GetFileName(fallbackPath);
        var version = packageJson.Version ?? "0.0.0";
        return new ProjectIdentity(name, version);
    }

    /// <summary>
    /// Auto-detects project type and extracts identity. Falls back to folder name + 0.0.0.
    /// </summary>
    public static async Task<ProjectIdentity> ExtractIdentityAsync(string path, CancellationToken ct = default)
    {
        var dir = File.Exists(path) ? Path.GetDirectoryName(path)! : path;

        // Try package.json first
        var packageJsonPath = Path.Combine(dir, "package.json");
        if (File.Exists(packageJsonPath))
        {
            try
            {
                var json = await File.ReadAllTextAsync(packageJsonPath, ct).ConfigureAwait(false);
                var packageJson = System.Text.Json.JsonSerializer.Deserialize<PackageJson>(json);
                if (packageJson is not null)
                    return ExtractNpmIdentity(packageJson, dir);
            }
            catch
            {
                // Fall through to .NET detection
            }
        }

        // Try .csproj files
        var csprojFiles = Directory.GetFiles(dir, "*.csproj", SearchOption.TopDirectoryOnly);
        if (csprojFiles.Length > 0)
        {
            var result = await ExtractDotNetIdentityAsync(csprojFiles[0], ct).ConfigureAwait(false);
            if (result.IsSuccess)
                return result.Value;
        }

        // Fallback
        return new ProjectIdentity(Path.GetFileName(dir), "0.0.0");
    }

    private static string? GetMsBuildProperty(XDocument doc, string propertyName)
    {
        var value = doc.Descendants(propertyName).FirstOrDefault()?.Value?.Trim();
        if (string.IsNullOrEmpty(value))
            return null;

        // Skip MSBuild variables like $(Foo)
        if (value.Contains("$("))
            return null;

        return value;
    }

    private static async Task<string?> FindVersionInDirectoryBuildPropsAsync(string startDir, CancellationToken ct)
    {
        var dir = startDir;
        while (dir is not null)
        {
            var propsPath = Path.Combine(dir, "Directory.Build.props");
            if (File.Exists(propsPath))
            {
                try
                {
                    using var stream = File.OpenRead(propsPath);
                    var doc = await XDocument.LoadAsync(stream, LoadOptions.None, ct).ConfigureAwait(false);
                    var version = GetMsBuildProperty(doc, "Version");
                    if (version is not null)
                        return version;
                }
                catch
                {
                    // Ignore parse errors, continue searching
                }
            }

            dir = Path.GetDirectoryName(dir);
        }

        return null;
    }
}
