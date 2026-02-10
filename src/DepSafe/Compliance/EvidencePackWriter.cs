using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace DepSafe.Compliance;

/// <summary>
/// Writes a CRA evidence pack: a timestamped directory containing all compliance
/// artifacts with SHA-256 integrity checksums in a manifest.json.
/// </summary>
public static class EvidencePackWriter
{
    public static async Task<(string OutputDir, EvidencePackManifest Manifest)> WriteAsync(
        string projectPath,
        string projectName,
        string baseOutputDir,
        string reportHtml,
        string reportJson,
        string? sbomJson = null,
        string? vexJson = null,
        string? licenseAttribution = null,
        CancellationToken ct = default)
    {
        var now = DateTime.UtcNow;
        var timestamp = now.ToString("yyyyMMdd-HHmmss");
        var safeName = SanitizeDirectoryName(projectName);
        var outputDir = Path.Combine(baseOutputDir, $"{safeName}-evidence-{timestamp}");

        Directory.CreateDirectory(outputDir);

        var artifacts = new List<EvidenceArtifact>(5);

        artifacts.Add(await WriteArtifactAsync(
            outputDir, "cra-report.html", "cra-report-html", reportHtml, ct).ConfigureAwait(false));

        artifacts.Add(await WriteArtifactAsync(
            outputDir, "cra-report.json", "cra-report-json", reportJson, ct).ConfigureAwait(false));

        if (sbomJson is not null)
        {
            artifacts.Add(await WriteArtifactAsync(
                outputDir, "sbom.spdx.json", "sbom-spdx", sbomJson, ct).ConfigureAwait(false));
        }

        if (vexJson is not null)
        {
            artifacts.Add(await WriteArtifactAsync(
                outputDir, "vex.json", "vex", vexJson, ct).ConfigureAwait(false));
        }

        if (licenseAttribution is not null)
        {
            artifacts.Add(await WriteArtifactAsync(
                outputDir, "license-attribution.txt", "license-attribution", licenseAttribution, ct).ConfigureAwait(false));
        }

        var asmVersion = Assembly.GetExecutingAssembly().GetName().Version;
        var toolVersion = asmVersion is not null
            ? $"{asmVersion.Major}.{asmVersion.Minor}.{asmVersion.Build}"
            : "1.0.0";

        var manifest = new EvidencePackManifest
        {
            GeneratedAt = now,
            ToolVersion = toolVersion,
            ProjectPath = projectPath,
            Artifacts = artifacts,
            Signed = false,
        };

        var manifestJson = JsonSerializer.Serialize(manifest, JsonDefaults.Indented);
        await File.WriteAllTextAsync(
            Path.Combine(outputDir, "manifest.json"), manifestJson, Encoding.UTF8, ct).ConfigureAwait(false);

        return (outputDir, manifest);
    }

    private static async Task<EvidenceArtifact> WriteArtifactAsync(
        string outputDir, string fileName, string type, string content, CancellationToken ct)
    {
        var filePath = Path.Combine(outputDir, fileName);
        var bytes = Encoding.UTF8.GetBytes(content);

        await File.WriteAllBytesAsync(filePath, bytes, ct).ConfigureAwait(false);

        var hash = Convert.ToHexStringLower(SHA256.HashData(bytes));

        return new EvidenceArtifact
        {
            Type = type,
            File = fileName,
            Sha256 = hash,
        };
    }

    internal static string SanitizeDirectoryName(string name)
    {
        if (string.IsNullOrWhiteSpace(name))
            return "project";

        var invalidChars = Path.GetInvalidFileNameChars();
        var sb = new StringBuilder(name.Length);
        foreach (var c in name)
        {
            if (c == '.')
            {
                // Strip dots to prevent traversal sequences like ".."
                continue;
            }
            sb.Append(Array.IndexOf(invalidChars, c) >= 0 ? '_' : c);
        }

        var result = sb.ToString().Trim();
        return string.IsNullOrWhiteSpace(result) ? "project" : result;
    }
}
