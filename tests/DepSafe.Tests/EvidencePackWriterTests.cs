using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using DepSafe.Compliance;

namespace DepSafe.Tests;

public class EvidencePackWriterTests
{
    [Fact]
    public void ComputeSha256_KnownInput_ReturnsCorrectHash()
    {
        // SHA-256 of "hello" is well-known
        var bytes = Encoding.UTF8.GetBytes("hello");
        var expected = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";

        var hash = SHA256.HashData(bytes);
        var hex = Convert.ToHexStringLower(hash);

        Assert.Equal(expected, hex);
    }

    [Fact]
    public void CreateManifest_SerializesToValidJson()
    {
        var manifest = new EvidencePackManifest
        {
            GeneratedAt = new DateTime(2024, 6, 15, 10, 30, 0, DateTimeKind.Utc),
            ToolVersion = "1.6.0",
            ProjectPath = "/test/project",
            Artifacts =
            [
                new EvidenceArtifact { Type = "cra-report", File = "report.html", Sha256 = "abc123" },
                new EvidenceArtifact { Type = "sbom", File = "sbom.json", Sha256 = "def456" },
            ],
            Signed = false,
        };

        var json = JsonSerializer.Serialize(manifest, new JsonSerializerOptions { WriteIndented = true, PropertyNamingPolicy = JsonNamingPolicy.CamelCase });

        Assert.Contains("\"toolVersion\"", json);
        Assert.Contains("\"1.6.0\"", json);
        Assert.Contains("\"cra-report\"", json);
        Assert.Contains("\"sbom\"", json);
        Assert.Equal(2, manifest.Artifacts.Count);
    }

    [Fact]
    public void EvidenceArtifact_AllTypes_Supported()
    {
        // Verify all expected artifact types can be constructed
        var types = new[] { "cra-report-html", "cra-report-json", "sbom-spdx", "vex", "license-attribution" };

        foreach (var type in types)
        {
            var artifact = new EvidenceArtifact
            {
                Type = type,
                File = $"test.{type}",
                Sha256 = "0000000000000000000000000000000000000000000000000000000000000000",
            };
            Assert.Equal(type, artifact.Type);
        }
    }

    [Fact]
    public async Task WriteAsync_CreatesDirectoryAndManifest()
    {
        var tempDir = Path.Combine(Path.GetTempPath(), $"evidence-test-{Guid.NewGuid():N}");
        try
        {
            var reportContent = "<html>CRA Report</html>";
            var reportJsonContent = """{"healthScore": 80}""";

            var (outputDir, manifest) = await EvidencePackWriter.WriteAsync(
                projectPath: "/test",
                projectName: "TestProject",
                baseOutputDir: tempDir,
                reportHtml: reportContent,
                reportJson: reportJsonContent);

            Assert.True(Directory.Exists(outputDir));
            Assert.True(File.Exists(Path.Combine(outputDir, "manifest.json")));
            Assert.True(manifest.Artifacts.Count >= 2); // at least HTML + JSON reports
            Assert.Equal("/test", manifest.ProjectPath);

            // Verify SHA256 of HTML report matches
            var htmlArtifact = manifest.Artifacts.First(a => a.Type == "cra-report-html");
            var fileBytes = await File.ReadAllBytesAsync(Path.Combine(outputDir, htmlArtifact.File));
            var expectedHash = Convert.ToHexStringLower(SHA256.HashData(fileBytes));
            Assert.Equal(expectedHash, htmlArtifact.Sha256);
        }
        finally
        {
            if (Directory.Exists(tempDir))
                Directory.Delete(tempDir, true);
        }
    }

    [Fact]
    public async Task WriteAsync_WithOptionalArtifacts_IncludesAll()
    {
        var tempDir = Path.Combine(Path.GetTempPath(), $"evidence-test-{Guid.NewGuid():N}");
        try
        {
            var (outputDir, manifest) = await EvidencePackWriter.WriteAsync(
                projectPath: "/test",
                projectName: "TestProject",
                baseOutputDir: tempDir,
                reportHtml: "<html>Report</html>",
                reportJson: "{}",
                sbomJson: """{"spdxVersion": "SPDX-3.0"}""",
                vexJson: """{"statements": []}""",
                licenseAttribution: "MIT License Attribution");

            Assert.Equal(5, manifest.Artifacts.Count);
            Assert.Contains(manifest.Artifacts, a => a.Type == "cra-report-html");
            Assert.Contains(manifest.Artifacts, a => a.Type == "cra-report-json");
            Assert.Contains(manifest.Artifacts, a => a.Type == "sbom-spdx");
            Assert.Contains(manifest.Artifacts, a => a.Type == "vex");
            Assert.Contains(manifest.Artifacts, a => a.Type == "license-attribution");
        }
        finally
        {
            if (Directory.Exists(tempDir))
                Directory.Delete(tempDir, true);
        }
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData(null)]
    public void SanitizeDirectoryName_EmptyOrWhitespace_ReturnsFallback(string? name)
    {
        var result = EvidencePackWriter.SanitizeDirectoryName(name ?? "");
        Assert.Equal("project", result);
    }

    [Fact]
    public void SanitizeDirectoryName_PathTraversal_Sanitized()
    {
        var result = EvidencePackWriter.SanitizeDirectoryName("../../malicious");
        Assert.DoesNotContain("..", result);
        Assert.DoesNotContain("/", result);
        Assert.DoesNotContain("\\", result);
    }

    [Fact]
    public void SanitizeDirectoryName_ValidName_Preserved()
    {
        var result = EvidencePackWriter.SanitizeDirectoryName("MyProject");
        Assert.Equal("MyProject", result);
    }

    [Fact]
    public async Task WriteAsync_EmptyProjectName_CreatesValidDirectory()
    {
        var tempDir = Path.Combine(Path.GetTempPath(), $"evidence-test-{Guid.NewGuid():N}");
        try
        {
            var (outputDir, _) = await EvidencePackWriter.WriteAsync(
                projectPath: "/test",
                projectName: "",
                baseOutputDir: tempDir,
                reportHtml: "<html></html>",
                reportJson: "{}");

            Assert.True(Directory.Exists(outputDir));
            Assert.StartsWith(tempDir, outputDir);
        }
        finally
        {
            if (Directory.Exists(tempDir))
                Directory.Delete(tempDir, true);
        }
    }
}
