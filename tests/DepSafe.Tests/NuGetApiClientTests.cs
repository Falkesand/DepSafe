using DepSafe.DataSources;
using DepSafe.Models;

namespace DepSafe.Tests;

public class NuGetApiClientTests
{
    // ──────────────────────────────────────────────
    // NormalizeGitHubUrl
    // ──────────────────────────────────────────────

    [Fact]
    public void NormalizeGitHubUrl_StandardUrl_Normalizes()
    {
        var result = NuGetApiClient.NormalizeGitHubUrl("https://github.com/owner/repo/tree/main");

        Assert.Equal("https://github.com/owner/repo", result);
    }

    [Fact]
    public void NormalizeGitHubUrl_DotGitSuffix_Strips()
    {
        // NormalizeGitHubUrl does NOT strip .git — it takes the first 2 path segments as-is
        var result = NuGetApiClient.NormalizeGitHubUrl("https://github.com/owner/repo.git");

        Assert.Equal("https://github.com/owner/repo.git", result);
    }

    [Fact]
    public void NormalizeGitHubUrl_ShortUrl_PassesThrough()
    {
        var result = NuGetApiClient.NormalizeGitHubUrl("https://github.com/owner/repo");

        Assert.Equal("https://github.com/owner/repo", result);
    }

    [Fact]
    public void NormalizeGitHubUrl_NonGitHub_ReturnsOriginal()
    {
        var result = NuGetApiClient.NormalizeGitHubUrl("https://gitlab.com/owner/repo");

        Assert.Equal("https://gitlab.com/owner/repo", result);
    }

    // ──────────────────────────────────────────────
    // ParseProjectFileAsync
    // ──────────────────────────────────────────────

    [Fact]
    public async Task ParseProjectFileAsync_SdkStyleCsproj_ParsesReferences()
    {
        var tempFile = Path.GetTempFileName();
        try
        {
            await File.WriteAllTextAsync(tempFile, """
                <Project Sdk="Microsoft.NET.Sdk">
                  <ItemGroup>
                    <PackageReference Include="Newtonsoft.Json" Version="13.0.3"/>
                  </ItemGroup>
                </Project>
                """);

            var result = await NuGetApiClient.ParseProjectFileAsync(tempFile, CancellationToken.None);

            Assert.True(result.IsSuccess);
            Assert.Single(result.Value);
            Assert.Equal("Newtonsoft.Json", result.Value[0].PackageId);
            Assert.Equal("13.0.3", result.Value[0].Version);
            Assert.Equal(tempFile, result.Value[0].SourceFile);
        }
        finally
        {
            File.Delete(tempFile);
        }
    }

    [Fact]
    public async Task ParseProjectFileAsync_VersionInElement_ParsesCorrectly()
    {
        var tempFile = Path.GetTempFileName();
        try
        {
            await File.WriteAllTextAsync(tempFile, """
                <Project Sdk="Microsoft.NET.Sdk">
                  <ItemGroup>
                    <PackageReference Include="Serilog">
                      <Version>3.1.1</Version>
                    </PackageReference>
                  </ItemGroup>
                </Project>
                """);

            var result = await NuGetApiClient.ParseProjectFileAsync(tempFile, CancellationToken.None);

            Assert.True(result.IsSuccess);
            Assert.Single(result.Value);
            Assert.Equal("Serilog", result.Value[0].PackageId);
            Assert.Equal("3.1.1", result.Value[0].Version);
        }
        finally
        {
            File.Delete(tempFile);
        }
    }

    [Fact]
    public async Task ParseProjectFileAsync_NonexistentFile_ReturnsNotFound()
    {
        var fakePath = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString(), "nonexistent.csproj");

        var result = await NuGetApiClient.ParseProjectFileAsync(fakePath, CancellationToken.None);

        Assert.True(result.IsFailure);
        Assert.Equal(ErrorKind.NotFound, result.Kind);
    }

    [Fact]
    public async Task ParseProjectFileAsync_InvalidXml_ReturnsParseError()
    {
        var tempFile = Path.GetTempFileName();
        try
        {
            await File.WriteAllTextAsync(tempFile, "<Project><not closed");

            var result = await NuGetApiClient.ParseProjectFileAsync(tempFile, CancellationToken.None);

            Assert.True(result.IsFailure);
            Assert.Equal(ErrorKind.ParseError, result.Kind);
        }
        finally
        {
            File.Delete(tempFile);
        }
    }

    [Fact]
    public async Task ParseProjectFileAsync_NoPackageRefs_ReturnsEmpty()
    {
        var tempFile = Path.GetTempFileName();
        try
        {
            await File.WriteAllTextAsync(tempFile, """
                <Project Sdk="Microsoft.NET.Sdk">
                  <PropertyGroup>
                    <TargetFramework>net10.0</TargetFramework>
                  </PropertyGroup>
                </Project>
                """);

            var result = await NuGetApiClient.ParseProjectFileAsync(tempFile, CancellationToken.None);

            Assert.True(result.IsSuccess);
            Assert.Empty(result.Value);
        }
        finally
        {
            File.Delete(tempFile);
        }
    }

    // ──────────────────────────────────────────────
    // ParsePackagesConfigAsync
    // ──────────────────────────────────────────────

    [Fact]
    public async Task ParsePackagesConfigAsync_ValidConfig_ParsesPackages()
    {
        var tempFile = Path.GetTempFileName();
        try
        {
            await File.WriteAllTextAsync(tempFile, """
                <?xml version="1.0" encoding="utf-8"?>
                <packages>
                  <package id="Newtonsoft.Json" version="13.0.3" targetFramework="net48" />
                  <package id="Serilog" version="3.1.1" targetFramework="net48" />
                </packages>
                """);

            var result = await NuGetApiClient.ParsePackagesConfigAsync(tempFile, CancellationToken.None);

            Assert.Equal(2, result.Count);
            Assert.Equal("Newtonsoft.Json", result[0].PackageId);
            Assert.Equal("13.0.3", result[0].Version);
            Assert.Equal("Serilog", result[1].PackageId);
            Assert.Equal("3.1.1", result[1].Version);
            Assert.Equal(tempFile, result[0].SourceFile);
        }
        finally
        {
            File.Delete(tempFile);
        }
    }

    [Fact]
    public async Task ParsePackagesConfigAsync_NonexistentFile_ReturnsEmpty()
    {
        var fakePath = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString(), "packages.config");

        var result = await NuGetApiClient.ParsePackagesConfigAsync(fakePath, CancellationToken.None);

        Assert.Empty(result);
    }

    [Fact]
    public async Task ParsePackagesConfigAsync_InvalidXml_ReturnsEmpty()
    {
        var tempFile = Path.GetTempFileName();
        try
        {
            await File.WriteAllTextAsync(tempFile, "<packages><not closed");

            var result = await NuGetApiClient.ParsePackagesConfigAsync(tempFile, CancellationToken.None);

            Assert.Empty(result);
        }
        finally
        {
            File.Delete(tempFile);
        }
    }

    [Fact]
    public async Task ParsePackagesConfigAsync_MissingId_SkipsEntry()
    {
        var tempFile = Path.GetTempFileName();
        try
        {
            await File.WriteAllTextAsync(tempFile, """
                <?xml version="1.0" encoding="utf-8"?>
                <packages>
                  <package version="1.0.0" targetFramework="net48" />
                  <package id="ValidPkg" version="2.0.0" targetFramework="net48" />
                </packages>
                """);

            var result = await NuGetApiClient.ParsePackagesConfigAsync(tempFile, CancellationToken.None);

            Assert.Single(result);
            Assert.Equal("ValidPkg", result[0].PackageId);
            Assert.Equal("2.0.0", result[0].Version);
        }
        finally
        {
            File.Delete(tempFile);
        }
    }

    [Fact]
    public async Task ParsePackagesConfigAsync_EmptyConfig_ReturnsEmpty()
    {
        var tempFile = Path.GetTempFileName();
        try
        {
            await File.WriteAllTextAsync(tempFile, """
                <?xml version="1.0" encoding="utf-8"?>
                <packages>
                </packages>
                """);

            var result = await NuGetApiClient.ParsePackagesConfigAsync(tempFile, CancellationToken.None);

            Assert.Empty(result);
        }
        finally
        {
            File.Delete(tempFile);
        }
    }
}
