using DepSafe.Compliance;
using DepSafe.Models;

namespace DepSafe.Tests;

public class ProjectIdentityExtractorTests : IDisposable
{
    private readonly string _tempDir;

    public ProjectIdentityExtractorTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), $"depsafe-test-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_tempDir);
    }

    public void Dispose()
    {
        try { Directory.Delete(_tempDir, recursive: true); }
        catch { /* best effort cleanup */ }
    }

    [Fact]
    public async Task ExtractDotNetIdentityAsync_ReadsPackageIdAsName()
    {
        var csproj = Path.Combine(_tempDir, "Test.csproj");
        await File.WriteAllTextAsync(csproj, """
            <Project Sdk="Microsoft.NET.Sdk">
              <PropertyGroup>
                <PackageId>MyLibrary</PackageId>
                <Version>2.1.0</Version>
              </PropertyGroup>
            </Project>
            """);

        var result = await ProjectIdentityExtractor.ExtractDotNetIdentityAsync(csproj);

        Assert.True(result.IsSuccess);
        Assert.Equal("MyLibrary", result.Value.Name);
        Assert.Equal("2.1.0", result.Value.Version);
    }

    [Fact]
    public async Task ExtractDotNetIdentityAsync_FallsBackToAssemblyName()
    {
        var csproj = Path.Combine(_tempDir, "Test.csproj");
        await File.WriteAllTextAsync(csproj, """
            <Project Sdk="Microsoft.NET.Sdk">
              <PropertyGroup>
                <AssemblyName>MyAssembly</AssemblyName>
                <Version>1.0.0</Version>
              </PropertyGroup>
            </Project>
            """);

        var result = await ProjectIdentityExtractor.ExtractDotNetIdentityAsync(csproj);

        Assert.True(result.IsSuccess);
        Assert.Equal("MyAssembly", result.Value.Name);
    }

    [Fact]
    public async Task ExtractDotNetIdentityAsync_FallsBackToFilename()
    {
        var csproj = Path.Combine(_tempDir, "MyProject.csproj");
        await File.WriteAllTextAsync(csproj, """
            <Project Sdk="Microsoft.NET.Sdk">
              <PropertyGroup>
                <TargetFramework>net10.0</TargetFramework>
              </PropertyGroup>
            </Project>
            """);

        var result = await ProjectIdentityExtractor.ExtractDotNetIdentityAsync(csproj);

        Assert.True(result.IsSuccess);
        Assert.Equal("MyProject", result.Value.Name);
    }

    [Fact]
    public async Task ExtractDotNetIdentityAsync_ReadsVersionFromCsproj()
    {
        var csproj = Path.Combine(_tempDir, "App.csproj");
        await File.WriteAllTextAsync(csproj, """
            <Project Sdk="Microsoft.NET.Sdk">
              <PropertyGroup>
                <Version>3.5.1</Version>
              </PropertyGroup>
            </Project>
            """);

        var result = await ProjectIdentityExtractor.ExtractDotNetIdentityAsync(csproj);

        Assert.True(result.IsSuccess);
        Assert.Equal("3.5.1", result.Value.Version);
    }

    [Fact]
    public async Task ExtractDotNetIdentityAsync_ReadsVersionFromDirectoryBuildProps()
    {
        var subDir = Path.Combine(_tempDir, "src");
        Directory.CreateDirectory(subDir);

        await File.WriteAllTextAsync(Path.Combine(_tempDir, "Directory.Build.props"), """
            <Project>
              <PropertyGroup>
                <Version>4.0.0</Version>
              </PropertyGroup>
            </Project>
            """);

        var csproj = Path.Combine(subDir, "Lib.csproj");
        await File.WriteAllTextAsync(csproj, """
            <Project Sdk="Microsoft.NET.Sdk">
              <PropertyGroup>
                <TargetFramework>net10.0</TargetFramework>
              </PropertyGroup>
            </Project>
            """);

        var result = await ProjectIdentityExtractor.ExtractDotNetIdentityAsync(csproj);

        Assert.True(result.IsSuccess);
        Assert.Equal("4.0.0", result.Value.Version);
    }

    [Fact]
    public async Task ExtractDotNetIdentityAsync_SkipsMsBuildVariables()
    {
        var csproj = Path.Combine(_tempDir, "Versioned.csproj");
        await File.WriteAllTextAsync(csproj, """
            <Project Sdk="Microsoft.NET.Sdk">
              <PropertyGroup>
                <PackageId>$(AssemblyName)</PackageId>
                <Version>$(VersionPrefix)</Version>
              </PropertyGroup>
            </Project>
            """);

        var result = await ProjectIdentityExtractor.ExtractDotNetIdentityAsync(csproj);

        Assert.True(result.IsSuccess);
        Assert.Equal("Versioned", result.Value.Name);
        Assert.Equal("0.0.0", result.Value.Version);
    }

    [Fact]
    public async Task ExtractDotNetIdentityAsync_ReturnsFailureForMissingFile()
    {
        var result = await ProjectIdentityExtractor.ExtractDotNetIdentityAsync(
            Path.Combine(_tempDir, "nonexistent.csproj"));

        Assert.True(result.IsFailure);
        Assert.Equal(ErrorKind.NotFound, result.Kind);
    }

    [Fact]
    public void ExtractNpmIdentity_UsesPackageJsonNameAndVersion()
    {
        var packageJson = new PackageJson
        {
            Name = "my-library",
            Version = "2.3.0"
        };

        var identity = ProjectIdentityExtractor.ExtractNpmIdentity(packageJson, "/some/path");

        Assert.Equal("my-library", identity.Name);
        Assert.Equal("2.3.0", identity.Version);
    }

    [Fact]
    public void ExtractNpmIdentity_FallsBackToPathWhenNull()
    {
        var packageJson = new PackageJson();

        var identity = ProjectIdentityExtractor.ExtractNpmIdentity(packageJson, "/some/my-app");

        Assert.Equal("my-app", identity.Name);
        Assert.Equal("0.0.0", identity.Version);
    }
}
