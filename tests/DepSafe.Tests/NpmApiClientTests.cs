using System.Text.Json.Nodes;
using DepSafe.DataSources;
using DepSafe.Models;

namespace DepSafe.Tests;

public class NpmApiClientTests
{
    // ── NormalizeGitUrl ──────────────────────────────────────────────────

    [Fact]
    public void NormalizeGitUrl_GitPlusHttps_StripsPrefix()
    {
        var result = NpmApiClient.NormalizeGitUrl("git+https://github.com/o/r.git");

        Assert.Equal("https://github.com/o/r", result);
    }

    [Fact]
    public void NormalizeGitUrl_GitProtocol_ConvertsToHttps()
    {
        var result = NpmApiClient.NormalizeGitUrl("git://github.com/o/r.git");

        Assert.Equal("https://github.com/o/r", result);
    }

    [Fact]
    public void NormalizeGitUrl_DotGitSuffix_Stripped()
    {
        var result = NpmApiClient.NormalizeGitUrl("https://github.com/o/r.git");

        Assert.Equal("https://github.com/o/r", result);
    }

    [Fact]
    public void NormalizeGitUrl_Null_ReturnsNull()
    {
        Assert.Null(NpmApiClient.NormalizeGitUrl(null));
    }

    // ── CalculateMaxDepth ────────────────────────────────────────────────

    [Fact]
    public void CalculateMaxDepth_EmptyList_ReturnsZero()
    {
        var result = NpmApiClient.CalculateMaxDepth([]);

        Assert.Equal(0, result);
    }

    [Fact]
    public void CalculateMaxDepth_FlatNodes_ReturnsOne()
    {
        var roots = new List<DependencyTreeNode>
        {
            new()
            {
                PackageId = "root",
                Version = "1.0.0",
                Depth = 0,
                Children =
                [
                    new DependencyTreeNode
                    {
                        PackageId = "child-a",
                        Version = "1.0.0",
                        Depth = 1
                    },
                    new DependencyTreeNode
                    {
                        PackageId = "child-b",
                        Version = "2.0.0",
                        Depth = 1
                    }
                ]
            }
        };

        var result = NpmApiClient.CalculateMaxDepth(roots);

        Assert.Equal(1, result);
    }

    [Fact]
    public void CalculateMaxDepth_NestedThreeLevels_ReturnsThree()
    {
        var roots = new List<DependencyTreeNode>
        {
            new()
            {
                PackageId = "root",
                Version = "1.0.0",
                Depth = 0,
                Children =
                [
                    new DependencyTreeNode
                    {
                        PackageId = "child",
                        Version = "1.0.0",
                        Depth = 1,
                        Children =
                        [
                            new DependencyTreeNode
                            {
                                PackageId = "grandchild",
                                Version = "1.0.0",
                                Depth = 2,
                                Children =
                                [
                                    new DependencyTreeNode
                                    {
                                        PackageId = "great-grandchild",
                                        Version = "1.0.0",
                                        Depth = 3
                                    }
                                ]
                            }
                        ]
                    }
                ]
            }
        };

        var result = NpmApiClient.CalculateMaxDepth(roots);

        Assert.Equal(3, result);
    }

    // ── ExtractPackageNameFromPath ───────────────────────────────────────

    [Fact]
    public void ExtractPackageNameFromPath_SimplePackage_ReturnsName()
    {
        var result = NpmApiClient.ExtractPackageNameFromPath("node_modules/express");

        Assert.Equal("express", result);
    }

    [Fact]
    public void ExtractPackageNameFromPath_ScopedPackage_ReturnsScoped()
    {
        var result = NpmApiClient.ExtractPackageNameFromPath("node_modules/@types/node");

        Assert.Equal("@types/node", result);
    }

    [Fact]
    public void ExtractPackageNameFromPath_InvalidPath_ReturnsNull()
    {
        var result = NpmApiClient.ExtractPackageNameFromPath("src/index.js");

        Assert.Null(result);
    }

    // ── ExtractAuthorName ────────────────────────────────────────────────

    [Fact]
    public void ExtractAuthorName_StringValue_ReturnsName()
    {
        var node = JsonValue.Create("John Doe <john@x.com>");

        var result = NpmApiClient.ExtractAuthorName(node);

        Assert.Equal("John Doe", result);
    }

    [Fact]
    public void ExtractAuthorName_ObjectWithName_ReturnsName()
    {
        var node = JsonNode.Parse("""{"name": "Jane Doe"}""");

        var result = NpmApiClient.ExtractAuthorName(node);

        Assert.Equal("Jane Doe", result);
    }

    [Fact]
    public void ExtractAuthorName_Null_ReturnsNull()
    {
        var result = NpmApiClient.ExtractAuthorName(null);

        Assert.Null(result);
    }

    // ── ParseDependencyObject ────────────────────────────────────────────

    [Fact]
    public void ParseDependencyObject_ValidObject_ReturnsDictionary()
    {
        var node = JsonNode.Parse("""{"express": "^4.0", "lodash": "~4.17.21"}""");

        var result = NpmApiClient.ParseDependencyObject(node);

        Assert.Equal(2, result.Count);
        Assert.Equal("^4.0", result["express"]);
        Assert.Equal("~4.17.21", result["lodash"]);
    }

    [Fact]
    public void ParseDependencyObject_Null_ReturnsEmptyDict()
    {
        var result = NpmApiClient.ParseDependencyObject(null);

        Assert.Empty(result);
    }

    // ── ParsePackageJsonAsync ────────────────────────────────────────────

    [Fact]
    public async Task ParsePackageJsonAsync_CompleteJson_ParsesAllFields()
    {
        var tempFile = Path.GetTempFileName();
        try
        {
            await File.WriteAllTextAsync(tempFile, """
            {
                "name": "@myorg/myapp",
                "version": "2.1.0",
                "license": "MIT",
                "repository": {
                    "type": "git",
                    "url": "git+https://github.com/myorg/myapp.git"
                },
                "dependencies": {
                    "express": "^4.18.0",
                    "lodash": "^4.17.21"
                },
                "devDependencies": {
                    "jest": "^29.0.0"
                },
                "peerDependencies": {
                    "react": "^18.0.0"
                }
            }
            """);

            var result = await NpmApiClient.ParsePackageJsonAsync(tempFile, CancellationToken.None);

            Assert.True(result.IsSuccess);
            var pkg = result.Value;
            Assert.Equal("@myorg/myapp", pkg.Name);
            Assert.Equal("2.1.0", pkg.Version);
            Assert.Equal("MIT", pkg.License);
            Assert.Equal("https://github.com/myorg/myapp", pkg.Repository);
            Assert.Equal(2, pkg.Dependencies.Count);
            Assert.Equal("^4.18.0", pkg.Dependencies["express"]);
            Assert.Equal("^4.17.21", pkg.Dependencies["lodash"]);
            Assert.Single(pkg.DevDependencies);
            Assert.Equal("^29.0.0", pkg.DevDependencies["jest"]);
            Assert.Single(pkg.PeerDependencies);
            Assert.Equal("^18.0.0", pkg.PeerDependencies["react"]);
        }
        finally
        {
            File.Delete(tempFile);
        }
    }

    [Fact]
    public async Task ParsePackageJsonAsync_MinimalJson_ParsesName()
    {
        var tempFile = Path.GetTempFileName();
        try
        {
            await File.WriteAllTextAsync(tempFile, """{"name": "test"}""");

            var result = await NpmApiClient.ParsePackageJsonAsync(tempFile, CancellationToken.None);

            Assert.True(result.IsSuccess);
            Assert.Equal("test", result.Value.Name);
            Assert.Null(result.Value.Version);
            Assert.Empty(result.Value.Dependencies);
            Assert.Empty(result.Value.DevDependencies);
            Assert.Empty(result.Value.PeerDependencies);
        }
        finally
        {
            File.Delete(tempFile);
        }
    }

    [Fact]
    public async Task ParsePackageJsonAsync_NonexistentFile_ReturnsNotFound()
    {
        var fakePath = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString(), "package.json");

        var result = await NpmApiClient.ParsePackageJsonAsync(fakePath, CancellationToken.None);

        Assert.True(result.IsFailure);
        Assert.Equal(ErrorKind.NotFound, result.Kind);
    }

    [Fact]
    public async Task ParsePackageJsonAsync_InvalidJson_ReturnsParseError()
    {
        var tempFile = Path.GetTempFileName();
        try
        {
            await File.WriteAllTextAsync(tempFile, "this is not valid json {{{");

            var result = await NpmApiClient.ParsePackageJsonAsync(tempFile, CancellationToken.None);

            Assert.True(result.IsFailure);
            Assert.Equal(ErrorKind.ParseError, result.Kind);
        }
        finally
        {
            File.Delete(tempFile);
        }
    }

    // ── ParsePackageLockAsync ────────────────────────────────────────────

    [Fact]
    public async Task ParsePackageLockAsync_V2Format_ParsesPackages()
    {
        var tempFile = Path.GetTempFileName();
        try
        {
            await File.WriteAllTextAsync(tempFile, """
            {
                "name": "myapp",
                "version": "1.0.0",
                "lockfileVersion": 2,
                "packages": {
                    "": {
                        "name": "myapp",
                        "version": "1.0.0"
                    },
                    "node_modules/express": {
                        "version": "4.18.2",
                        "resolved": "https://registry.npmjs.org/express/-/express-4.18.2.tgz",
                        "integrity": "sha512-abc123",
                        "dependencies": {
                            "body-parser": "1.20.1"
                        }
                    },
                    "node_modules/@types/node": {
                        "version": "20.5.0",
                        "resolved": "https://registry.npmjs.org/@types/node/-/node-20.5.0.tgz",
                        "dev": true
                    }
                }
            }
            """);

            var result = await NpmApiClient.ParsePackageLockAsync(tempFile, CancellationToken.None);

            Assert.True(result.IsSuccess);
            var deps = result.Value;
            Assert.Equal(2, deps.Count);

            var express = deps.First(d => d.Name == "express");
            Assert.Equal("4.18.2", express.Version);
            Assert.Equal("https://registry.npmjs.org/express/-/express-4.18.2.tgz", express.ResolvedUrl);
            Assert.Equal("sha512-abc123", express.Integrity);
            Assert.False(express.IsDev);
            Assert.Single(express.Dependencies);
            Assert.Equal("1.20.1", express.Dependencies["body-parser"]);

            var typesNode = deps.First(d => d.Name == "@types/node");
            Assert.Equal("20.5.0", typesNode.Version);
            Assert.True(typesNode.IsDev);
        }
        finally
        {
            File.Delete(tempFile);
        }
    }

    [Fact]
    public async Task ParsePackageLockAsync_NonexistentFile_ReturnsNotFound()
    {
        var fakePath = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString(), "package-lock.json");

        var result = await NpmApiClient.ParsePackageLockAsync(fakePath, CancellationToken.None);

        Assert.True(result.IsFailure);
        Assert.Equal(ErrorKind.NotFound, result.Kind);
    }

    [Fact]
    public async Task ParsePackageLockAsync_InvalidJson_ReturnsParseError()
    {
        var tempFile = Path.GetTempFileName();
        try
        {
            await File.WriteAllTextAsync(tempFile, "not json at all!!!");

            var result = await NpmApiClient.ParsePackageLockAsync(tempFile, CancellationToken.None);

            Assert.True(result.IsFailure);
            Assert.Equal(ErrorKind.ParseError, result.Kind);
        }
        finally
        {
            File.Delete(tempFile);
        }
    }
}
