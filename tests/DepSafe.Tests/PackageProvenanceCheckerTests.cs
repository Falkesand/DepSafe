using System.Net;
using System.Text.Json;
using DepSafe.Compliance;
using DepSafe.Models;

namespace DepSafe.Tests;

public class PackageProvenanceCheckerTests
{
    private sealed class MockHandler : HttpMessageHandler
    {
        private readonly Func<HttpRequestMessage, HttpResponseMessage> _handler;
        public MockHandler(Func<HttpRequestMessage, HttpResponseMessage> h) => _handler = h;
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage r, CancellationToken ct)
            => Task.FromResult(_handler(r));
    }

    [Fact]
    public void IsAllowedUrl_NuGetApi_ReturnsTrue()
    {
        Assert.True(PackageProvenanceChecker.IsAllowedUrl("https://api.nuget.org/v3/catalog/data/2024.01.01.json"));
    }

    [Fact]
    public void IsAllowedUrl_NpmRegistry_ReturnsTrue()
    {
        Assert.True(PackageProvenanceChecker.IsAllowedUrl("https://registry.npmjs.org/express"));
    }

    [Fact]
    public void IsAllowedUrl_UnknownHost_ReturnsFalse()
    {
        Assert.False(PackageProvenanceChecker.IsAllowedUrl("https://evil.com/foo"));
    }

    [Fact]
    public void IsAllowedUrl_HttpScheme_ReturnsFalse()
    {
        Assert.False(PackageProvenanceChecker.IsAllowedUrl("http://api.nuget.org/v3/catalog/data/2024.01.01.json"));
    }

    [Fact]
    public void IsAllowedUrl_MalformedUrl_ReturnsFalse()
    {
        Assert.False(PackageProvenanceChecker.IsAllowedUrl("not-a-url"));
    }

    [Fact]
    public async Task CheckNuGetProvenanceAsync_SignedPackage_DetectsSignature()
    {
        var handler = new MockHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(JsonSerializer.Serialize(new
            {
                published = "2024-01-01T00:00:00Z"
            }))
        });

        using var checker = new PackageProvenanceChecker(new HttpClient(handler));

        var results = await checker.CheckNuGetProvenanceAsync(
            [("Newtonsoft.Json", "13.0.3")]);

        Assert.Single(results);
        var result = results[0];
        Assert.Equal("Newtonsoft.Json", result.PackageId);
        Assert.Equal("13.0.3", result.Version);
        Assert.True(result.HasRepositorySignature);
        Assert.True(result.IsVerified);
        Assert.Equal(PackageEcosystem.NuGet, result.Ecosystem);
    }

    [Fact]
    public async Task CheckNuGetProvenanceAsync_NotFound_GracefulDegradation()
    {
        var handler = new MockHandler(_ => new HttpResponseMessage(HttpStatusCode.NotFound));

        using var checker = new PackageProvenanceChecker(new HttpClient(handler));

        var results = await checker.CheckNuGetProvenanceAsync(
            [("NonExistent.Package", "0.0.1")]);

        Assert.Single(results);
        var result = results[0];
        Assert.Equal("NonExistent.Package", result.PackageId);
        Assert.Equal("0.0.1", result.Version);
        Assert.False(result.HasRepositorySignature);
        Assert.False(result.HasAuthorSignature);
        Assert.False(result.IsVerified);
        Assert.Equal(PackageEcosystem.NuGet, result.Ecosystem);
    }

    [Fact]
    public async Task CheckNuGetProvenanceAsync_EmptyInput_ReturnsEmpty()
    {
        var handler = new MockHandler(_ => new HttpResponseMessage(HttpStatusCode.OK));

        using var checker = new PackageProvenanceChecker(new HttpClient(handler));

        var results = await checker.CheckNuGetProvenanceAsync([]);

        Assert.Empty(results);
    }

    [Fact]
    public async Task CheckNpmProvenanceAsync_WithSignatures_DetectsSignature()
    {
        var handler = new MockHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(JsonSerializer.Serialize(new
            {
                dist = new
                {
                    signatures = new[]
                    {
                        new { keyid = "SHA256:abc", sig = "meow" }
                    },
                    integrity = "sha512-abc123def456"
                }
            }))
        });

        using var checker = new PackageProvenanceChecker(new HttpClient(handler));

        var results = await checker.CheckNpmProvenanceAsync(
            [("express", "4.18.2")]);

        Assert.Single(results);
        var result = results[0];
        Assert.Equal("express", result.PackageId);
        Assert.Equal("4.18.2", result.Version);
        Assert.True(result.HasRepositorySignature);
        Assert.True(result.IsVerified);
        Assert.Equal(PackageEcosystem.Npm, result.Ecosystem);
        Assert.Equal("SHA512", result.ContentHashAlgorithm);
        Assert.Equal("abc123def456", result.ContentHash);
    }

    [Fact]
    public async Task CheckNpmProvenanceAsync_UnsignedPackage_NoSignatures()
    {
        var handler = new MockHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(JsonSerializer.Serialize(new
            {
                dist = new
                {
                    integrity = "sha512-xyz789"
                }
            }))
        });

        using var checker = new PackageProvenanceChecker(new HttpClient(handler));

        var results = await checker.CheckNpmProvenanceAsync(
            [("some-unsigned-pkg", "1.0.0")]);

        Assert.Single(results);
        var result = results[0];
        Assert.Equal("some-unsigned-pkg", result.PackageId);
        Assert.Equal("1.0.0", result.Version);
        Assert.False(result.HasRepositorySignature);
        Assert.False(result.HasAuthorSignature);
        Assert.False(result.IsVerified);
        Assert.Equal(PackageEcosystem.Npm, result.Ecosystem);
    }

    [Fact]
    public async Task CheckNpmProvenanceAsync_NotFound_GracefulDegradation()
    {
        var handler = new MockHandler(_ => new HttpResponseMessage(HttpStatusCode.NotFound));

        using var checker = new PackageProvenanceChecker(new HttpClient(handler));

        var results = await checker.CheckNpmProvenanceAsync(
            [("nonexistent-pkg", "0.0.1")]);

        Assert.Single(results);
        var result = results[0];
        Assert.Equal("nonexistent-pkg", result.PackageId);
        Assert.Equal("0.0.1", result.Version);
        Assert.False(result.HasRepositorySignature);
        Assert.False(result.HasAuthorSignature);
        Assert.False(result.IsVerified);
        Assert.Equal(PackageEcosystem.Npm, result.Ecosystem);
    }

    [Fact]
    public async Task CheckNpmProvenanceAsync_EmptyInput_ReturnsEmpty()
    {
        var handler = new MockHandler(_ => new HttpResponseMessage(HttpStatusCode.OK));

        using var checker = new PackageProvenanceChecker(new HttpClient(handler));

        var results = await checker.CheckNpmProvenanceAsync([]);

        Assert.Empty(results);
    }
}
