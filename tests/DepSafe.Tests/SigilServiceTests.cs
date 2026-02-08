using System.Text.Json;
using DepSafe.Models;
using DepSafe.Signing;

namespace DepSafe.Tests;

public class SigilServiceTests
{
    // --- ParseEnvelope ---

    [Fact]
    public void ParseEnvelope_ValidJson_ReturnsEnvelope()
    {
        var json = """
        {
            "subject": {
                "name": "report.html",
                "digests": { "sha256": "abc123" },
                "mediaType": "text/html"
            },
            "signatures": [
                {
                    "keyId": "key-1",
                    "algorithm": "Ed25519",
                    "value": "sig-value-base64",
                    "timestamp": "2026-01-15T10:30:00Z",
                    "label": "release"
                }
            ]
        }
        """;

        var tempFile = Path.GetTempFileName();
        try
        {
            File.WriteAllText(tempFile, json);
            var result = SigilService.ParseEnvelope(tempFile);

            Assert.True(result.IsSuccess);
            Assert.Equal("report.html", result.Value.Subject.Name);
            Assert.Equal("abc123", result.Value.Subject.Digests["sha256"]);
            Assert.Single(result.Value.Signatures);
            Assert.Equal("Ed25519", result.Value.Signatures[0].Algorithm);
            Assert.Equal("key-1", result.Value.Signatures[0].KeyId);
        }
        finally
        {
            File.Delete(tempFile);
        }
    }

    [Fact]
    public void ParseEnvelope_InvalidJson_ReturnsParseError()
    {
        var tempFile = Path.GetTempFileName();
        try
        {
            File.WriteAllText(tempFile, "not valid json {{{");
            var result = SigilService.ParseEnvelope(tempFile);

            Assert.True(result.IsFailure);
            Assert.Equal(ErrorKind.ParseError, result.Kind);
        }
        finally
        {
            File.Delete(tempFile);
        }
    }

    [Fact]
    public void ParseEnvelope_MissingFile_ReturnsNotFound()
    {
        var result = SigilService.ParseEnvelope("/nonexistent/path/file.sig.json");

        Assert.True(result.IsFailure);
        Assert.Equal(ErrorKind.NotFound, result.Kind);
    }

    [Fact]
    public void ParseEnvelope_NullSubject_ReturnsParseError()
    {
        var json = """
        {
            "signatures": [
                { "keyId": "k1", "algorithm": "Ed25519", "value": "v1" }
            ]
        }
        """;

        var tempFile = Path.GetTempFileName();
        try
        {
            File.WriteAllText(tempFile, json);
            var result = SigilService.ParseEnvelope(tempFile);

            Assert.True(result.IsFailure);
            Assert.Equal(ErrorKind.ParseError, result.Kind);
        }
        finally
        {
            File.Delete(tempFile);
        }
    }

    // --- FindSignatureFiles ---

    [Fact]
    public void FindSignatureFiles_WithSigFiles_ReturnsMatches()
    {
        var tempDir = Path.Combine(Path.GetTempPath(), $"sigil-test-{Guid.NewGuid():N}");
        Directory.CreateDirectory(tempDir);
        try
        {
            File.WriteAllText(Path.Combine(tempDir, "report.html"), "content");
            File.WriteAllText(Path.Combine(tempDir, "report.html.sig.json"), "{}");
            File.WriteAllText(Path.Combine(tempDir, "sbom.json"), "content");
            // No sig for sbom.json

            var sigFiles = SigilService.FindSignatureFiles(tempDir);

            Assert.Single(sigFiles);
            Assert.Contains("report.html.sig.json", sigFiles[0]);
        }
        finally
        {
            Directory.Delete(tempDir, recursive: true);
        }
    }

    [Fact]
    public void FindSignatureFiles_NoSigFiles_ReturnsEmpty()
    {
        var tempDir = Path.Combine(Path.GetTempPath(), $"sigil-test-{Guid.NewGuid():N}");
        Directory.CreateDirectory(tempDir);
        try
        {
            File.WriteAllText(Path.Combine(tempDir, "report.html"), "content");

            var sigFiles = SigilService.FindSignatureFiles(tempDir);

            Assert.Empty(sigFiles);
        }
        finally
        {
            Directory.Delete(tempDir, recursive: true);
        }
    }

    // --- CheckAvailabilityAsync ---

    [Fact]
    public async Task CheckAvailabilityAsync_SigilAvailable_ReturnsSuccess()
    {
        var service = new SigilService(processRunner: (args, _) =>
            Task.FromResult(Result<(string StdOut, string StdErr, int ExitCode)>.Ok(
                ("sigil v1.0.0", "", 0))));

        var result = await service.CheckAvailabilityAsync(CancellationToken.None);

        Assert.True(result.IsSuccess);
        Assert.Equal("sigil v1.0.0", result.Value);
    }

    [Fact]
    public async Task CheckAvailabilityAsync_SigilNotFound_ReturnsExternalToolNotFound()
    {
        var service = new SigilService(processRunner: (_, _) =>
            Task.FromResult(Result<(string StdOut, string StdErr, int ExitCode)>.Fail(
                "sigil not found", ErrorKind.ExternalToolNotFound)));

        var result = await service.CheckAvailabilityAsync(CancellationToken.None);

        Assert.True(result.IsFailure);
        Assert.Equal(ErrorKind.ExternalToolNotFound, result.Kind);
    }

    // --- SignAsync ---

    [Fact]
    public async Task SignAsync_Success_ReturnsSignaturePath()
    {
        string? capturedArgs = null;
        var service = new SigilService(processRunner: (args, _) =>
        {
            capturedArgs = args;
            return Task.FromResult(Result<(string StdOut, string StdErr, int ExitCode)>.Ok(
                ("Signed: artifact.html.sig.json", "", 0)));
        });

        var result = await service.SignAsync("artifact.html", "mykey.pem", CancellationToken.None);

        Assert.True(result.IsSuccess);
        Assert.NotNull(capturedArgs);
        Assert.Contains("sign", capturedArgs);
        Assert.Contains("artifact.html", capturedArgs);
        Assert.Contains("mykey.pem", capturedArgs);
    }

    [Fact]
    public async Task SignAsync_Failure_ReturnsError()
    {
        var service = new SigilService(processRunner: (_, _) =>
            Task.FromResult(Result<(string StdOut, string StdErr, int ExitCode)>.Ok(
                ("", "Error: key not found", 1))));

        var result = await service.SignAsync("artifact.html", "badkey.pem", CancellationToken.None);

        Assert.True(result.IsFailure);
    }

    [Fact]
    public async Task SignAsync_WithoutKey_OmitsKeyArg()
    {
        string? capturedArgs = null;
        var service = new SigilService(processRunner: (args, _) =>
        {
            capturedArgs = args;
            return Task.FromResult(Result<(string StdOut, string StdErr, int ExitCode)>.Ok(
                ("Signed: artifact.html.sig.json", "", 0)));
        });

        var result = await service.SignAsync("artifact.html", null, CancellationToken.None);

        Assert.True(result.IsSuccess);
        Assert.NotNull(capturedArgs);
        Assert.DoesNotContain("--key", capturedArgs);
    }

    // --- VerifyAsync ---

    [Fact]
    public async Task VerifyAsync_ValidSignature_ReturnsVerificationResult()
    {
        var verifyOutput = JsonSerializer.Serialize(new
        {
            valid = true,
            algorithm = "Ed25519",
            fingerprint = "SHA256:abc123",
            signedAt = "2026-01-15T10:30:00Z"
        });

        string? capturedArgs = null;
        var service = new SigilService(processRunner: (args, _) =>
        {
            capturedArgs = args;
            return Task.FromResult(Result<(string StdOut, string StdErr, int ExitCode)>.Ok(
                (verifyOutput, "", 0)));
        });

        var result = await service.VerifyAsync("artifact.html.sig.json", null, CancellationToken.None);

        Assert.True(result.IsSuccess);
        Assert.True(result.Value.IsValid);
        Assert.Equal("Ed25519", result.Value.Algorithm);
        Assert.Equal("SHA256:abc123", result.Value.Fingerprint);
        Assert.NotNull(capturedArgs);
        Assert.Contains("verify", capturedArgs);
    }

    [Fact]
    public async Task VerifyAsync_WithTrustBundle_IncludesArg()
    {
        string? capturedArgs = null;
        var service = new SigilService(processRunner: (args, _) =>
        {
            capturedArgs = args;
            return Task.FromResult(Result<(string StdOut, string StdErr, int ExitCode)>.Ok(
                ("{\"valid\":true}", "", 0)));
        });

        var result = await service.VerifyAsync("artifact.sig.json", "trusted-keys.pem", CancellationToken.None);

        Assert.True(result.IsSuccess);
        Assert.NotNull(capturedArgs);
        Assert.Contains("--trust-bundle", capturedArgs);
        Assert.Contains("trusted-keys.pem", capturedArgs);
    }

    [Fact]
    public async Task VerifyAsync_InvalidSignature_ReturnsInvalidResult()
    {
        var service = new SigilService(processRunner: (_, _) =>
            Task.FromResult(Result<(string StdOut, string StdErr, int ExitCode)>.Ok(
                ("", "Error: signature verification failed", 1))));

        var result = await service.VerifyAsync("artifact.sig.json", null, CancellationToken.None);

        Assert.True(result.IsSuccess);
        Assert.False(result.Value.IsValid);
        Assert.NotNull(result.Value.Error);
    }

    [Fact]
    public async Task VerifyAsync_ProcessFailure_ReturnsError()
    {
        var service = new SigilService(processRunner: (_, _) =>
            Task.FromResult(Result<(string StdOut, string StdErr, int ExitCode)>.Fail(
                "process crashed", ErrorKind.Unknown)));

        var result = await service.VerifyAsync("artifact.sig.json", null, CancellationToken.None);

        Assert.True(result.IsFailure);
    }

    // --- EscapeArgument ---

    [Theory]
    [InlineData("simple.html", "\"simple.html\"")]
    [InlineData("path with spaces.html", "\"path with spaces.html\"")]
    [InlineData("file\"name.html", "\"file\\\"name.html\"")]
    [InlineData("C:\\path\\to\\dir\\", "\"C:\\path\\to\\dir\\\\\"")]
    [InlineData("C:\\path\\\"evil", "\"C:\\path\\\\\\\"evil\"")]
    [InlineData("dir\\\\", "\"dir\\\\\\\\\"")]
    [InlineData("", "\"\"")]
    public void EscapeArgument_EscapesCorrectly(string input, string expected)
    {
        var result = SigilService.EscapeArgument(input);

        Assert.Equal(expected, result);
    }
}
