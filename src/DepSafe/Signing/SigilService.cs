using System.Diagnostics;
using System.Text.Json;
using DepSafe.Models;

namespace DepSafe.Signing;

/// <summary>
/// Wraps the sigil CLI for signing and verifying artifact envelopes.
/// Uses process invocation with timeout and cancellation support.
/// </summary>
public sealed class SigilService
{
    private static readonly TimeSpan ProcessTimeout = TimeSpan.FromSeconds(30);

    internal delegate Task<Result<(string StdOut, string StdErr, int ExitCode)>> ProcessRunner(
        string arguments, CancellationToken ct);

    private readonly ProcessRunner _runProcess;

    public SigilService()
    {
        _runProcess = RunProcessAsync;
    }

    internal SigilService(ProcessRunner processRunner)
    {
        _runProcess = processRunner;
    }

    /// <summary>
    /// Check whether sigil CLI is installed and available on PATH.
    /// Returns the version string on success.
    /// </summary>
    public async Task<Result<string>> CheckAvailabilityAsync(CancellationToken ct)
    {
        var result = await _runProcess("--version", ct);
        if (result.IsFailure)
            return Result.Fail<string>(result.Error, result.Kind);

        var (stdout, stderr, exitCode) = result.Value;
        if (exitCode != 0)
            return Result.Fail<string>(
                string.IsNullOrWhiteSpace(stderr) ? "sigil exited with non-zero code" : stderr.Trim(),
                ErrorKind.ExternalToolNotFound);

        return stdout.Trim();
    }

    /// <summary>
    /// Sign an artifact file, producing a detached .sig.json envelope.
    /// </summary>
    /// <param name="artifactPath">Path to the file to sign.</param>
    /// <param name="keyPath">Optional path to the signing key. If null, sigil uses its default key.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>Path to the generated .sig.json file.</returns>
    public async Task<Result<string>> SignAsync(string artifactPath, string? keyPath, CancellationToken ct)
    {
        var args = keyPath is not null
            ? $"sign --key {EscapeArgument(keyPath)} {EscapeArgument(artifactPath)}"
            : $"sign {EscapeArgument(artifactPath)}";

        var result = await _runProcess(args, ct);
        if (result.IsFailure)
            return Result.Fail<string>(result.Error, result.Kind);

        var (stdout, stderr, exitCode) = result.Value;
        if (exitCode != 0)
        {
            var errorMsg = string.IsNullOrWhiteSpace(stderr) ? stdout.Trim() : stderr.Trim();
            return Result.Fail<string>(
                string.IsNullOrEmpty(errorMsg) ? "sigil sign failed" : errorMsg,
                ErrorKind.Unknown);
        }

        var sigPath = $"{artifactPath}.sig.json";
        return sigPath;
    }

    /// <summary>
    /// Verify a .sig.json envelope against its artifact.
    /// </summary>
    /// <param name="signaturePath">Path to the .sig.json file.</param>
    /// <param name="trustBundlePath">Optional path to a trust bundle for key verification.</param>
    /// <param name="ct">Cancellation token.</param>
    public async Task<Result<VerificationResult>> VerifyAsync(string signaturePath, string? trustBundlePath, CancellationToken ct)
    {
        var args = trustBundlePath is not null
            ? $"verify --trust-bundle {EscapeArgument(trustBundlePath)} {EscapeArgument(signaturePath)}"
            : $"verify {EscapeArgument(signaturePath)}";

        var result = await _runProcess(args, ct);
        if (result.IsFailure)
            return Result.Fail<VerificationResult>(result.Error, result.Kind);

        var (stdout, stderr, exitCode) = result.Value;
        if (exitCode != 0)
        {
            return new VerificationResult
            {
                IsValid = false,
                Error = string.IsNullOrWhiteSpace(stderr) ? "Verification failed" : stderr.Trim()
            };
        }

        try
        {
            using var doc = JsonDocument.Parse(stdout);
            var root = doc.RootElement;

            return new VerificationResult
            {
                IsValid = root.TryGetProperty("valid", out var v) && v.GetBoolean(),
                Algorithm = root.TryGetProperty("algorithm", out var a) ? a.GetString() : null,
                Fingerprint = root.TryGetProperty("fingerprint", out var f) ? f.GetString() : null,
                SignedAt = root.TryGetProperty("signedAt", out var s) && s.TryGetDateTime(out var dt) ? dt : null
            };
        }
        catch (JsonException)
        {
            // Non-JSON output but exit code 0 — treat as valid with no metadata
            return new VerificationResult { IsValid = true };
        }
    }

    /// <summary>
    /// Parse a .sig.json envelope file without running sigil.
    /// </summary>
    public static Result<SignatureEnvelope> ParseEnvelope(string signaturePath)
    {
        if (!File.Exists(signaturePath))
            return Result.Fail<SignatureEnvelope>($"Signature file not found: {signaturePath}", ErrorKind.NotFound);

        try
        {
            var json = File.ReadAllText(signaturePath);
            var envelope = JsonSerializer.Deserialize<SignatureEnvelope>(json);

            if (envelope?.Subject is null || envelope.Signatures is null)
                return Result.Fail<SignatureEnvelope>("Invalid envelope: missing subject or signatures", ErrorKind.ParseError);

            return envelope;
        }
        catch (JsonException ex)
        {
            return Result.Fail<SignatureEnvelope>($"Failed to parse envelope: {ex.Message}", ErrorKind.ParseError);
        }
    }

    /// <summary>
    /// Find all .sig.json files in a directory.
    /// </summary>
    public static List<string> FindSignatureFiles(string directory)
    {
        if (!Directory.Exists(directory))
            return [];

        return Directory.GetFiles(directory, "*.sig.json")
            .OrderBy(f => f, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    /// <summary>
    /// Escape a value for safe use as a process argument on Windows.
    /// Follows the MSVC CRT CommandLineToArgvW convention:
    /// - Wraps in double quotes
    /// - Backslashes before a quote are doubled, then the quote is escaped
    /// - Trailing backslashes before the closing quote are doubled
    /// </summary>
    internal static string EscapeArgument(string value)
    {
        var sb = new System.Text.StringBuilder(value.Length + 4);
        sb.Append('"');

        for (var i = 0; i < value.Length; i++)
        {
            var backslashCount = 0;
            while (i < value.Length && value[i] == '\\')
            {
                backslashCount++;
                i++;
            }

            if (i == value.Length)
            {
                // Trailing backslashes: double them before the closing quote
                sb.Append('\\', backslashCount * 2);
                break;
            }

            if (value[i] == '"')
            {
                // Backslashes before a quote: double them, then escape the quote
                sb.Append('\\', backslashCount * 2 + 1);
                sb.Append('"');
            }
            else
            {
                // Backslashes not before a quote: keep as-is
                sb.Append('\\', backslashCount);
                sb.Append(value[i]);
            }
        }

        sb.Append('"');
        return sb.ToString();
    }

    private static async Task<Result<(string StdOut, string StdErr, int ExitCode)>> RunProcessAsync(
        string arguments, CancellationToken ct)
    {
        try
        {
            using var process = new Process();
            process.StartInfo = new ProcessStartInfo
            {
                FileName = "sigil",
                Arguments = arguments,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            process.Start();

            var stdoutTask = process.StandardOutput.ReadToEndAsync(ct);
            var stderrTask = process.StandardError.ReadToEndAsync(ct);

            using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeoutCts.CancelAfter(ProcessTimeout);

            try
            {
                await process.WaitForExitAsync(timeoutCts.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested)
            {
                try { process.Kill(entireProcessTree: true); } catch { /* best effort */ }
                return Result.Fail<(string, string, int)>("sigil process timed out", ErrorKind.Timeout);
            }

            var stdout = await stdoutTask.ConfigureAwait(false);
            var stderr = await stderrTask.ConfigureAwait(false);

            return (stdout, stderr, process.ExitCode);
        }
        catch (System.ComponentModel.Win32Exception)
        {
            return Result.Fail<(string, string, int)>(
                "sigil CLI not found. Install from https://github.com/Falkesand/Sigil.Sign",
                ErrorKind.ExternalToolNotFound);
        }
        catch (OperationCanceledException)
        {
            throw; // Let cancellation propagate
        }
        catch (Exception ex)
        {
            return Result.Fail<(string, string, int)>($"Failed to run sigil: {ex.Message}", ErrorKind.Unknown);
        }
    }
}
