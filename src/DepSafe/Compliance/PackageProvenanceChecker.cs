using System.Net;
using System.Text.Json;
using DepSafe.Models;

namespace DepSafe.Compliance;

/// <summary>
/// Checks package signing/provenance per CRA Art. 13(5).
/// Supports NuGet repository signatures and npm registry signatures/attestations.
/// </summary>
public sealed class PackageProvenanceChecker : IDisposable
{
    private static readonly string s_userAgent = GetUserAgent();

    private static readonly HashSet<string> s_allowedHosts = new(StringComparer.OrdinalIgnoreCase)
    {
        "api.nuget.org",
        "www.nuget.org",
        "registry.npmjs.org",
        "www.npmjs.com"
    };

    private readonly HttpClient _httpClient;
    private readonly bool _ownsHttpClient;
    private bool _disposed;

    public PackageProvenanceChecker(HttpClient? httpClient = null)
    {
        if (httpClient is not null)
        {
            _httpClient = httpClient;
            _ownsHttpClient = false;
        }
        else
        {
            var handler = new HttpClientHandler
            {
                AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate
            };
            _httpClient = new HttpClient(handler);
            _ownsHttpClient = true;
        }
        _httpClient.DefaultRequestHeaders.UserAgent.TryParseAdd(s_userAgent);
    }

    /// <summary>
    /// Check provenance for a batch of NuGet packages.
    /// Uses the NuGet V3 registration API to check for signature info.
    /// </summary>
    public async Task<List<ProvenanceResult>> CheckNuGetProvenanceAsync(
        IReadOnlyList<(string PackageId, string Version)> packages)
    {
        using var semaphore = new SemaphoreSlim(5);

        var tasks = packages.Select(async pkg =>
        {
            await semaphore.WaitAsync();
            try
            {
                return await CheckSingleNuGetPackageAsync(pkg.PackageId, pkg.Version);
            }
            finally
            {
                semaphore.Release();
            }
        });

        var results = await Task.WhenAll(tasks);
        return [.. results];
    }

    private async Task<ProvenanceResult> CheckSingleNuGetPackageAsync(string packageId, string version)
    {
        try
        {
            // NuGet.org signs all packages with a repository signature
            // Check the registration endpoint for signature metadata
            var url = $"https://api.nuget.org/v3/registration5-gz-semver2/{Uri.EscapeDataString(packageId.ToLowerInvariant())}/{Uri.EscapeDataString(version.ToLowerInvariant())}.json";

            using var response = await _httpClient.GetAsync(url);
            if (!response.IsSuccessStatusCode)
            {
                return new ProvenanceResult
                {
                    PackageId = packageId,
                    Version = version,
                    HasRepositorySignature = false,
                    HasAuthorSignature = false,
                    Ecosystem = PackageEcosystem.NuGet
                };
            }

            var json = await response.Content.ReadAsStringAsync();
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;

            // Check for published property (indicates it's on nuget.org, which repo-signs everything)
            var hasCatalog = root.TryGetProperty("catalogEntry", out var catalog);
            var hasPublished = root.TryGetProperty("published", out _) ||
                               (hasCatalog && catalog.TryGetProperty("published", out _));

            // Fetch package hash from catalog entry
            string? contentHash = null;
            string? hashAlgorithm = null;
            if (hasCatalog && catalog.ValueKind == JsonValueKind.String)
            {
                try
                {
                    var catalogUrl = catalog.GetString();
                    if (!string.IsNullOrEmpty(catalogUrl) && IsAllowedUrl(catalogUrl))
                    {
                        using var catalogResponse = await _httpClient.GetAsync(catalogUrl);
                        if (catalogResponse.IsSuccessStatusCode)
                        {
                            var catalogJson = await catalogResponse.Content.ReadAsStringAsync();
                            using var catalogDoc = JsonDocument.Parse(catalogJson);
                            if (catalogDoc.RootElement.TryGetProperty("packageHash", out var hashProp))
                            {
                                contentHash = hashProp.GetString();
                                hashAlgorithm = catalogDoc.RootElement.TryGetProperty("packageHashAlgorithm", out var algProp)
                                    ? algProp.GetString() : "SHA512";
                            }
                        }
                    }
                }
                catch (Exception ex) when (ex is HttpRequestException or JsonException) { /* Non-critical — checksum is best-effort */ }
            }

            // NuGet.org repository-signs all packages since April 2019
            // If the package exists on nuget.org, it has a repository signature
            return new ProvenanceResult
            {
                PackageId = packageId,
                Version = version,
                HasRepositorySignature = hasPublished,
                HasAuthorSignature = false, // Author signatures require deeper analysis
                Ecosystem = PackageEcosystem.NuGet,
                ContentHash = contentHash,
                ContentHashAlgorithm = hashAlgorithm
            };
        }
        catch (Exception ex) when (ex is HttpRequestException or JsonException)
        {
            return new ProvenanceResult
            {
                PackageId = packageId,
                Version = version,
                HasRepositorySignature = false,
                HasAuthorSignature = false,
                Ecosystem = PackageEcosystem.NuGet
            };
        }
    }

    /// <summary>
    /// Check provenance for a batch of npm packages.
    /// Uses the npm registry per-version endpoint to check for signatures and attestations.
    /// </summary>
    public async Task<List<ProvenanceResult>> CheckNpmProvenanceAsync(
        IReadOnlyList<(string PackageId, string Version)> packages)
    {
        using var semaphore = new SemaphoreSlim(10);

        var tasks = packages.Select(async pkg =>
        {
            await semaphore.WaitAsync();
            try
            {
                return await CheckSingleNpmPackageAsync(pkg.PackageId, pkg.Version);
            }
            finally
            {
                semaphore.Release();
            }
        });

        var results = await Task.WhenAll(tasks);
        return [.. results];
    }

    private async Task<ProvenanceResult> CheckSingleNpmPackageAsync(string packageId, string version)
    {
        try
        {
            // Scoped packages like @scope/name need URL encoding
            var encodedName = Uri.EscapeDataString(packageId);
            var encodedVersion = Uri.EscapeDataString(version);
            var url = $"https://registry.npmjs.org/{encodedName}/{encodedVersion}";

            using var response = await _httpClient.GetAsync(url);
            if (!response.IsSuccessStatusCode)
            {
                return new ProvenanceResult
                {
                    PackageId = packageId,
                    Version = version,
                    HasRepositorySignature = false,
                    HasAuthorSignature = false,
                    Ecosystem = PackageEcosystem.Npm
                };
            }

            var json = await response.Content.ReadAsStringAsync();
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;

            var hasRepoSignature = false;
            var hasAuthorSignature = false;
            string? contentHash = null;
            string? hashAlgorithm = null;

            // Check dist.signatures — npm ECDSA registry signatures (present since 2022)
            if (root.TryGetProperty("dist", out var dist))
            {
                if (dist.TryGetProperty("signatures", out var signatures) &&
                    signatures.ValueKind == JsonValueKind.Array &&
                    signatures.GetArrayLength() > 0)
                {
                    hasRepoSignature = true;
                }

                // Check dist.attestations — Sigstore provenance from publisher
                if (dist.TryGetProperty("attestations", out var attestations) &&
                    attestations.TryGetProperty("url", out _))
                {
                    hasAuthorSignature = true;
                }

                // Extract content hash from dist.integrity (SRI format: "sha512-...")
                if (dist.TryGetProperty("integrity", out var integrity))
                {
                    var sri = integrity.GetString();
                    if (!string.IsNullOrEmpty(sri))
                    {
                        var dashIndex = sri.IndexOf('-');
                        if (dashIndex > 0)
                        {
                            hashAlgorithm = sri[..dashIndex].ToUpperInvariant();
                            contentHash = sri[(dashIndex + 1)..];
                        }
                    }
                }
            }

            return new ProvenanceResult
            {
                PackageId = packageId,
                Version = version,
                HasRepositorySignature = hasRepoSignature,
                HasAuthorSignature = hasAuthorSignature,
                Ecosystem = PackageEcosystem.Npm,
                ContentHash = contentHash,
                ContentHashAlgorithm = hashAlgorithm
            };
        }
        catch (Exception ex) when (ex is HttpRequestException or JsonException)
        {
            return new ProvenanceResult
            {
                PackageId = packageId,
                Version = version,
                HasRepositorySignature = false,
                HasAuthorSignature = false,
                Ecosystem = PackageEcosystem.Npm
            };
        }
    }

    internal static bool IsAllowedUrl(string url)
    {
        return Uri.TryCreate(url, UriKind.Absolute, out var uri)
            && uri.Scheme == Uri.UriSchemeHttps
            && s_allowedHosts.Contains(uri.Host);
    }

    private static string GetUserAgent()
    {
        var version = typeof(PackageProvenanceChecker).Assembly.GetName().Version;
        var versionString = version is not null ? $"{version.Major}.{version.Minor}" : "1.0";
        return $"DepSafe/{versionString}";
    }

    public void Dispose()
    {
        if (!_disposed)
        {
            if (_ownsHttpClient)
            {
                _httpClient.Dispose();
            }
            _disposed = true;
        }
    }
}
