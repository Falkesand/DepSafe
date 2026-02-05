using System.Net;
using System.Text.Json;
using DepSafe.Models;

namespace DepSafe.Compliance;

/// <summary>
/// Checks NuGet package signing/provenance per CRA Art. 13(5).
/// v1.2 scope: NuGet repository signatures only. npm provenance in v1.3.
/// </summary>
public sealed class PackageProvenanceChecker : IDisposable
{
    private readonly HttpClient _httpClient;
    private bool _disposed;

    public PackageProvenanceChecker(HttpClient? httpClient = null)
    {
        if (httpClient is not null)
        {
            _httpClient = httpClient;
        }
        else
        {
            var handler = new HttpClientHandler
            {
                AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate
            };
            _httpClient = new HttpClient(handler);
        }
        _httpClient.DefaultRequestHeaders.UserAgent.TryParseAdd("DepSafe/1.2");
    }

    /// <summary>
    /// Check provenance for a batch of NuGet packages.
    /// Uses the NuGet V3 registration API to check for signature info.
    /// </summary>
    public async Task<List<ProvenanceResult>> CheckNuGetProvenanceAsync(
        IReadOnlyList<(string PackageId, string Version)> packages)
    {
        var results = new List<ProvenanceResult>();
        var semaphore = new SemaphoreSlim(5);

        var tasks = packages.Select(async pkg =>
        {
            await semaphore.WaitAsync();
            try
            {
                var result = await CheckSingleNuGetPackageAsync(pkg.PackageId, pkg.Version);
                lock (results)
                {
                    results.Add(result);
                }
            }
            finally
            {
                semaphore.Release();
            }
        });

        await Task.WhenAll(tasks);
        return results;
    }

    private async Task<ProvenanceResult> CheckSingleNuGetPackageAsync(string packageId, string version)
    {
        try
        {
            // NuGet.org signs all packages with a repository signature
            // Check the registration endpoint for signature metadata
            var url = $"https://api.nuget.org/v3/registration5-gz-semver2/{packageId.ToLowerInvariant()}/{version.ToLowerInvariant()}.json";

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
            var doc = JsonDocument.Parse(json);
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
                    if (!string.IsNullOrEmpty(catalogUrl))
                    {
                        using var catalogResponse = await _httpClient.GetAsync(catalogUrl);
                        if (catalogResponse.IsSuccessStatusCode)
                        {
                            var catalogJson = await catalogResponse.Content.ReadAsStringAsync();
                            var catalogDoc = JsonDocument.Parse(catalogJson);
                            if (catalogDoc.RootElement.TryGetProperty("packageHash", out var hashProp))
                            {
                                contentHash = hashProp.GetString();
                                hashAlgorithm = catalogDoc.RootElement.TryGetProperty("packageHashAlgorithm", out var algProp)
                                    ? algProp.GetString() : "SHA512";
                            }
                        }
                    }
                }
                catch { /* Non-critical — checksum is best-effort */ }
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
        catch
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

    public void Dispose()
    {
        if (!_disposed)
        {
            _httpClient.Dispose();
            _disposed = true;
        }
    }
}
