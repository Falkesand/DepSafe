using System.Net.Http.Json;
using System.Text.Json;

namespace DepSafe.DataSources;

/// <summary>
/// Service to check against CISA's Known Exploited Vulnerabilities (KEV) catalog.
/// CRA Article 10(4) requires no known exploitable vulnerabilities.
/// </summary>
public sealed class CisaKevService : IDisposable
{
    private const string KevUrl = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
    private readonly HttpClient _httpClient;
    private readonly ResponseCache _cache;
    private readonly bool _ownsCache;
    private readonly SemaphoreSlim _loadLock = new(1, 1);
    private HashSet<string>? _kevCves; // Uses OrdinalIgnoreCase comparer

    public CisaKevService(ResponseCache? cache = null)
    {
        _httpClient = new HttpClient(new HttpClientHandler
        {
            AutomaticDecompression = System.Net.DecompressionMethods.GZip | System.Net.DecompressionMethods.Deflate
        })
        { Timeout = TimeSpan.FromSeconds(30) };
        _cache = cache ?? new ResponseCache();
        _ownsCache = cache is null;
    }

    /// <summary>
    /// Load the KEV catalog (cached for 24 hours).
    /// </summary>
    public async Task<Result> LoadCatalogAsync(CancellationToken ct = default)
    {
        if (_kevCves is not null) return Result.Ok();

        await _loadLock.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            if (_kevCves is not null) return Result.Ok(); // double-check after acquiring lock

            var cached = await _cache.GetAsync<HashSet<string>>("cisa:kev", ct).ConfigureAwait(false);
            if (cached is not null)
            {
                _kevCves = cached;
                return Result.Ok();
            }

            try
            {
                using var response = await _httpClient.GetAsync(KevUrl, ct).ConfigureAwait(false);
                if (!response.IsSuccessStatusCode)
                {
                    _kevCves = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                    return Result.Fail($"CISA KEV API returned {(int)response.StatusCode}", ErrorKind.NetworkError);
                }

                var json = await response.Content.ReadFromJsonAsync<JsonElement>(ct).ConfigureAwait(false);
                _kevCves = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

                if (json.TryGetProperty("vulnerabilities", out var vulns))
                {
                    foreach (var vuln in vulns.EnumerateArray())
                    {
                        if (vuln.TryGetProperty("cveID", out var cveId))
                        {
                            var cve = cveId.GetString();
                            if (!string.IsNullOrEmpty(cve))
                            {
                                _kevCves.Add(cve);
                            }
                        }
                    }
                }

                await _cache.SetAsync("cisa:kev", _kevCves, TimeSpan.FromHours(24), ct).ConfigureAwait(false);
                return Result.Ok();
            }
            catch (HttpRequestException ex)
            {
                Console.Error.WriteLine($"[WARN] Failed to fetch CISA KEV catalog: {ex.Message}");
                _kevCves = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                return Result.Fail($"Failed to fetch CISA KEV catalog: {ex.Message}", ErrorKind.NetworkError);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                Console.Error.WriteLine($"[WARN] Failed to fetch CISA KEV catalog: {ex.Message}");
                _kevCves = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                return Result.Fail($"Failed to fetch CISA KEV catalog: {ex.Message}", ErrorKind.Unknown);
            }
        }
        finally
        {
            _loadLock.Release();
        }
    }

    /// <summary>
    /// Check if a CVE is in the KEV catalog (actively exploited).
    /// </summary>
    public bool IsKnownExploited(string cveId)
    {
        if (_kevCves is null || string.IsNullOrEmpty(cveId)) return false;
        return _kevCves.Contains(cveId);
    }

    /// <summary>
    /// Check if any of the given CVEs are in the KEV catalog.
    /// </summary>
    public List<string> GetKnownExploitedCves(IEnumerable<string> cves)
    {
        if (_kevCves is null) return [];
        return cves.Where(cve => _kevCves.Contains(cve)).ToList();
    }

    /// <summary>
    /// Number of CVEs in the KEV catalog.
    /// </summary>
    public int CatalogSize => _kevCves?.Count ?? 0;

    public void Dispose()
    {
        _httpClient.Dispose();
        _loadLock.Dispose();
        if (_ownsCache) _cache.Dispose();
    }
}
