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
    private HashSet<string>? _kevCves; // Uses OrdinalIgnoreCase comparer

    public CisaKevService(ResponseCache? cache = null)
    {
        _httpClient = new HttpClient(new HttpClientHandler
        {
            AutomaticDecompression = System.Net.DecompressionMethods.GZip | System.Net.DecompressionMethods.Deflate
        })
        { Timeout = TimeSpan.FromSeconds(30) };
        _cache = cache ?? new ResponseCache();
    }

    /// <summary>
    /// Load the KEV catalog (cached for 24 hours).
    /// </summary>
    public async Task LoadCatalogAsync(CancellationToken ct = default)
    {
        if (_kevCves is not null) return;

        var cached = await _cache.GetAsync<HashSet<string>>("cisa:kev", ct);
        if (cached is not null)
        {
            _kevCves = cached;
            return;
        }

        try
        {
            using var response = await _httpClient.GetAsync(KevUrl, ct);
            if (!response.IsSuccessStatusCode)
            {
                _kevCves = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                return;
            }

            var json = await response.Content.ReadFromJsonAsync<JsonElement>(ct);
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

            await _cache.SetAsync("cisa:kev", _kevCves, TimeSpan.FromHours(24), ct);
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[WARN] Failed to fetch CISA KEV catalog: {ex.Message}");
            _kevCves = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
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
    }
}
