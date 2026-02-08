using System.Net.Http.Json;
using System.Text.Json;

namespace DepSafe.DataSources;

/// <summary>
/// Service to fetch FIRST EPSS (Exploit Prediction Scoring System) scores.
/// EPSS provides the probability that a CVE will be exploited in the next 30 days.
/// CRA compliance: helps prioritize vulnerability remediation by real-world exploit risk.
/// </summary>
public sealed class EpssService : IDisposable
{
    private const string EpssApiUrl = "https://api.first.org/data/v1/epss";
    private const int BatchSize = 100; // Keep URLs under ~4000 chars
    private readonly HttpClient _httpClient;
    private readonly ResponseCache _cache;
    private readonly bool _ownsCache;

    public EpssService(ResponseCache? cache = null)
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
    /// Get EPSS scores for a collection of CVE IDs (batched, cached 24h).
    /// Returns a dictionary of CVE ID → EpssScore.
    /// </summary>
    public async Task<Dictionary<string, EpssScore>> GetScoresAsync(
        IEnumerable<string> cveIds, CancellationToken ct = default)
    {
        var uniqueCves = cveIds
            .Where(c => !string.IsNullOrWhiteSpace(c))
            .Select(c => c.Trim())
            .Distinct()
            .ToList();

        if (uniqueCves.Count == 0)
            return [];

        var result = new Dictionary<string, EpssScore>(uniqueCves.Count, StringComparer.OrdinalIgnoreCase);

        // Check cache first, collect uncached CVEs
        var uncached = new List<string>(uniqueCves.Count);
        foreach (var cve in uniqueCves)
        {
            var cached = await _cache.GetAsync<EpssScore>($"epss:{cve}", ct).ConfigureAwait(false);
            if (cached is not null)
            {
                result[cve] = cached;
            }
            else
            {
                uncached.Add(cve);
            }
        }

        if (uncached.Count == 0)
            return result;

        // Fetch uncached CVEs in batches
        foreach (var batch in Batch(uncached, BatchSize))
        {
            var fetchResult = await FetchBatchAsync(batch, ct).ConfigureAwait(false);
            foreach (var score in fetchResult.ValueOr([]))
            {
                result[score.Cve] = score;
                await _cache.SetAsync($"epss:{score.Cve}", score, TimeSpan.FromHours(24), ct).ConfigureAwait(false);
            }

            // Cache misses as zero scores so we don't re-fetch
            foreach (var cve in batch)
            {
                var missing = new EpssScore { Cve = cve, Probability = 0, Percentile = 0 };
                if (result.TryAdd(cve, missing))
                {
                    await _cache.SetAsync($"epss:{cve}", missing, TimeSpan.FromHours(24), ct).ConfigureAwait(false);
                }
            }
        }

        return result;
    }

    private async Task<Result<List<EpssScore>>> FetchBatchAsync(
        List<string> cveIds, CancellationToken ct)
    {
        try
        {
            var cveParam = string.Join(",", cveIds);
            var url = $"{EpssApiUrl}?cve={Uri.EscapeDataString(cveParam)}";

            using var response = await _httpClient.GetAsync(url, ct).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode)
            {
                Console.Error.WriteLine($"[WARN] EPSS API returned {(int)response.StatusCode} for batch of {cveIds.Count} CVEs");
                return Result.Fail<List<EpssScore>>(
                    $"EPSS API returned {(int)response.StatusCode} for batch of {cveIds.Count} CVEs", ErrorKind.NetworkError);
            }

            var json = await response.Content.ReadFromJsonAsync<JsonElement>(ct).ConfigureAwait(false);
            return ParseResponse(json);
        }
        catch (HttpRequestException ex)
        {
            Console.Error.WriteLine($"[WARN] Failed to fetch EPSS scores: {ex.Message}");
            return Result.Fail<List<EpssScore>>($"Failed to fetch EPSS scores: {ex.Message}", ErrorKind.NetworkError);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            Console.Error.WriteLine($"[WARN] Failed to fetch EPSS scores: {ex.Message}");
            return Result.Fail<List<EpssScore>>($"Failed to fetch EPSS scores: {ex.Message}", ErrorKind.Unknown);
        }
    }

    /// <summary>
    /// Parse EPSS API response JSON into EpssScore objects.
    /// </summary>
    public static List<EpssScore> ParseResponse(JsonElement json)
    {
        var scores = new List<EpssScore>();

        if (!json.TryGetProperty("data", out var dataArray))
            return scores;

        foreach (var item in dataArray.EnumerateArray())
        {
            var cve = item.TryGetProperty("cve", out var cveEl) ? cveEl.GetString() : null;
            if (string.IsNullOrEmpty(cve))
                continue;

            var probability = ParseDouble(item, "epss");
            var percentile = ParseDouble(item, "percentile");

            scores.Add(new EpssScore
            {
                Cve = cve,
                Probability = probability,
                Percentile = percentile
            });
        }

        return scores;
    }

    private static double ParseDouble(JsonElement element, string property)
    {
        if (!element.TryGetProperty(property, out var prop))
            return 0;

        // EPSS API returns numbers as strings
        if (prop.ValueKind == JsonValueKind.String)
        {
            return double.TryParse(prop.GetString(), System.Globalization.NumberStyles.Float,
                System.Globalization.CultureInfo.InvariantCulture, out var val) ? val : 0;
        }

        if (prop.ValueKind == JsonValueKind.Number)
        {
            return prop.GetDouble();
        }

        return 0;
    }

    private static IEnumerable<List<string>> Batch(List<string> source, int batchSize)
    {
        for (var i = 0; i < source.Count; i += batchSize)
        {
            yield return source.GetRange(i, Math.Min(batchSize, source.Count - i));
        }
    }

    public void Dispose()
    {
        _httpClient.Dispose();
        if (_ownsCache) _cache.Dispose();
    }
}
