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

    public EpssService(ResponseCache? cache = null)
    {
        _httpClient = new HttpClient { Timeout = TimeSpan.FromSeconds(30) };
        _cache = cache ?? new ResponseCache();
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
            .Select(c => c.Trim().ToUpperInvariant())
            .Distinct()
            .ToList();

        if (uniqueCves.Count == 0)
            return [];

        var result = new Dictionary<string, EpssScore>(StringComparer.OrdinalIgnoreCase);

        // Check cache first, collect uncached CVEs
        var uncached = new List<string>();
        foreach (var cve in uniqueCves)
        {
            var cached = await _cache.GetAsync<EpssScore>($"epss:{cve}", ct);
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
            var scores = await FetchBatchAsync(batch, ct);
            foreach (var score in scores)
            {
                result[score.Cve] = score;
                await _cache.SetAsync($"epss:{score.Cve}", score, TimeSpan.FromHours(24), ct);
            }

            // Cache misses as zero scores so we don't re-fetch
            foreach (var cve in batch)
            {
                if (!result.ContainsKey(cve))
                {
                    var missing = new EpssScore { Cve = cve, Probability = 0, Percentile = 0 };
                    result[cve] = missing;
                    await _cache.SetAsync($"epss:{cve}", missing, TimeSpan.FromHours(24), ct);
                }
            }
        }

        return result;
    }

    private async Task<List<EpssScore>> FetchBatchAsync(
        List<string> cveIds, CancellationToken ct)
    {
        try
        {
            var cveParam = string.Join(",", cveIds);
            var url = $"{EpssApiUrl}?cve={Uri.EscapeDataString(cveParam)}";

            var response = await _httpClient.GetAsync(url, ct);
            if (!response.IsSuccessStatusCode)
            {
                Console.Error.WriteLine($"[WARN] EPSS API returned {(int)response.StatusCode} for batch of {cveIds.Count} CVEs");
                return [];
            }

            var json = await response.Content.ReadFromJsonAsync<JsonElement>(ct);
            return ParseResponse(json);
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[WARN] Failed to fetch EPSS scores: {ex.Message}");
            return [];
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
                Cve = cve.ToUpperInvariant(),
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
    }
}

/// <summary>
/// EPSS score for a single CVE.
/// </summary>
public sealed class EpssScore
{
    /// <summary>CVE identifier (e.g., CVE-2021-44228).</summary>
    public required string Cve { get; init; }

    /// <summary>Probability of exploitation in the next 30 days (0.0-1.0).</summary>
    public required double Probability { get; init; }

    /// <summary>Percentile ranking relative to all scored CVEs (0.0-1.0).</summary>
    public required double Percentile { get; init; }
}
