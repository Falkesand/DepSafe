using System.Reflection;
using System.Text.Json;
using DepSafe.DataSources;
using DepSafe.Models;

namespace DepSafe.Typosquatting;

/// <summary>
/// Provides popular package lists from embedded seed data and optional online refresh.
/// Embedded data works offline; online refresh caches for 7 days.
/// </summary>
public sealed class PopularPackageProvider : IDisposable
{
    private readonly HttpClient _httpClient;
    private readonly ResponseCache _cache;
    private readonly bool _ownsCache;
    private readonly bool _offlineOnly;

    private const string NuGetSearchUrl = "https://azuresearch-usnc.nuget.org/query?q=&take=100&sortBy=totalDownloads-desc&prerelease=false";
    private const string NpmRegistryUrl = "https://registry.npmjs.org/-/v1/search?text=&popularity=1.0&size=250";

    public PopularPackageProvider(bool offlineOnly = false, ResponseCache? cache = null)
    {
        _offlineOnly = offlineOnly;
        _httpClient = new HttpClient { Timeout = TimeSpan.FromSeconds(30) };
        _cache = cache ?? new ResponseCache();
        _ownsCache = cache is null;
    }

    /// <summary>
    /// Load popular packages into the index, combining embedded data with optional online refresh.
    /// </summary>
    public async Task<PopularPackageIndex> LoadAsync(CancellationToken ct = default)
    {
        var index = new PopularPackageIndex();

        // Always load embedded seed data first (works offline)
        var embeddedNuGet = LoadEmbeddedData("nuget-popular.json", PackageEcosystem.NuGet);
        var embeddedNpm = LoadEmbeddedData("npm-popular.json", PackageEcosystem.Npm);

        index.AddRange(embeddedNuGet);
        index.AddRange(embeddedNpm);

        // Online refresh if not offline-only
        if (!_offlineOnly)
        {
            var onlineNuGet = await FetchOnlineNuGetAsync(ct).ConfigureAwait(false);
            var onlineNpm = await FetchOnlineNpmAsync(ct).ConfigureAwait(false);

            index.AddRange(onlineNuGet);
            index.AddRange(onlineNpm);
        }

        index.Freeze();
        return index;
    }

    private static List<PopularPackageEntry> LoadEmbeddedData(string resourceName, PackageEcosystem ecosystem)
    {
        var assembly = Assembly.GetExecutingAssembly();
        var fullName = assembly.GetManifestResourceNames()
            .FirstOrDefault(n => n.EndsWith(resourceName, StringComparison.OrdinalIgnoreCase));

        if (fullName is null)
            return [];

        try
        {
            using var stream = assembly.GetManifestResourceStream(fullName);
            if (stream is null) return [];

            var entries = JsonSerializer.Deserialize<List<EmbeddedPackageEntry>>(stream);
            if (entries is null) return [];

            return entries
                .Where(e => !string.IsNullOrWhiteSpace(e.Name))
                .Select(e =>
                {
                    var name = e.Name!;
                    var normalized = name.ToLowerInvariant();
                    return new PopularPackageEntry
                    {
                        Name = name,
                        NormalizedName = normalized,
                        HomoglyphNormalizedName = StringDistance.NormalizeHomoglyphs(normalized),
                        Downloads = e.Downloads,
                        Ecosystem = ecosystem
                    };
                })
                .ToList();
        }
        catch (JsonException)
        {
            return [];
        }
    }

    private async Task<List<PopularPackageEntry>> FetchOnlineNuGetAsync(CancellationToken ct)
    {
        var cached = await _cache.GetAsync<List<PopularPackageEntry>>("typosquat:nuget-popular", ct).ConfigureAwait(false);
        if (cached is not null) return cached;

        try
        {
            var response = await _httpClient.GetAsync(NuGetSearchUrl, ct).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode) return [];

            var json = await response.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
            var doc = JsonSerializer.Deserialize<JsonElement>(json);

            var entries = new List<PopularPackageEntry>();
            if (doc.TryGetProperty("data", out var data))
            {
                foreach (var item in data.EnumerateArray())
                {
                    var id = item.TryGetProperty("id", out var idEl) ? idEl.GetString() : null;
                    var downloads = item.TryGetProperty("totalDownloads", out var dlEl) ? dlEl.GetInt64() : 0;

                    if (!string.IsNullOrEmpty(id))
                    {
                        entries.Add(new PopularPackageEntry
                        {
                            Name = id,
                            Downloads = downloads,
                            Ecosystem = PackageEcosystem.NuGet
                        });
                    }
                }
            }

            if (entries.Count > 0)
                await _cache.SetAsync("typosquat:nuget-popular", entries, TimeSpan.FromDays(7), ct).ConfigureAwait(false);

            return entries;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[WARN] Failed to fetch online NuGet popular packages: {ex.Message}");
            return [];
        }
    }

    private async Task<List<PopularPackageEntry>> FetchOnlineNpmAsync(CancellationToken ct)
    {
        var cached = await _cache.GetAsync<List<PopularPackageEntry>>("typosquat:npm-popular", ct).ConfigureAwait(false);
        if (cached is not null) return cached;

        try
        {
            var response = await _httpClient.GetAsync(NpmRegistryUrl, ct).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode) return [];

            var json = await response.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
            var doc = JsonSerializer.Deserialize<JsonElement>(json);

            var entries = new List<PopularPackageEntry>();
            if (doc.TryGetProperty("objects", out var objects))
            {
                foreach (var item in objects.EnumerateArray())
                {
                    if (!item.TryGetProperty("package", out var pkg)) continue;

                    var name = pkg.TryGetProperty("name", out var nameEl) ? nameEl.GetString() : null;

                    if (!string.IsNullOrEmpty(name))
                    {
                        entries.Add(new PopularPackageEntry
                        {
                            Name = name,
                            Downloads = 0, // npm search doesn't provide download counts directly
                            Ecosystem = PackageEcosystem.Npm
                        });
                    }
                }
            }

            if (entries.Count > 0)
                await _cache.SetAsync("typosquat:npm-popular", entries, TimeSpan.FromDays(7), ct).ConfigureAwait(false);

            return entries;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[WARN] Failed to fetch online npm popular packages: {ex.Message}");
            return [];
        }
    }

    public void Dispose()
    {
        _httpClient.Dispose();
        if (_ownsCache) _cache.Dispose();
    }

    /// <summary>Internal model for JSON deserialization of embedded data.</summary>
    private sealed class EmbeddedPackageEntry
    {
        public string? Name { get; set; }
        public long Downloads { get; set; }
    }
}
