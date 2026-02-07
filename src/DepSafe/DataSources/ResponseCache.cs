using System.Collections.Concurrent;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace DepSafe.DataSources;

/// <summary>
/// Disk-based cache for API responses with in-memory L1 layer.
/// Thread-safe for concurrent access to the same cache keys.
/// </summary>
public sealed class ResponseCache : IDisposable
{
    private readonly string _cacheDir;
    private readonly TimeSpan _defaultTtl;
    private readonly ConcurrentDictionary<string, CacheEntry> _memoryCache = new();
    private readonly SemaphoreSlim[] _stripedLocks = Enumerable.Range(0, 64)
        .Select(_ => new SemaphoreSlim(1, 1)).ToArray();

    public ResponseCache(string? cacheDir = null, TimeSpan? defaultTtl = null)
    {
        _cacheDir = cacheDir ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "DepSafe",
            "cache");
        _defaultTtl = defaultTtl ?? TimeSpan.FromHours(24);

        Directory.CreateDirectory(_cacheDir);
    }

    public async Task<T?> GetAsync<T>(string key, CancellationToken ct = default) where T : class
    {
        // L1: Check in-memory cache first
        if (_memoryCache.TryGetValue(key, out var entry))
        {
            if (DateTime.UtcNow <= entry.Expiry)
                return entry.Value as T;

            _memoryCache.TryRemove(key, out _);
        }

        // L2: Check disk cache with striped locking
        var keyLock = _stripedLocks[(uint)key.GetHashCode() % (uint)_stripedLocks.Length];
        await keyLock.WaitAsync(ct);
        try
        {
            // Double-check memory after acquiring lock (another thread may have populated it)
            if (_memoryCache.TryGetValue(key, out entry) && DateTime.UtcNow <= entry.Expiry)
                return entry.Value as T;

            var path = GetCachePath(key);
            if (!File.Exists(path)) return null;

            var metaPath = path + ".meta";
            if (File.Exists(metaPath))
            {
                var meta = await File.ReadAllTextAsync(metaPath, ct);
                var expiry = DateTime.Parse(meta, CultureInfo.InvariantCulture, System.Globalization.DateTimeStyles.RoundtripKind);
                if (DateTime.UtcNow > expiry)
                {
                    // Cache expired
                    TryDeleteFile(path);
                    TryDeleteFile(metaPath);
                    return null;
                }

                await using var stream = File.OpenRead(path);
                var result = await JsonSerializer.DeserializeAsync<T>(stream, cancellationToken: ct);

                // Promote to L1
                if (result is not null)
                    _memoryCache[key] = new CacheEntry(result, expiry);

                return result;
            }

            return null;
        }
        catch (Exception ex) when (ex is IOException or JsonException or FormatException)
        {
            return null;
        }
        finally
        {
            keyLock.Release();
        }
    }

    public async Task SetAsync<T>(string key, T value, TimeSpan? ttl = null, CancellationToken ct = default)
    {
        var expiry = DateTime.UtcNow.Add(ttl ?? _defaultTtl);

        // Always update L1 immediately
        _memoryCache[key] = new CacheEntry(value!, expiry);

        // Write to L2 (disk) with striped locking
        var keyLock = _stripedLocks[(uint)key.GetHashCode() % (uint)_stripedLocks.Length];
        await keyLock.WaitAsync(ct);
        try
        {
            var path = GetCachePath(key);
            var metaPath = path + ".meta";

            await using var stream = File.Create(path);
            await JsonSerializer.SerializeAsync(stream, value, cancellationToken: ct);
            await File.WriteAllTextAsync(metaPath, expiry.ToString("O"), ct);
        }
        catch (Exception ex) when (ex is IOException or JsonException)
        {
            // Ignore cache write failures — L1 still holds the value
        }
        finally
        {
            keyLock.Release();
        }
    }

    public void Clear()
    {
        _memoryCache.Clear();

        if (Directory.Exists(_cacheDir))
        {
            foreach (var file in Directory.GetFiles(_cacheDir))
            {
                TryDeleteFile(file);
            }
        }
    }

    /// <summary>
    /// Remove expired cache files from disk.
    /// </summary>
    public void CleanupExpired()
    {
        if (!Directory.Exists(_cacheDir))
            return;

        foreach (var file in Directory.GetFiles(_cacheDir))
        {
            // Skip meta files - we check them with their parent
            if (file.EndsWith(".meta", StringComparison.OrdinalIgnoreCase))
                continue;

            try
            {
                var metaPath = file + ".meta";
                if (File.Exists(metaPath))
                {
                    var meta = File.ReadAllText(metaPath);
                    if (DateTime.TryParse(meta, CultureInfo.InvariantCulture, DateTimeStyles.None, out var expiry) && DateTime.UtcNow > expiry)
                    {
                        TryDeleteFile(file);
                        TryDeleteFile(metaPath);
                    }
                }
                else
                {
                    // Cache file without meta - delete orphan
                    TryDeleteFile(file);
                }
            }
            catch
            {
                // Ignore cleanup failures
            }
        }
    }

    private string GetCachePath(string key)
    {
        // Use stackalloc to avoid heap allocation for small keys
        var maxByteCount = Encoding.UTF8.GetMaxByteCount(key.Length);
        Span<byte> keyBytes = maxByteCount <= 256
            ? stackalloc byte[maxByteCount]
            : new byte[maxByteCount];

        var actualByteCount = Encoding.UTF8.GetBytes(key.AsSpan(), keyBytes);

        Span<byte> hashBytes = stackalloc byte[32]; // SHA256 = 32 bytes
        SHA256.HashData(keyBytes[..actualByteCount], hashBytes);

        return Path.Combine(_cacheDir, Convert.ToHexString(hashBytes[..16]));
    }

    private static void TryDeleteFile(string path)
    {
        try { File.Delete(path); } catch { }
    }

    public void Dispose()
    {
        foreach (var l in _stripedLocks)
            l.Dispose();
    }

    private sealed record CacheEntry(object Value, DateTime Expiry);
}
