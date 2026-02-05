using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace DepSafe.DataSources;

/// <summary>
/// Simple disk-based cache for API responses.
/// </summary>
public sealed class ResponseCache
{
    private readonly string _cacheDir;
    private readonly TimeSpan _defaultTtl;

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
        var path = GetCachePath(key);
        if (!File.Exists(path)) return null;

        try
        {
            var metaPath = path + ".meta";
            if (File.Exists(metaPath))
            {
                var meta = await File.ReadAllTextAsync(metaPath, ct);
                var expiry = DateTime.Parse(meta);
                if (DateTime.UtcNow > expiry)
                {
                    // Cache expired
                    File.Delete(path);
                    File.Delete(metaPath);
                    return null;
                }
            }

            var json = await File.ReadAllTextAsync(path, ct);
            return JsonSerializer.Deserialize<T>(json);
        }
        catch
        {
            return null;
        }
    }

    public async Task SetAsync<T>(string key, T value, TimeSpan? ttl = null, CancellationToken ct = default)
    {
        var path = GetCachePath(key);
        var metaPath = path + ".meta";
        var expiry = DateTime.UtcNow.Add(ttl ?? _defaultTtl);

        try
        {
            var json = JsonSerializer.Serialize(value, new JsonSerializerOptions { WriteIndented = false });
            await File.WriteAllTextAsync(path, json, ct);
            await File.WriteAllTextAsync(metaPath, expiry.ToString("O"), ct);
        }
        catch
        {
            // Ignore cache write failures
        }
    }

    public void Clear()
    {
        if (Directory.Exists(_cacheDir))
        {
            foreach (var file in Directory.GetFiles(_cacheDir))
            {
                try { File.Delete(file); } catch { }
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

        return Path.Combine(_cacheDir, Convert.ToHexString(hashBytes)[..16]);
    }
}
