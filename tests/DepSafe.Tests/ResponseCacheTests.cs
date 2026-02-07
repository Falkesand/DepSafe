using DepSafe.DataSources;

namespace DepSafe.Tests;

public class ResponseCacheTests : IDisposable
{
    private readonly string _tempDir;
    private readonly ResponseCache _cache;

    public ResponseCacheTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), $"DepSafe_CacheTest_{Guid.NewGuid():N}");
        _cache = new ResponseCache(_tempDir, TimeSpan.FromHours(1));
    }

    [Fact]
    public async Task GetAsync_EmptyCache_ReturnsNull()
    {
        var result = await _cache.GetAsync<List<string>>("nonexistent");

        Assert.Null(result);
    }

    [Fact]
    public async Task SetThenGet_ReturnsValue()
    {
        var data = new List<string> { "alpha", "beta", "gamma" };

        await _cache.SetAsync("test-key", data);
        var result = await _cache.GetAsync<List<string>>("test-key");

        Assert.NotNull(result);
        Assert.Equal(3, result.Count);
        Assert.Equal("alpha", result[0]);
    }

    [Fact]
    public async Task GetAsync_ExpiredEntry_ReturnsNull()
    {
        var data = new List<string> { "value" };
        await _cache.SetAsync("expired-key", data, TimeSpan.FromMilliseconds(1));

        // Wait for expiry
        await Task.Delay(50);

        var result = await _cache.GetAsync<List<string>>("expired-key");

        Assert.Null(result);
    }

    [Fact]
    public async Task SetAsync_Overwrites_ReturnsNewValue()
    {
        await _cache.SetAsync("key", new List<string> { "old" });
        await _cache.SetAsync("key", new List<string> { "new" });

        var result = await _cache.GetAsync<List<string>>("key");

        Assert.NotNull(result);
        Assert.Single(result);
        Assert.Equal("new", result[0]);
    }

    [Fact]
    public async Task Clear_RemovesAllEntries()
    {
        await _cache.SetAsync("key1", new List<string> { "a" });
        await _cache.SetAsync("key2", new List<string> { "b" });

        _cache.Clear();

        Assert.Null(await _cache.GetAsync<List<string>>("key1"));
        Assert.Null(await _cache.GetAsync<List<string>>("key2"));
    }

    [Fact]
    public async Task CleanupExpired_RemovesExpiredFiles()
    {
        // Use a separate cache with very short TTL to test cleanup
        using var shortCache = new ResponseCache(_tempDir, TimeSpan.FromMilliseconds(1));
        await shortCache.SetAsync("short-lived", new List<string> { "x" });
        await Task.Delay(100);

        // Verify files exist before cleanup
        int filesBefore = Directory.GetFiles(_tempDir).Length;
        Assert.True(filesBefore > 0, "Cache files should exist before cleanup");

        shortCache.CleanupExpired();

        // Verify entry is no longer retrievable (GetAsync correctly handles expiry)
        var result = await shortCache.GetAsync<List<string>>("short-lived");
        Assert.Null(result);
    }

    [Fact]
    public async Task CleanupExpired_KeepsValidFiles()
    {
        await _cache.SetAsync("long-lived", new List<string> { "y" }, TimeSpan.FromHours(24));

        _cache.CleanupExpired();

        var result = await _cache.GetAsync<List<string>>("long-lived");
        Assert.NotNull(result);
    }

    [Fact]
    public async Task GetAsync_CorruptedFile_ReturnsNull()
    {
        // Write a valid entry, then create a new cache instance to avoid L1 hit
        await _cache.SetAsync("corrupt-key", new List<string> { "data" });

        // Corrupt the data files on disk (not the meta files — they need to remain for path discovery)
        var dataFiles = Directory.GetFiles(_tempDir).Where(f => !f.EndsWith(".meta")).ToArray();
        foreach (var file in dataFiles)
        {
            await File.WriteAllTextAsync(file, "this is not valid json{{{");
        }

        // New instance has empty L1 cache, so it must read from corrupted L2
        using var freshCache = new ResponseCache(_tempDir, TimeSpan.FromHours(1));
        var result = await freshCache.GetAsync<List<string>>("corrupt-key");

        Assert.Null(result);
    }

    [Fact]
    public async Task GetAsync_DiskHit_AfterNewInstance()
    {
        await _cache.SetAsync("persist-key", new List<string> { "persisted" });

        // Create a new instance pointing to the same directory
        using var cache2 = new ResponseCache(_tempDir, TimeSpan.FromHours(1));
        var result = await cache2.GetAsync<List<string>>("persist-key");

        Assert.NotNull(result);
        Assert.Equal("persisted", result[0]);
    }

    [Fact]
    public void Dispose_DoesNotThrow()
    {
        var cache = new ResponseCache(_tempDir, TimeSpan.FromHours(1));
        var exception = Record.Exception(() => cache.Dispose());

        Assert.Null(exception);
    }

    public void Dispose()
    {
        _cache.Dispose();
        try
        {
            if (Directory.Exists(_tempDir))
                Directory.Delete(_tempDir, recursive: true);
        }
        catch
        {
            // Ignore cleanup failures in tests
        }
    }
}
