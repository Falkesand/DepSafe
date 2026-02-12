using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using DepSafe.Models;

namespace DepSafe.Persistence;

public sealed class TrendSnapshotStore
{
    private readonly string _basePath;

    public TrendSnapshotStore(string? basePath = null)
    {
        _basePath = basePath ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "DepSafe",
            "snapshots");
    }

    public async Task SaveAsync(TrendSnapshot snapshot, CancellationToken ct = default)
    {
        var projectDir = GetProjectDirectory(snapshot.ProjectPath);
        Directory.CreateDirectory(projectDir);

        var fileName = snapshot.CapturedAt.ToString("yyyy-MM-ddTHHmmssZ") + ".json";
        var filePath = Path.Combine(projectDir, fileName);

        var json = JsonSerializer.Serialize(snapshot, JsonDefaults.CamelCase);
        await File.WriteAllTextAsync(filePath, json, ct);
    }

    public async Task<List<TrendSnapshot>> LoadAsync(string projectPath, int? maxCount = null, CancellationToken ct = default)
    {
        var projectDir = GetProjectDirectory(projectPath);
        if (!Directory.Exists(projectDir))
            return [];

        var files = Directory.GetFiles(projectDir, "*.json");
        Array.Sort(files, StringComparer.Ordinal); // Lexicographic = chronological

        var snapshots = new List<TrendSnapshot>(files.Length);
        foreach (var file in files)
        {
            try
            {
                var json = await File.ReadAllTextAsync(file, ct);
                var snapshot = JsonSerializer.Deserialize<TrendSnapshot>(json, JsonDefaults.CamelCase);
                if (snapshot is not null)
                    snapshots.Add(snapshot);
            }
            catch (JsonException)
            {
                // Skip corrupted files - warn on stderr
                await Console.Error.WriteLineAsync($"Warning: Skipping corrupted snapshot file: {Path.GetFileName(file)}");
            }
        }

        if (maxCount.HasValue && snapshots.Count > maxCount.Value)
        {
            return snapshots.GetRange(snapshots.Count - maxCount.Value, maxCount.Value);
        }

        return snapshots;
    }

    public static string GetProjectHash(string projectPath)
    {
        var normalized = projectPath.Replace('\\', '/').TrimEnd('/').ToLowerInvariant();
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(normalized));
        return Convert.ToHexString(hash)[..12].ToLowerInvariant();
    }

    private string GetProjectDirectory(string projectPath)
    {
        return Path.Combine(_basePath, GetProjectHash(projectPath));
    }
}
