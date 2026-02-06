using System.Collections.Frozen;
using DepSafe.Models;

namespace DepSafe.Typosquatting;

/// <summary>
/// Length-bucketed index for fast similarity search against popular packages.
/// Only compares packages within +/-2 characters of each other, eliminating ~80% of comparisons.
/// Call <see cref="Freeze"/> after all entries are added to optimize read performance.
/// </summary>
public sealed class PopularPackageIndex
{
    private readonly Dictionary<int, List<PopularPackageEntry>> _buckets = [];
    private readonly HashSet<string> _allNames = new(StringComparer.OrdinalIgnoreCase);
    private const int LengthTolerance = 2;

    private FrozenDictionary<int, List<PopularPackageEntry>>? _frozenBuckets;
    private FrozenSet<string>? _frozenNames;

    /// <summary>
    /// Add a popular package entry to the index.
    /// </summary>
    public void Add(PopularPackageEntry entry)
    {
        if (!_allNames.Add(entry.Name))
            return;

        // Ensure NormalizedName and HomoglyphNormalizedName are set
        var normalized = string.IsNullOrEmpty(entry.NormalizedName)
            ? entry.Name.ToLowerInvariant()
            : entry.NormalizedName;

        if (string.IsNullOrEmpty(entry.NormalizedName) || string.IsNullOrEmpty(entry.HomoglyphNormalizedName))
        {
            entry = new PopularPackageEntry
            {
                Name = entry.Name,
                NormalizedName = normalized,
                HomoglyphNormalizedName = StringDistance.NormalizeHomoglyphs(normalized),
                Downloads = entry.Downloads,
                Ecosystem = entry.Ecosystem
            };
        }

        var len = entry.Name.Length;

        if (!_buckets.TryGetValue(len, out var bucket))
        {
            bucket = [];
            _buckets[len] = bucket;
        }

        bucket.Add(entry);
    }

    /// <summary>
    /// Add multiple entries to the index.
    /// </summary>
    public void AddRange(IEnumerable<PopularPackageEntry> entries)
    {
        foreach (var entry in entries)
            Add(entry);
    }

    /// <summary>
    /// Freeze the index for optimal read performance. Call after all entries have been added.
    /// </summary>
    public void Freeze()
    {
        _frozenBuckets = _buckets.ToFrozenDictionary();
        _frozenNames = _allNames.ToFrozenSet(StringComparer.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Check if a package name is already in the popular index (exact, case-insensitive).
    /// </summary>
    public bool Contains(string packageName) =>
        _frozenNames?.Contains(packageName) ?? _allNames.Contains(packageName);

    /// <summary>
    /// Find popular packages similar to the candidate within length tolerance.
    /// Returns entries from buckets within +/-LengthTolerance of the candidate length.
    /// </summary>
    public IEnumerable<PopularPackageEntry> FindCandidates(string packageName)
    {
        var targetLen = packageName.Length;
        var buckets = (IReadOnlyDictionary<int, List<PopularPackageEntry>>?)_frozenBuckets ?? _buckets;

        for (var len = targetLen - LengthTolerance; len <= targetLen + LengthTolerance; len++)
        {
            if (buckets.TryGetValue(len, out var bucket))
            {
                foreach (var entry in bucket)
                {
                    yield return entry;
                }
            }
        }
    }

    /// <summary>
    /// All entries across all buckets.
    /// </summary>
    public IEnumerable<PopularPackageEntry> AllEntries =>
        ((IReadOnlyDictionary<int, List<PopularPackageEntry>>?)_frozenBuckets ?? _buckets)
            .Values.SelectMany(b => b);

    /// <summary>
    /// Total number of entries in the index.
    /// </summary>
    public int Count => _frozenNames?.Count ?? _allNames.Count;
}
