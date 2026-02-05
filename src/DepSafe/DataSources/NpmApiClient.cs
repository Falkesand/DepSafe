using System.Collections.Concurrent;
using System.Net;
using System.Text.Json;
using System.Text.Json.Nodes;
using DepSafe.Models;

namespace DepSafe.DataSources;

/// <summary>
/// Client for npm registry API.
/// </summary>
public sealed class NpmApiClient : IDisposable
{
    private readonly HttpClient _httpClient;
    private readonly ResponseCache _cache;
    private const string NpmRegistryUrl = "https://registry.npmjs.org";
    private const string NpmDownloadsUrl = "https://api.npmjs.org/downloads/point/last-week";

    public NpmApiClient(ResponseCache? cache = null)
    {
        _httpClient = new HttpClient
        {
            Timeout = TimeSpan.FromSeconds(30)
        };
        _httpClient.DefaultRequestHeaders.Add("Accept", "application/json");
        _cache = cache ?? new ResponseCache();
    }

    /// <summary>
    /// Get package information from npm registry.
    /// </summary>
    public async Task<NpmPackageInfo?> GetPackageInfoAsync(string packageName, CancellationToken ct = default)
    {
        var cacheKey = $"npm:{packageName}";
        var cached = await _cache.GetAsync<NpmPackageInfo>(cacheKey, ct);
        if (cached is not null) return cached;

        try
        {
            // URL encode package name (handles scoped packages like @org/package)
            var encodedName = Uri.EscapeDataString(packageName);
            var response = await _httpClient.GetAsync($"{NpmRegistryUrl}/{encodedName}", ct);

            if (response.StatusCode == HttpStatusCode.NotFound)
            {
                return null;
            }

            response.EnsureSuccessStatusCode();
            // Parse directly from stream to avoid large string allocation
            using var stream = await response.Content.ReadAsStreamAsync(ct);
            var doc = await JsonNode.ParseAsync(stream, cancellationToken: ct);

            if (doc is null) return null;

            var distTags = doc["dist-tags"]?.AsObject();
            var latestVersion = distTags?["latest"]?.GetValue<string>() ?? "";

            var timeObj = doc["time"]?.AsObject();
            var versions = new List<NpmVersionInfo>();

            if (timeObj is not null)
            {
                foreach (var prop in timeObj)
                {
                    if (prop.Key == "created" || prop.Key == "modified") continue;

                    if (DateTime.TryParse(prop.Value?.GetValue<string>(), out var publishedDate))
                    {
                        var versionNode = doc["versions"]?[prop.Key];
                        var deprecated = versionNode?["deprecated"] is not null;

                        versions.Add(new NpmVersionInfo
                        {
                            Version = prop.Key,
                            PublishedDate = publishedDate,
                            IsDeprecated = deprecated
                        });
                    }
                }
            }

            versions = versions.OrderByDescending(v => v.PublishedDate).ToList();

            // Get latest version node for dependencies
            var latestVersionNode = doc["versions"]?[latestVersion];
            var dependencies = ParseDependencyObject(latestVersionNode?["dependencies"]);
            var devDependencies = ParseDependencyObject(latestVersionNode?["devDependencies"]);
            var peerDependencies = ParseDependencyObject(latestVersionNode?["peerDependencies"]);

            // Extract repository URL
            var repositoryUrl = ExtractRepositoryUrl(doc["repository"]);

            // Check if deprecated
            var isDeprecated = latestVersionNode?["deprecated"] is not null;
            var deprecationMessage = latestVersionNode?["deprecated"]?.GetValue<string>();

            // Fetch download count separately
            var weeklyDownloads = await GetDownloadCountAsync(packageName, ct);

            var result = new NpmPackageInfo
            {
                Name = packageName,
                LatestVersion = latestVersion,
                Versions = versions,
                WeeklyDownloads = weeklyDownloads,
                RepositoryUrl = repositoryUrl,
                License = doc["license"]?.GetValue<string>(),
                Description = doc["description"]?.GetValue<string>(),
                Homepage = doc["homepage"]?.GetValue<string>(),
                Keywords = ParseStringArray(doc["keywords"]),
                IsDeprecated = isDeprecated,
                DeprecationMessage = deprecationMessage,
                Dependencies = dependencies,
                DevDependencies = devDependencies,
                PeerDependencies = peerDependencies
            };

            await _cache.SetAsync(cacheKey, result, TimeSpan.FromHours(12), ct);
            return result;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Error fetching npm info for {packageName}: {ex.Message}");
            return null;
        }
    }

    /// <summary>
    /// Get package information for multiple packages in parallel with concurrency control.
    /// </summary>
    public async Task<Dictionary<string, NpmPackageInfo>> GetPackageInfoBatchAsync(
        IEnumerable<string> packageNames,
        int maxConcurrency = 10,
        CancellationToken ct = default)
    {
        var results = new ConcurrentDictionary<string, NpmPackageInfo>(StringComparer.OrdinalIgnoreCase);
        var packageList = packageNames.Distinct(StringComparer.OrdinalIgnoreCase).ToList();

        if (packageList.Count == 0)
            return new Dictionary<string, NpmPackageInfo>(results);

        var semaphore = new SemaphoreSlim(maxConcurrency);

        var tasks = packageList.Select(async packageName =>
        {
            await semaphore.WaitAsync(ct);
            try
            {
                var info = await GetPackageInfoAsync(packageName, ct);
                if (info is not null)
                {
                    results[packageName] = info;
                }
            }
            finally
            {
                semaphore.Release();
            }
        });

        await Task.WhenAll(tasks);
        return new Dictionary<string, NpmPackageInfo>(results);
    }

    /// <summary>
    /// Get weekly download count from npm.
    /// </summary>
    public async Task<long> GetDownloadCountAsync(string packageName, CancellationToken ct = default)
    {
        try
        {
            var encodedName = Uri.EscapeDataString(packageName);
            var response = await _httpClient.GetAsync($"{NpmDownloadsUrl}/{encodedName}", ct);

            if (!response.IsSuccessStatusCode) return 0;

            // Parse directly from stream to avoid string allocation
            using var stream = await response.Content.ReadAsStreamAsync(ct);
            var doc = await JsonNode.ParseAsync(stream, cancellationToken: ct);

            return doc?["downloads"]?.GetValue<long>() ?? 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[WARN] Failed to fetch download count for {packageName}: {ex.Message}");
            return 0;
        }
    }

    /// <summary>
    /// Parse package.json file.
    /// </summary>
    public static async Task<PackageJson?> ParsePackageJsonAsync(string path, CancellationToken ct = default)
    {
        if (!File.Exists(path)) return null;

        try
        {
            var json = await File.ReadAllTextAsync(path, ct);
            var doc = JsonNode.Parse(json);

            if (doc is null) return null;

            return new PackageJson
            {
                Name = doc["name"]?.GetValue<string>(),
                Version = doc["version"]?.GetValue<string>(),
                Dependencies = ParseDependencyObject(doc["dependencies"]),
                DevDependencies = ParseDependencyObject(doc["devDependencies"]),
                PeerDependencies = ParseDependencyObject(doc["peerDependencies"]),
                License = doc["license"]?.GetValue<string>(),
                Repository = ExtractRepositoryUrl(doc["repository"])
            };
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Error parsing package.json at {path}: {ex.Message}");
            return null;
        }
    }

    /// <summary>
    /// Parse package-lock.json and build dependency information.
    /// Supports lockfileVersion 2 and 3.
    /// </summary>
    public static async Task<List<NpmLockDependency>> ParsePackageLockAsync(string path, CancellationToken ct = default)
    {
        var dependencies = new List<NpmLockDependency>();

        if (!File.Exists(path)) return dependencies;

        try
        {
            var json = await File.ReadAllTextAsync(path, ct);
            var doc = JsonNode.Parse(json);

            if (doc is null) return dependencies;

            var lockfileVersion = doc["lockfileVersion"]?.GetValue<int>() ?? 1;

            if (lockfileVersion >= 2)
            {
                // lockfileVersion 2/3 uses "packages" field
                var packages = doc["packages"]?.AsObject();
                if (packages is not null)
                {
                    foreach (var pkg in packages)
                    {
                        // Skip root package (empty key)
                        if (string.IsNullOrEmpty(pkg.Key)) continue;

                        // Extract package name from node_modules path
                        var name = ExtractPackageNameFromPath(pkg.Key);
                        if (string.IsNullOrEmpty(name)) continue;

                        var pkgNode = pkg.Value;
                        var version = pkgNode?["version"]?.GetValue<string>() ?? "";
                        var resolved = pkgNode?["resolved"]?.GetValue<string>() ?? "";
                        var isDev = pkgNode?["dev"]?.GetValue<bool>() ?? false;
                        var isOptional = pkgNode?["optional"]?.GetValue<bool>() ?? false;
                        var deps = ParseDependencyObject(pkgNode?["dependencies"]);

                        dependencies.Add(new NpmLockDependency
                        {
                            Name = name,
                            Version = version,
                            ResolvedUrl = resolved,
                            IsDev = isDev,
                            IsOptional = isOptional,
                            Dependencies = deps
                        });
                    }
                }
            }
            else
            {
                // lockfileVersion 1 uses "dependencies" field
                ParseLegacyDependencies(doc["dependencies"]?.AsObject(), dependencies);
            }
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Error parsing package-lock.json at {path}: {ex.Message}");
        }

        return dependencies;
    }

    private static void ParseLegacyDependencies(JsonObject? depsNode, List<NpmLockDependency> dependencies, bool isDev = false)
    {
        if (depsNode is null) return;

        foreach (var dep in depsNode)
        {
            var name = dep.Key;
            var node = dep.Value;

            var version = node?["version"]?.GetValue<string>() ?? "";
            var resolved = node?["resolved"]?.GetValue<string>() ?? "";
            var devFlag = node?["dev"]?.GetValue<bool>() ?? isDev;
            var optional = node?["optional"]?.GetValue<bool>() ?? false;
            var subDeps = ParseDependencyObject(node?["requires"]);

            dependencies.Add(new NpmLockDependency
            {
                Name = name,
                Version = version,
                ResolvedUrl = resolved,
                IsDev = devFlag,
                IsOptional = optional,
                Dependencies = subDeps
            });

            // Recursively parse nested dependencies
            ParseLegacyDependencies(node?["dependencies"]?.AsObject(), dependencies, devFlag);
        }
    }

    private static string? ExtractPackageNameFromPath(string path)
    {
        // path format: "node_modules/@scope/package" or "node_modules/package"
        const string prefix = "node_modules/";

        if (!path.StartsWith(prefix)) return null;

        var name = path[prefix.Length..];

        // Handle nested node_modules (take only the last package name)
        var lastIdx = name.LastIndexOf("node_modules/", StringComparison.Ordinal);
        if (lastIdx >= 0)
        {
            name = name[(lastIdx + prefix.Length)..];
        }

        return name;
    }

    /// <summary>
    /// Find all package.json files in a directory (excluding node_modules).
    /// </summary>
    public static IEnumerable<string> FindPackageJsonFiles(string rootPath)
    {
        if (File.Exists(rootPath))
        {
            if (rootPath.EndsWith("package.json", StringComparison.OrdinalIgnoreCase))
            {
                yield return rootPath;
            }
            yield break;
        }

        if (!Directory.Exists(rootPath)) yield break;

        var queue = new Queue<string>();
        queue.Enqueue(rootPath);

        while (queue.Count > 0)
        {
            var dir = queue.Dequeue();

            var packageJsonPath = Path.Combine(dir, "package.json");
            if (File.Exists(packageJsonPath))
            {
                yield return packageJsonPath;
            }

            try
            {
                foreach (var subDir in Directory.EnumerateDirectories(dir))
                {
                    var dirName = Path.GetFileName(subDir);

                    // Skip node_modules and common non-project directories
                    if (dirName.Equals("node_modules", StringComparison.OrdinalIgnoreCase) ||
                        dirName.Equals(".git", StringComparison.OrdinalIgnoreCase) ||
                        dirName.Equals("dist", StringComparison.OrdinalIgnoreCase) ||
                        dirName.Equals("build", StringComparison.OrdinalIgnoreCase) ||
                        dirName.StartsWith('.'))
                    {
                        continue;
                    }

                    queue.Enqueue(subDir);
                }
            }
            catch
            {
                // Ignore directories we can't access
            }
        }
    }

    /// <summary>
    /// Build dependency tree from package-lock.json.
    /// </summary>
    public async Task<DependencyTree> BuildDependencyTreeAsync(
        string packageJsonPath,
        int maxDepth = 10,
        CancellationToken ct = default)
    {
        var packageJson = await ParsePackageJsonAsync(packageJsonPath, ct);
        var lockPath = Path.Combine(Path.GetDirectoryName(packageJsonPath) ?? ".", "package-lock.json");
        var lockDeps = await ParsePackageLockAsync(lockPath, ct);

        var lockLookup = lockDeps
            .GroupBy(d => d.Name)
            .ToDictionary(g => g.Key, g => g.First(), StringComparer.OrdinalIgnoreCase);

        var roots = new List<DependencyTreeNode>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var licenseLookup = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);

        // Build tree from direct dependencies
        if (packageJson is not null)
        {
            foreach (var dep in packageJson.Dependencies)
            {
                var node = await BuildTreeNodeAsync(dep.Key, dep.Value, 0, maxDepth, lockLookup, seen, licenseLookup, false, ct);
                if (node is not null)
                {
                    roots.Add(node);
                }
            }

            foreach (var dep in packageJson.DevDependencies)
            {
                var node = await BuildTreeNodeAsync(dep.Key, dep.Value, 0, maxDepth, lockLookup, seen, licenseLookup, true, ct);
                if (node is not null)
                {
                    roots.Add(node);
                }
            }
        }

        var tree = new DependencyTree
        {
            ProjectPath = packageJsonPath,
            ProjectType = ProjectType.Npm,
            Roots = roots,
            TotalPackages = seen.Count,
            MaxDepth = CalculateMaxDepth(roots)
        };

        return tree;
    }

    private async Task<DependencyTreeNode?> BuildTreeNodeAsync(
        string name,
        string versionRange,
        int depth,
        int maxDepth,
        Dictionary<string, NpmLockDependency> lockLookup,
        HashSet<string> seen,
        Dictionary<string, string?> licenseLookup,
        bool isDev,
        CancellationToken ct)
    {
        if (depth > maxDepth) return null;

        // Get version from lock file
        lockLookup.TryGetValue(name, out var lockDep);
        var version = lockDep?.Version ?? versionRange;

        var key = $"{name}@{version}";
        var isDuplicate = !seen.Add(key);

        var node = new DependencyTreeNode
        {
            PackageId = name,
            Version = version,
            Depth = depth,
            DependencyType = depth == 0
                ? (isDev ? DependencyType.Direct : DependencyType.Direct)
                : DependencyType.Transitive,
            IsDuplicate = isDuplicate,
            Ecosystem = PackageEcosystem.Npm
        };

        // Fetch health info for this package or get from cache
        if (!isDuplicate)
        {
            var npmInfo = await GetPackageInfoAsync(name, ct);
            if (npmInfo is not null)
            {
                node.License = npmInfo.License;
                licenseLookup[key] = npmInfo.License;
            }
        }
        else if (licenseLookup.TryGetValue(key, out var cachedLicense))
        {
            // Duplicate: use cached license from first occurrence
            node.License = cachedLicense;
        }

        // Build children from lock file dependencies
        if (!isDuplicate && lockDep?.Dependencies is not null && depth < maxDepth)
        {
            foreach (var childDep in lockDep.Dependencies)
            {
                var child = await BuildTreeNodeAsync(
                    childDep.Key, childDep.Value, depth + 1, maxDepth, lockLookup, seen, licenseLookup, isDev, ct);
                if (child is not null)
                {
                    node.Children.Add(child);
                }
            }
        }

        return node;
    }

    private static int CalculateMaxDepth(List<DependencyTreeNode> roots)
    {
        var maxDepth = 0;

        void Visit(DependencyTreeNode node)
        {
            if (node.Depth > maxDepth) maxDepth = node.Depth;
            foreach (var child in node.Children)
            {
                Visit(child);
            }
        }

        foreach (var root in roots)
        {
            Visit(root);
        }

        return maxDepth;
    }

    private static Dictionary<string, string> ParseDependencyObject(JsonNode? node)
    {
        var deps = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        if (node is JsonObject obj)
        {
            foreach (var prop in obj)
            {
                var value = prop.Value?.GetValue<string>();
                if (!string.IsNullOrEmpty(value))
                {
                    deps[prop.Key] = value;
                }
            }
        }

        return deps;
    }

    private static List<string> ParseStringArray(JsonNode? node)
    {
        var result = new List<string>();

        if (node is JsonArray arr)
        {
            foreach (var item in arr)
            {
                var value = item?.GetValue<string>();
                if (!string.IsNullOrEmpty(value))
                {
                    result.Add(value);
                }
            }
        }

        return result;
    }

    private static string? ExtractRepositoryUrl(JsonNode? node)
    {
        if (node is null) return null;

        // Can be string or object { type: "git", url: "..." }
        if (node is JsonValue val)
        {
            return NormalizeGitUrl(val.GetValue<string>());
        }

        if (node is JsonObject obj)
        {
            var url = obj["url"]?.GetValue<string>();
            return NormalizeGitUrl(url);
        }

        return null;
    }

    private static string? NormalizeGitUrl(string? url)
    {
        if (string.IsNullOrEmpty(url)) return null;

        // Common formats:
        // git+https://github.com/owner/repo.git
        // git://github.com/owner/repo.git
        // https://github.com/owner/repo.git
        // github:owner/repo

        url = url.Replace("git+", "").Replace("git://", "https://");

        if (url.StartsWith("github:"))
        {
            url = $"https://github.com/{url[7..]}";
        }

        if (url.EndsWith(".git"))
        {
            url = url[..^4];
        }

        return url;
    }

    public void Dispose()
    {
        _httpClient.Dispose();
    }
}
