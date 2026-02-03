using System.Xml.Linq;
using NuGet.Common;
using NuGet.Configuration;
using NuGet.Protocol;
using NuGet.Protocol.Core.Types;
using NuGet.Versioning;
using NuGetHealthAnalyzer.Models;

namespace NuGetHealthAnalyzer.DataSources;

/// <summary>
/// Client for NuGet API v3 using NuGet.Protocol.
/// </summary>
public sealed class NuGetApiClient : IDisposable
{
    private readonly SourceCacheContext _cacheContext;
    private readonly SourceRepository _repository;
    private readonly ResponseCache _cache;
    private readonly ILogger _logger;

    public NuGetApiClient(string? sourceUrl = null, ResponseCache? cache = null)
    {
        _cacheContext = new SourceCacheContext();
        var source = new PackageSource(sourceUrl ?? "https://api.nuget.org/v3/index.json");
        _repository = Repository.Factory.GetCoreV3(source);
        _cache = cache ?? new ResponseCache();
        _logger = NullLogger.Instance;
    }

    /// <summary>
    /// Get package information from NuGet.
    /// </summary>
    public async Task<NuGetPackageInfo?> GetPackageInfoAsync(string packageId, CancellationToken ct = default)
    {
        var cacheKey = $"nuget:{packageId}";
        var cached = await _cache.GetAsync<NuGetPackageInfo>(cacheKey, ct);
        if (cached is not null) return cached;

        try
        {
            var metadataResource = await _repository.GetResourceAsync<PackageMetadataResource>(ct);
            var packages = await metadataResource.GetMetadataAsync(
                packageId,
                includePrerelease: true,
                includeUnlisted: false,
                _cacheContext,
                _logger,
                ct);

            var packageList = packages.ToList();
            if (packageList.Count == 0) return null;

            var latest = packageList
                .Where(p => !p.Identity.Version.IsPrerelease)
                .OrderByDescending(p => p.Identity.Version)
                .FirstOrDefault() ?? packageList.OrderByDescending(p => p.Identity.Version).First();

            var versions = packageList
                .Select(p => new Models.VersionInfo
                {
                    Version = p.Identity.Version.ToNormalizedString(),
                    PublishedDate = p.Published?.UtcDateTime ?? DateTime.MinValue,
                    Downloads = p.DownloadCount ?? 0,
                    IsPrerelease = p.Identity.Version.IsPrerelease,
                    IsListed = true
                })
                .OrderByDescending(v => NuGetVersion.Parse(v.Version))
                .ToList();

            // Fetch deprecation info once (async)
            var deprecationInfo = await latest.GetDeprecationMetadataAsync();

            var result = new NuGetPackageInfo
            {
                PackageId = packageId,
                LatestVersion = latest.Identity.Version.ToNormalizedString(),
                Versions = versions,
                TotalDownloads = packageList.Sum(p => p.DownloadCount ?? 0),
                ProjectUrl = latest.ProjectUrl?.ToString(),
                RepositoryUrl = ExtractRepositoryUrl(latest),
                License = latest.LicenseMetadata?.License ?? latest.LicenseUrl?.ToString(),
                LicenseUrl = latest.LicenseUrl?.ToString(),
                Description = latest.Description,
                Authors = latest.Authors?.Split(',').Select(a => a.Trim()).ToList() ?? [],
                Tags = latest.Tags?.Split(',').Select(t => t.Trim()).ToList() ?? [],
                IsDeprecated = deprecationInfo is not null,
                DeprecationReason = deprecationInfo?.Message
            };

            await _cache.SetAsync(cacheKey, result, TimeSpan.FromHours(12), ct);
            return result;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Error fetching NuGet info for {packageId}: {ex.Message}");
            return null;
        }
    }

    private static string? ExtractRepositoryUrl(IPackageSearchMetadata metadata)
    {
        // Try project URL first, then look for GitHub patterns
        var projectUrl = metadata.ProjectUrl?.ToString();
        if (projectUrl?.Contains("github.com", StringComparison.OrdinalIgnoreCase) == true)
        {
            return NormalizeGitHubUrl(projectUrl);
        }
        return projectUrl;
    }

    private static string? NormalizeGitHubUrl(string url)
    {
        // Convert various GitHub URL formats to owner/repo
        var uri = new Uri(url);
        if (uri.Host.Contains("github.com"))
        {
            var segments = uri.AbsolutePath.Trim('/').Split('/');
            if (segments.Length >= 2)
            {
                return $"https://github.com/{segments[0]}/{segments[1]}";
            }
        }
        return url;
    }

    /// <summary>
    /// Parse package references from a project file.
    /// </summary>
    public static async Task<List<PackageReference>> ParseProjectFileAsync(string projectPath, CancellationToken ct = default)
    {
        var references = new List<PackageReference>();

        if (!File.Exists(projectPath)) return references;

        try
        {
            var content = await File.ReadAllTextAsync(projectPath, ct);
            var doc = XDocument.Parse(content);

            // Check for central package management
            var centralPackagesPath = FindCentralPackagesProps(projectPath);
            var centralVersions = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

            if (centralPackagesPath is not null && File.Exists(centralPackagesPath))
            {
                centralVersions = await ParseCentralPackageVersionsAsync(centralPackagesPath, ct);
            }

            // Parse PackageReference elements
            var packageRefs = doc.Descendants()
                .Where(e => e.Name.LocalName == "PackageReference");

            foreach (var pkg in packageRefs)
            {
                var id = pkg.Attribute("Include")?.Value;
                if (string.IsNullOrEmpty(id)) continue;

                var version = pkg.Attribute("Version")?.Value
                    ?? pkg.Elements().FirstOrDefault(e => e.Name.LocalName == "Version")?.Value;

                // Try central package management if no version specified
                if (string.IsNullOrEmpty(version) && centralVersions.TryGetValue(id, out var centralVersion))
                {
                    version = centralVersion;
                }

                if (!string.IsNullOrEmpty(version))
                {
                    references.Add(new PackageReference
                    {
                        PackageId = id,
                        Version = version,
                        SourceFile = projectPath
                    });
                }
            }
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Error parsing project file {projectPath}: {ex.Message}");
        }

        return references;
    }

    private static string? FindCentralPackagesProps(string projectPath)
    {
        var dir = Path.GetDirectoryName(projectPath);
        while (!string.IsNullOrEmpty(dir))
        {
            var propsPath = Path.Combine(dir, "Directory.Packages.props");
            if (File.Exists(propsPath)) return propsPath;
            dir = Path.GetDirectoryName(dir);
        }
        return null;
    }

    private static async Task<Dictionary<string, string>> ParseCentralPackageVersionsAsync(
        string propsPath, CancellationToken ct)
    {
        var versions = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        try
        {
            var content = await File.ReadAllTextAsync(propsPath, ct);
            var doc = XDocument.Parse(content);

            var packageVersions = doc.Descendants()
                .Where(e => e.Name.LocalName == "PackageVersion");

            foreach (var pkg in packageVersions)
            {
                var id = pkg.Attribute("Include")?.Value;
                var version = pkg.Attribute("Version")?.Value;

                if (!string.IsNullOrEmpty(id) && !string.IsNullOrEmpty(version))
                {
                    versions[id] = version;
                }
            }
        }
        catch
        {
            // Ignore errors parsing props file
        }

        return versions;
    }

    /// <summary>
    /// Find all project files in a directory.
    /// </summary>
    public static IEnumerable<string> FindProjectFiles(string rootPath)
    {
        if (File.Exists(rootPath))
        {
            if (rootPath.EndsWith(".csproj", StringComparison.OrdinalIgnoreCase) ||
                rootPath.EndsWith(".fsproj", StringComparison.OrdinalIgnoreCase) ||
                rootPath.EndsWith(".vbproj", StringComparison.OrdinalIgnoreCase))
            {
                yield return rootPath;
            }
            else if (rootPath.EndsWith(".sln", StringComparison.OrdinalIgnoreCase))
            {
                foreach (var proj in ParseSolutionForProjects(rootPath))
                {
                    yield return proj;
                }
            }
            yield break;
        }

        if (!Directory.Exists(rootPath)) yield break;

        foreach (var file in Directory.EnumerateFiles(rootPath, "*.csproj", SearchOption.AllDirectories))
        {
            yield return file;
        }
        foreach (var file in Directory.EnumerateFiles(rootPath, "*.fsproj", SearchOption.AllDirectories))
        {
            yield return file;
        }
        foreach (var file in Directory.EnumerateFiles(rootPath, "*.vbproj", SearchOption.AllDirectories))
        {
            yield return file;
        }
    }

    private static IEnumerable<string> ParseSolutionForProjects(string slnPath)
    {
        var slnDir = Path.GetDirectoryName(slnPath) ?? ".";
        var lines = File.ReadAllLines(slnPath);

        foreach (var line in lines)
        {
            if (line.StartsWith("Project("))
            {
                var parts = line.Split('"');
                if (parts.Length >= 6)
                {
                    var projectPath = parts[5];
                    if (projectPath.EndsWith(".csproj", StringComparison.OrdinalIgnoreCase) ||
                        projectPath.EndsWith(".fsproj", StringComparison.OrdinalIgnoreCase) ||
                        projectPath.EndsWith(".vbproj", StringComparison.OrdinalIgnoreCase))
                    {
                        var fullPath = Path.GetFullPath(Path.Combine(slnDir, projectPath));
                        if (File.Exists(fullPath))
                        {
                            yield return fullPath;
                        }
                    }
                }
            }
        }
    }

    public void Dispose()
    {
        _cacheContext.Dispose();
    }
}
