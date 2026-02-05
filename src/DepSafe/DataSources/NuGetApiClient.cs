using System.Diagnostics;
using System.Text.Json;
using System.Xml.Linq;
using NuGet.Common;
using NuGet.Configuration;
using NuGet.Protocol;
using NuGet.Protocol.Core.Types;
using NuGet.Frameworks;
using NuGet.Versioning;
using DepSafe.Models;

namespace DepSafe.DataSources;

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

            // Fetch dependencies using DependencyInfoResource (more reliable than DependencySets)
            var dependencies = await GetPackageDependenciesAsync(latest.Identity, ct);

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
                DeprecationReason = deprecationInfo?.Message,
                Dependencies = dependencies
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

    /// <summary>
    /// Get package information for multiple packages in parallel with concurrency control.
    /// </summary>
    public async Task<Dictionary<string, NuGetPackageInfo>> GetPackageInfoBatchAsync(
        IEnumerable<string> packageIds,
        int maxConcurrency = 10,
        CancellationToken ct = default)
    {
        var results = new Dictionary<string, NuGetPackageInfo>(StringComparer.OrdinalIgnoreCase);
        var packageList = packageIds.Distinct(StringComparer.OrdinalIgnoreCase).ToList();

        if (packageList.Count == 0)
            return results;

        var semaphore = new SemaphoreSlim(maxConcurrency);
        var lockObj = new object();

        var tasks = packageList.Select(async packageId =>
        {
            await semaphore.WaitAsync(ct);
            try
            {
                var info = await GetPackageInfoAsync(packageId, ct);
                if (info is not null)
                {
                    lock (lockObj)
                    {
                        results[packageId] = info;
                    }
                }
            }
            finally
            {
                semaphore.Release();
            }
        });

        await Task.WhenAll(tasks);
        return results;
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
    /// Get package dependencies using DependencyInfoResource.
    /// </summary>
    private async Task<List<PackageDependency>> GetPackageDependenciesAsync(
        NuGet.Packaging.Core.PackageIdentity packageIdentity, CancellationToken ct)
    {
        var dependencies = new List<PackageDependency>();

        try
        {
            var dependencyInfoResource = await _repository.GetResourceAsync<DependencyInfoResource>(ct);
            if (dependencyInfoResource == null) return dependencies;

            // Try different frameworks in preference order
            var frameworks = new[]
            {
                NuGetFramework.Parse("net8.0"),
                NuGetFramework.Parse("net6.0"),
                NuGetFramework.Parse("netstandard2.1"),
                NuGetFramework.Parse("netstandard2.0"),
                NuGetFramework.AnyFramework
            };

            foreach (var framework in frameworks)
            {
                var dependencyInfo = await dependencyInfoResource.ResolvePackage(
                    packageIdentity,
                    framework,
                    _cacheContext,
                    _logger,
                    ct);

                if (dependencyInfo?.Dependencies != null && dependencyInfo.Dependencies.Any())
                {
                    foreach (var dep in dependencyInfo.Dependencies)
                    {
                        dependencies.Add(new PackageDependency
                        {
                            PackageId = dep.Id,
                            VersionRange = dep.VersionRange?.ToString(),
                            TargetFramework = framework.GetShortFolderName()
                        });
                    }
                    break; // Found dependencies, stop trying other frameworks
                }
            }
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[WARN] Failed to fetch dependencies for {packageIdentity.Id}: {ex.Message}");
        }

        return dependencies;
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
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[WARN] Failed to parse {propsPath}: {ex.Message}");
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

    /// <summary>
    /// Parse packages using dotnet list package command for resolved versions and transitive dependencies.
    /// This resolves MSBuild variables like $(AspireVersion).
    /// </summary>
    public static async Task<(List<PackageReference> TopLevel, List<PackageReference> Transitive)> ParsePackagesWithDotnetAsync(
        string path, CancellationToken ct = default)
    {
        var topLevel = new List<PackageReference>();
        var transitive = new List<PackageReference>();

        try
        {
            // Determine working directory and arguments based on path type
            string workingDir;
            string arguments;

            if (File.Exists(path) && (path.EndsWith(".csproj") || path.EndsWith(".fsproj") || path.EndsWith(".vbproj") || path.EndsWith(".sln")))
            {
                // Project or solution file specified
                workingDir = Path.GetDirectoryName(path) ?? ".";
                arguments = $"list \"{path}\" package --include-transitive --format json";
            }
            else if (Directory.Exists(path))
            {
                // Directory specified - use it as working directory
                workingDir = path;
                arguments = "list package --include-transitive --format json";
            }
            else
            {
                // Fallback
                workingDir = Path.GetDirectoryName(path) ?? ".";
                arguments = "list package --include-transitive --format json";
            }

            var startInfo = new ProcessStartInfo
            {
                FileName = "dotnet",
                Arguments = arguments,
                WorkingDirectory = workingDir,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            using var process = new Process { StartInfo = startInfo };
            process.Start();

            var output = await process.StandardOutput.ReadToEndAsync(ct);
            await process.WaitForExitAsync(ct);

            if (process.ExitCode != 0 || string.IsNullOrWhiteSpace(output))
            {
                return (topLevel, transitive);
            }

            var options = new JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true
            };
            var result = JsonSerializer.Deserialize<DotnetPackageListOutput>(output, options);

            if (result?.Projects == null) return (topLevel, transitive);

            var seenTopLevel = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var seenTransitive = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            foreach (var project in result.Projects)
            {
                foreach (var framework in project.Frameworks)
                {
                    foreach (var pkg in framework.TopLevelPackages)
                    {
                        if (seenTopLevel.Add(pkg.Id))
                        {
                            topLevel.Add(new PackageReference
                            {
                                PackageId = pkg.Id,
                                Version = pkg.ResolvedVersion,
                                RequestedVersion = pkg.RequestedVersion,
                                ResolvedVersion = pkg.ResolvedVersion,
                                SourceFile = project.Path,
                                IsTransitive = false
                            });
                        }
                    }

                    foreach (var pkg in framework.TransitivePackages)
                    {
                        if (seenTransitive.Add(pkg.Id) && !seenTopLevel.Contains(pkg.Id))
                        {
                            transitive.Add(new PackageReference
                            {
                                PackageId = pkg.Id,
                                Version = pkg.ResolvedVersion,
                                ResolvedVersion = pkg.ResolvedVersion,
                                SourceFile = project.Path,
                                IsTransitive = true
                            });
                        }
                    }
                }
            }
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Error running dotnet list package: {ex.Message}");
        }

        return (topLevel, transitive);
    }
}
