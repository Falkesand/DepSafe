using System.Collections.Concurrent;
using System.CommandLine;
using System.CommandLine.Invocation;
using System.Text.Json;
using DepSafe.Compliance;
using DepSafe.DataSources;
using DepSafe.Models;
using DepSafe.Scoring;
using Spectre.Console;

namespace DepSafe.Commands;

public static class SbomCommand
{
    public static Command Create()
    {
        var pathArg = new Argument<string?>(
            "path",
            () => ".",
            "Path to project, solution, or directory");

        var formatOption = new Option<SbomFormat>(
            ["--format", "-f"],
            () => SbomFormat.Spdx,
            "Output format (spdx or cyclonedx)");

        var outputOption = new Option<string?>(
            ["--output", "-o"],
            "Output file path (default: stdout)");

        var skipGitHubOption = new Option<bool>(
            ["--skip-github"],
            "Skip GitHub API calls (faster, but no vulnerability data in SBOM)");

        var command = new Command("sbom", "Generate Software Bill of Materials (SBOM)")
        {
            pathArg,
            formatOption,
            outputOption,
            skipGitHubOption
        };

        command.SetHandler(async context =>
        {
            var path = context.ParseResult.GetValueForArgument(pathArg);
            var format = context.ParseResult.GetValueForOption(formatOption);
            var outputPath = context.ParseResult.GetValueForOption(outputOption);
            var skipGitHub = context.ParseResult.GetValueForOption(skipGitHubOption);
            var ct = context.GetCancellationToken();
            context.ExitCode = await ExecuteAsync(path, format, outputPath, skipGitHub, ct);
        });

        return command;
    }

    private static async Task<int> ExecuteAsync(string? path, SbomFormat format, string? outputPath, bool skipGitHub, CancellationToken ct)
    {
        path = string.IsNullOrEmpty(path) ? Directory.GetCurrentDirectory() : Path.GetFullPath(path);

        if (!File.Exists(path) && !Directory.Exists(path))
        {
            AnsiConsole.MarkupLine($"[red]Path not found: {Markup.Escape(path)}[/]");
            return 1;
        }

        // Validate output path: block relative path traversal
        if (!string.IsNullOrEmpty(outputPath) && !Path.IsPathRooted(outputPath))
        {
            var fullOutputPath = Path.GetFullPath(outputPath);
            var workingDir = Path.GetFullPath(Directory.GetCurrentDirectory());
            if (!fullOutputPath.StartsWith(workingDir, StringComparison.OrdinalIgnoreCase))
            {
                AnsiConsole.MarkupLine("[red]Error: Relative output path must not traverse outside the working directory.[/]");
                return 1;
            }
        }

        // Detect project type
        var hasNetProjects = NuGetApiClient.FindProjectFiles(path).Any();
        var hasPackageJson = NpmApiClient.FindPackageJsonFiles(path).Any();

        if (!hasNetProjects && !hasPackageJson)
        {
            AnsiConsole.MarkupLine("[yellow]No project files found (no .csproj/.sln or package.json).[/]");
            return 0;
        }

        var projectType = (hasNetProjects, hasPackageJson) switch
        {
            (true, true) => ProjectType.Mixed,
            (true, false) => ProjectType.DotNet,
            _ => ProjectType.Npm
        };

        AnsiConsole.MarkupLine($"[dim]Detected project type: {projectType}[/]");

        var packages = new List<PackageHealth>();

        if (projectType is ProjectType.DotNet or ProjectType.Mixed)
        {
            var dotnetPackages = await ResolveDotNetPackagesAsync(path, skipGitHub, ct);
            packages.AddRange(dotnetPackages);
        }

        if (projectType is ProjectType.Npm or ProjectType.Mixed)
        {
            var npmPackages = await ResolveNpmPackagesAsync(path, skipGitHub, ct);
            packages.AddRange(npmPackages);
        }

        // Deduplicate (possible overlap in mixed projects)
        if (projectType == ProjectType.Mixed)
        {
            packages = packages
                .DistinctBy(p => $"{p.PackageId}@{p.Version}")
                .ToList();
        }

        if (packages.Count == 0)
        {
            AnsiConsole.MarkupLine("[yellow]No packages found.[/]");
            return 0;
        }

        AnsiConsole.MarkupLine($"[dim]Total packages for SBOM: {packages.Count}[/]");

        var projectName = Path.GetFileNameWithoutExtension(path);
        var generator = new SbomGenerator();

        string output;
        if (format == SbomFormat.CycloneDx)
        {
            var cycloneDx = generator.GenerateCycloneDx(projectName, packages);
            output = JsonSerializer.Serialize(cycloneDx, JsonDefaults.Indented);
        }
        else
        {
            var spdx = generator.Generate(projectName, packages);
            output = JsonSerializer.Serialize(spdx, JsonDefaults.IndentedDefault);
        }

        if (!string.IsNullOrEmpty(outputPath))
        {
            await File.WriteAllTextAsync(outputPath, output, ct);
            AnsiConsole.MarkupLine($"[green]SBOM written to {Markup.Escape(outputPath)}[/]");
        }
        else
        {
            Console.WriteLine(output);
        }

        return 0;
    }

    /// <summary>
    /// Resolve .NET packages including transitive dependencies via dotnet list package.
    /// </summary>
    private static async Task<List<PackageHealth>> ResolveDotNetPackagesAsync(string path, bool skipGitHub, CancellationToken ct)
    {
        // Phase 1: Resolve direct + transitive packages
        var allReferences = new Dictionary<string, PackageReference>(StringComparer.OrdinalIgnoreCase);

        var projectFiles = NuGetApiClient.FindProjectFiles(path).ToList();
        AnsiConsole.MarkupLine($"[dim]Found {projectFiles.Count} .NET project file(s)[/]");

        await AnsiConsole.Status()
            .StartAsync("Resolving .NET dependencies (direct + transitive)...", async _ =>
            {
                foreach (var projectFile in projectFiles)
                {
                    var dotnetResult = await NuGetApiClient.ParsePackagesWithDotnetAsync(projectFile, ct);
                    var (topLevel, transitive) = dotnetResult.ValueOr(([], []));

                    foreach (var r in topLevel)
                        allReferences.TryAdd(r.PackageId, r);

                    foreach (var r in transitive)
                        allReferences.TryAdd(r.PackageId, r);
                }
            });

        if (allReferences.Count == 0)
            return [];

        AnsiConsole.MarkupLine($"[dim]Resolved {allReferences.Count} .NET packages (direct + transitive)[/]");

        // Phase 2: Enrich via AnalysisPipeline (NuGet info, GitHub, vulnerabilities, health scores)
        using var pipeline = new AnalysisPipeline(skipGitHub);
        pipeline.ShowGitHubStatus("No vulnerability data in SBOM.");

        await pipeline.RunAsync(allReferences, ct);

        return pipeline.Packages;
    }

    /// <summary>
    /// Resolve npm packages including transitive dependencies via dependency tree.
    /// </summary>
    private static async Task<List<PackageHealth>> ResolveNpmPackagesAsync(string path, bool skipGitHub, CancellationToken ct)
    {
        var packageJsonFiles = NpmApiClient.FindPackageJsonFiles(path).ToList();
        if (packageJsonFiles.Count == 0)
            return [];

        var packageJsonPath = packageJsonFiles[0];
        AnsiConsole.MarkupLine($"[dim]Using: {packageJsonPath}[/]");

        // Parse package.json for direct deps
        var packageJsonResult = await NpmApiClient.ParsePackageJsonAsync(packageJsonPath, ct);
        if (packageJsonResult.IsFailure)
        {
            AnsiConsole.MarkupLine($"[red]{Markup.Escape(packageJsonResult.Error)}[/]");
            return [];
        }

        var packageJson = packageJsonResult.Value;
        var allDeps = packageJson.Dependencies
            .Concat(packageJson.DevDependencies)
            .ToDictionary(kv => kv.Key, kv => kv.Value, StringComparer.OrdinalIgnoreCase);

        if (allDeps.Count == 0)
        {
            AnsiConsole.MarkupLine("[yellow]No dependencies found in package.json[/]");
            return [];
        }

        AnsiConsole.MarkupLine($"[dim]Found {packageJson.Dependencies.Count} dependencies and {packageJson.DevDependencies.Count} dev dependencies[/]");

        // Build dependency tree (resolves transitive deps from lock file)
        using var npmClient = new NpmApiClient();
        DependencyTree? dependencyTree = null;

        await AnsiConsole.Status()
            .StartAsync("Building npm dependency tree...", async _ =>
            {
                dependencyTree = await npmClient.BuildDependencyTreeAsync(packageJsonPath, maxDepth: 10, ct);
            });

        // Collect transitive package IDs
        var directPackageIds = new HashSet<string>(allDeps.Keys, StringComparer.OrdinalIgnoreCase);
        var transitiveNpmPackageIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (dependencyTree is not null)
        {
            CollectTransitivePackageIds(dependencyTree.Roots, directPackageIds, transitiveNpmPackageIds);
        }

        // Fetch npm info for ALL packages (direct + transitive) for complete SBOM
        var allNpmPackageIds = allDeps.Keys
            .Concat(transitiveNpmPackageIds)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        AnsiConsole.MarkupLine($"[dim]Fetching npm info for {allNpmPackageIds.Count} packages (direct + transitive)[/]");

        var npmInfoMap = new ConcurrentDictionary<string, NpmPackageInfo>(StringComparer.OrdinalIgnoreCase);

        await AnsiConsole.Progress()
            .StartAsync(async ctx =>
            {
                var task = ctx.AddTask($"Fetching npm info for {allNpmPackageIds.Count} packages", maxValue: allNpmPackageIds.Count);

                using var semaphore = new SemaphoreSlim(10);
                var tasks = allNpmPackageIds.Select(async packageName =>
                {
                    await semaphore.WaitAsync(ct);
                    try
                    {
                        var result = await npmClient.GetPackageInfoAsync(packageName, ct);
                        if (result.IsSuccess)
                        {
                            npmInfoMap[packageName] = result.Value;
                        }
                    }
                    finally
                    {
                        semaphore.Release();
                        task.Increment(1);
                    }
                });
                await Task.WhenAll(tasks);
            });

        // Optional: GitHub repo info for richer SBOM metadata
        using var githubClient = skipGitHub ? null : new GitHubApiClient();
        var repoInfoMap = new Dictionary<string, GitHubRepoInfo?>(StringComparer.OrdinalIgnoreCase);

        if (githubClient is not null && !githubClient.IsRateLimited)
        {
            await AnsiConsole.Status()
                .StartAsync("Fetching GitHub repository info...", async _ =>
                {
                    var repoUrls = npmInfoMap.Values
                        .Select(n => n.RepositoryUrl)
                        .Where(u => u?.Contains("github.com", StringComparison.OrdinalIgnoreCase) == true)
                        .Distinct(StringComparer.OrdinalIgnoreCase)
                        .ToList();

                    if (repoUrls.Count > 0)
                    {
                        var results = await githubClient.GetRepositoriesBatchAsync(repoUrls!, ct);
                        foreach (var (packageId, info) in npmInfoMap)
                        {
                            if (info.RepositoryUrl is not null && results.TryGetValue(info.RepositoryUrl, out var repoInfo))
                            {
                                repoInfoMap[packageId] = repoInfo;
                            }
                        }
                    }
                });
        }

        // Fetch vulnerabilities from OSV
        var allVulnerabilities = new Dictionary<string, List<VulnerabilityInfo>>(StringComparer.OrdinalIgnoreCase);
        using var osvClient = new OsvApiClient();

        await AnsiConsole.Status()
            .StartAsync($"Checking vulnerabilities via OSV ({allNpmPackageIds.Count} packages)...", async _ =>
            {
                var vulns = await osvClient.QueryNpmPackagesAsync(allNpmPackageIds, ct);
                foreach (var (name, v) in vulns)
                {
                    allVulnerabilities[name] = v;
                }
            });

        // Build installed version lookup from dependency tree
        var installedVersions = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (dependencyTree is not null)
        {
            foreach (var root in dependencyTree.Roots)
            {
                installedVersions[root.PackageId] = root.Version;
            }
        }

        // Parse lock file for integrity hashes
        var lockPath = Path.Combine(Path.GetDirectoryName(packageJsonPath) ?? ".", "package-lock.json");
        var lockDepsResult = await NpmApiClient.ParsePackageLockAsync(lockPath, ct);
        var lockDeps = lockDepsResult.ValueOr([]);
        var integrityLookup = lockDeps
            .Where(d => !string.IsNullOrEmpty(d.Integrity))
            .GroupBy(d => d.Name, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key, g => g.First().Integrity!, StringComparer.OrdinalIgnoreCase);

        // Calculate health scores for direct packages
        var calculator = new HealthScoreCalculator();
        var packages = new List<PackageHealth>();

        foreach (var (packageName, versionRange) in allDeps)
        {
            if (!npmInfoMap.TryGetValue(packageName, out var npmInfo))
                continue;

            repoInfoMap.TryGetValue(packageName, out var repoInfo);
            if (!allVulnerabilities.TryGetValue(packageName, out var vulnerabilities))
                vulnerabilities = [];

            var installedVersion = installedVersions.GetValueOrDefault(packageName, npmInfo.LatestVersion);

            var health = calculator.Calculate(
                packageName,
                installedVersion,
                npmInfo,
                repoInfo,
                vulnerabilities);

            if (integrityLookup.TryGetValue(packageName, out var integrity))
                health.ContentIntegrity = integrity;

            packages.Add(health);
        }

        // Extract transitive packages from dependency tree
        if (dependencyTree is not null)
        {
            var transitivePackages = ExtractNpmPackagesFromTree(
                dependencyTree.Roots,
                directPackageIds,
                integrityLookup);

            packages.AddRange(transitivePackages);
            AnsiConsole.MarkupLine($"[dim]Including {transitivePackages.Count} transitive npm packages[/]");
        }

        return packages;
    }

    /// <summary>
    /// Collect transitive package IDs from the dependency tree, excluding direct packages.
    /// </summary>
    private static void CollectTransitivePackageIds(
        List<DependencyTreeNode> roots,
        HashSet<string> excludePackageIds,
        HashSet<string> transitiveIds)
    {
        var visited = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        void Visit(DependencyTreeNode node)
        {
            var key = $"{node.PackageId}@{node.Version}";
            if (!visited.Add(key)) return;

            if (!excludePackageIds.Contains(node.PackageId))
            {
                transitiveIds.Add(node.PackageId);
            }

            foreach (var child in node.Children)
            {
                Visit(child);
            }
        }

        foreach (var root in roots) Visit(root);
    }

    /// <summary>
    /// Walk the dependency tree and create PackageHealth entries for transitive npm packages.
    /// Simplified for SBOM: identity, version, license, ecosystem, integrity.
    /// </summary>
    private static List<PackageHealth> ExtractNpmPackagesFromTree(
        List<DependencyTreeNode> roots,
        HashSet<string> excludePackageIds,
        Dictionary<string, string> integrityLookup)
    {
        var packages = new List<PackageHealth>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        void Visit(DependencyTreeNode node)
        {
            var key = $"{node.PackageId}@{node.Version}";
            if (!seen.Add(key)) return;

            if (!excludePackageIds.Contains(node.PackageId))
            {
                var pkg = new PackageHealth
                {
                    PackageId = node.PackageId,
                    Version = node.Version,
                    Score = node.HealthScore ?? 50,
                    Status = node.Status ?? HealthStatus.Watch,
                    Metrics = new PackageMetrics(),
                    License = node.License,
                    DependencyType = DependencyType.Transitive,
                    Ecosystem = node.Ecosystem,
                    Authors = ExtractNpmScopeAuthor(node.PackageId)
                };

                if (integrityLookup.TryGetValue(node.PackageId, out var integrity))
                    pkg.ContentIntegrity = integrity;

                packages.Add(pkg);
            }

            foreach (var child in node.Children)
            {
                Visit(child);
            }
        }

        foreach (var root in roots) Visit(root);

        return packages;
    }

    private static List<string> ExtractNpmScopeAuthor(string packageId)
    {
        if (packageId.StartsWith('@') && packageId.Contains('/'))
        {
            var scope = packageId[1..packageId.IndexOf('/')];
            return [scope];
        }
        return [];
    }
}
