using System.CommandLine;
using NuGetHealthAnalyzer.Compliance;
using NuGetHealthAnalyzer.DataSources;
using NuGetHealthAnalyzer.Models;
using NuGetHealthAnalyzer.Scoring;
using Spectre.Console;

namespace NuGetHealthAnalyzer.Commands;

public static class CraReportCommand
{
    public static Command Create()
    {
        var pathArg = new Argument<string?>(
            "path",
            () => ".",
            "Path to project, solution, or directory");

        var formatOption = new Option<CraOutputFormat>(
            ["--format", "-f"],
            () => CraOutputFormat.Html,
            "Output format (html or json)");

        var outputOption = new Option<string?>(
            ["--output", "-o"],
            "Output file path (default: cra-report.html or cra-report.json)");

        var skipGitHubOption = new Option<bool>(
            ["--skip-github"],
            "Skip GitHub API calls (faster, but vulnerability data will be incomplete)");

        var deepOption = new Option<bool>(
            ["--deep", "-d"],
            "Fetch full metadata for all transitive packages (slower, but complete health scores)");

        var command = new Command("cra-report", "Generate comprehensive CRA compliance report")
        {
            pathArg,
            formatOption,
            outputOption,
            skipGitHubOption,
            deepOption
        };

        command.SetHandler(ExecuteAsync, pathArg, formatOption, outputOption, skipGitHubOption, deepOption);

        return command;
    }

    private static ProjectType DetectProjectType(string path)
    {
        var hasNetProjects = NuGetApiClient.FindProjectFiles(path).Any();
        var hasPackageJson = NpmApiClient.FindPackageJsonFiles(path).Any();

        return (hasNetProjects, hasPackageJson) switch
        {
            (true, true) => ProjectType.Mixed,
            (true, false) => ProjectType.DotNet,
            (false, true) => ProjectType.Npm,
            _ => throw new InvalidOperationException("No project files found")
        };
    }

    private static async Task<int> ExecuteAsync(string? path, CraOutputFormat format, string? outputPath, bool skipGitHub, bool deepScan)
    {
        path = string.IsNullOrEmpty(path) ? Directory.GetCurrentDirectory() : Path.GetFullPath(path);

        if (!File.Exists(path) && !Directory.Exists(path))
        {
            AnsiConsole.MarkupLine($"[red]Path not found: {path}[/]");
            return 1;
        }

        // Detect project type
        ProjectType projectType;
        try
        {
            projectType = DetectProjectType(path);
        }
        catch (InvalidOperationException)
        {
            AnsiConsole.MarkupLine("[yellow]No project files found (no .csproj/.sln or package.json).[/]");
            return 0;
        }

        AnsiConsole.MarkupLine($"[dim]Detected project type: {projectType}[/]");
        if (deepScan)
        {
            AnsiConsole.MarkupLine("[dim]Deep scan enabled - fetching full metadata for all packages[/]");
        }

        // Process based on project type
        return projectType switch
        {
            ProjectType.Npm => await ExecuteNpmAsync(path, format, outputPath, skipGitHub, deepScan),
            ProjectType.DotNet => await ExecuteDotNetAsync(path, format, outputPath, skipGitHub, deepScan),
            ProjectType.Mixed => await ExecuteMixedAsync(path, format, outputPath, skipGitHub, deepScan),
            _ => 0
        };
    }

    private static async Task<int> ExecuteNpmAsync(string path, CraOutputFormat format, string? outputPath, bool skipGitHub, bool deepScan)
    {
        var packageJsonFiles = NpmApiClient.FindPackageJsonFiles(path).ToList();
        if (packageJsonFiles.Count == 0)
        {
            AnsiConsole.MarkupLine("[yellow]No package.json files found.[/]");
            return 0;
        }

        // Use first package.json found
        var packageJsonPath = packageJsonFiles[0];
        AnsiConsole.MarkupLine($"[dim]Using: {packageJsonPath}[/]");

        using var npmClient = new NpmApiClient();
        var githubClient = skipGitHub ? null : new GitHubApiClient();
        var calculator = new HealthScoreCalculator();

        // Show GitHub status
        ShowGitHubStatus(githubClient, skipGitHub);

        // Parse package.json
        var packageJson = await NpmApiClient.ParsePackageJsonAsync(packageJsonPath);
        if (packageJson is null)
        {
            AnsiConsole.MarkupLine("[red]Failed to parse package.json[/]");
            return 1;
        }

        var allDeps = packageJson.Dependencies
            .Concat(packageJson.DevDependencies)
            .ToDictionary(kv => kv.Key, kv => kv.Value, StringComparer.OrdinalIgnoreCase);

        if (allDeps.Count == 0)
        {
            AnsiConsole.MarkupLine("[yellow]No dependencies found in package.json[/]");
            return 0;
        }

        AnsiConsole.MarkupLine($"[dim]Found {packageJson.Dependencies.Count} dependencies and {packageJson.DevDependencies.Count} dev dependencies[/]");

        // Build dependency tree
        DependencyTree? dependencyTree = null;
        await AnsiConsole.Status()
            .StartAsync("Building dependency tree...", async _ =>
            {
                dependencyTree = await npmClient.BuildDependencyTreeAsync(packageJsonPath, maxDepth: 10);
            });

        // Collect transitive package IDs from tree for vulnerability scanning
        var directPackageIds = new HashSet<string>(allDeps.Keys, StringComparer.OrdinalIgnoreCase);
        var transitiveNpmPackageIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (dependencyTree is not null)
        {
            CollectTransitivePackageIds(dependencyTree.Roots, directPackageIds, transitiveNpmPackageIds);
        }

        // Phase 1: Fetch npm info for direct packages (and transitive if deep scan)
        var npmInfoMap = new Dictionary<string, NpmPackageInfo>(StringComparer.OrdinalIgnoreCase);
        var packagesToFetch = deepScan
            ? allDeps.Keys.Concat(transitiveNpmPackageIds).Distinct(StringComparer.OrdinalIgnoreCase).ToList()
            : allDeps.Keys.ToList();

        await AnsiConsole.Progress()
            .StartAsync(async ctx =>
            {
                var task = ctx.AddTask($"Fetching npm info for {packagesToFetch.Count} packages", maxValue: packagesToFetch.Count);

                foreach (var packageName in packagesToFetch)
                {
                    task.Description = $"npm: {packageName}";
                    var info = await npmClient.GetPackageInfoAsync(packageName);
                    if (info is not null)
                    {
                        npmInfoMap[packageName] = info;
                    }
                    task.Increment(1);
                }
            });

        // Phase 2: Fetch vulnerabilities from OSV (free, no auth required) and GitHub repo info
        var repoInfoMap = new Dictionary<string, GitHubRepoInfo?>(StringComparer.OrdinalIgnoreCase);
        var allVulnerabilities = new Dictionary<string, List<VulnerabilityInfo>>(StringComparer.OrdinalIgnoreCase);
        var allNpmPackageIds = allDeps.Keys.Concat(transitiveNpmPackageIds).Distinct(StringComparer.OrdinalIgnoreCase).ToList();

        // Fetch vulnerabilities from OSV (always available, no auth)
        using var osvClient = new OsvApiClient();
        await AnsiConsole.Status()
            .StartAsync($"Checking vulnerabilities via OSV ({allNpmPackageIds.Count} packages)...", async _ =>
            {
                var vulns = await osvClient.QueryNpmPackagesAsync(allNpmPackageIds);
                foreach (var (name, v) in vulns)
                {
                    allVulnerabilities[name] = v;
                }
            });

        // Optionally fetch GitHub repo info (for stars, commits, etc.)
        if (githubClient is not null && !githubClient.IsRateLimited)
        {
            await FetchGitHubRepoInfoAsync(
                githubClient,
                npmInfoMap.Values.Select(n => n.RepositoryUrl).Where(u => u is not null).ToList()!,
                npmInfoMap,
                repoInfoMap);
        }

        // Phase 3: Calculate health scores
        var packages = new List<PackageHealth>();

        foreach (var (packageName, versionRange) in allDeps)
        {
            if (!npmInfoMap.TryGetValue(packageName, out var npmInfo))
                continue;

            repoInfoMap.TryGetValue(packageName, out var repoInfo);
            var vulnerabilities = allVulnerabilities.GetValueOrDefault(packageName, []);

            var health = calculator.Calculate(
                packageName,
                npmInfo.LatestVersion,
                npmInfo,
                repoInfo,
                vulnerabilities);

            packages.Add(health);

            // Update tree node with health data
            UpdateTreeNodeHealth(dependencyTree, packageName, health.Score, health.Status);
        }

        // Update tree with transitive vulnerability info
        if (dependencyTree is not null)
        {
            UpdateTreeVulnerabilities(dependencyTree.Roots, allVulnerabilities);
            PropagateVulnerabilityStatus(dependencyTree.Roots);
            dependencyTree.VulnerableCount = CountVulnerableNodes(dependencyTree.Roots);
            DetectVersionConflicts(dependencyTree);
        }

        // Create health entries for transitive npm packages
        var transitivePackages = new List<PackageHealth>();
        if (dependencyTree is not null)
        {
            if (deepScan)
            {
                // Deep scan: calculate full health scores for transitive packages
                var transitiveFromTree = ExtractTransitivePackagesWithFullHealth(
                    dependencyTree.Roots, directPackageIds, allVulnerabilities,
                    npmInfoMap, repoInfoMap, calculator);
                transitivePackages.AddRange(transitiveFromTree);
                AnsiConsole.MarkupLine($"[dim]Including {transitivePackages.Count} transitive npm packages with full health data[/]");
            }
            else
            {
                // Minimal scan: only CRA scores (no full health metrics)
                var transitiveFromTree = ExtractTransitivePackagesFromTree(dependencyTree.Roots, directPackageIds, allVulnerabilities);
                transitivePackages.AddRange(transitiveFromTree);
                AnsiConsole.MarkupLine($"[dim]Including {transitivePackages.Count} transitive npm packages in SBOM[/]");
            }
        }

        return await GenerateReportAsync(
            path,
            packages,
            transitivePackages,
            allVulnerabilities,
            dependencyTree,
            format,
            outputPath,
            false,
            false);
    }

    private static List<PackageHealth> ExtractTransitivePackagesFromTree(
        List<DependencyTreeNode> roots,
        HashSet<string> excludePackageIds)
    {
        return ExtractTransitivePackagesFromTree(roots, excludePackageIds, new Dictionary<string, List<VulnerabilityInfo>>());
    }

    private static List<PackageHealth> ExtractTransitivePackagesFromTree(
        List<DependencyTreeNode> roots,
        HashSet<string> excludePackageIds,
        Dictionary<string, List<VulnerabilityInfo>> vulnerabilities)
    {
        var packages = new List<PackageHealth>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        void Visit(DependencyTreeNode node)
        {
            var key = $"{node.PackageId}@{node.Version}";
            if (!seen.Add(key)) return;

            // Skip direct packages (already have full health data)
            if (!excludePackageIds.Contains(node.PackageId))
            {
                var pkgVulns = vulnerabilities.GetValueOrDefault(node.PackageId, []);
                var activeVulns = pkgVulns.Where(v => IsVersionActuallyVulnerable(node.Version, [v])).ToList();
                var (craScore, craStatus) = CalculateTransitiveCraScore(activeVulns, node.License, node.PackageId, node.Version);

                packages.Add(new PackageHealth
                {
                    PackageId = node.PackageId,
                    Version = node.Version,
                    Score = node.HealthScore ?? (activeVulns.Count > 0 ? 30 : 50),
                    Status = node.Status ?? (activeVulns.Count > 0 ? HealthStatus.Critical : HealthStatus.Watch),
                    CraScore = craScore,
                    CraStatus = craStatus,
                    Metrics = new PackageMetrics { VulnerabilityCount = activeVulns.Count },
                    License = node.License,
                    DependencyType = DependencyType.Transitive,
                    Ecosystem = node.Ecosystem,
                    Vulnerabilities = activeVulns.Select(v => v.Id).ToList()
                });
            }

            foreach (var child in node.Children)
            {
                Visit(child);
            }
        }

        foreach (var root in roots)
        {
            Visit(root);
        }

        return packages;
    }

    /// <summary>
    /// Extract transitive packages from tree with full health data (deep scan mode).
    /// Uses npm info that was fetched during the deep scan to calculate proper health scores.
    /// </summary>
    private static List<PackageHealth> ExtractTransitivePackagesWithFullHealth(
        List<DependencyTreeNode> roots,
        HashSet<string> excludePackageIds,
        Dictionary<string, List<VulnerabilityInfo>> vulnerabilities,
        Dictionary<string, NpmPackageInfo> npmInfoMap,
        Dictionary<string, GitHubRepoInfo?> repoInfoMap,
        HealthScoreCalculator calculator)
    {
        var packages = new List<PackageHealth>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        void Visit(DependencyTreeNode node)
        {
            var key = $"{node.PackageId}@{node.Version}";
            if (!seen.Add(key)) return;

            // Skip direct packages (already have full health data)
            if (!excludePackageIds.Contains(node.PackageId))
            {
                var pkgVulns = vulnerabilities.GetValueOrDefault(node.PackageId, []);
                var activeVulns = pkgVulns.Where(v => IsVersionActuallyVulnerable(node.Version, [v])).ToList();

                // Check if we have npm info for this package (deep scan fetches this)
                if (npmInfoMap.TryGetValue(node.PackageId, out var npmInfo))
                {
                    // Full health calculation using fetched npm data
                    repoInfoMap.TryGetValue(node.PackageId, out var repoInfo);
                    var health = calculator.Calculate(
                        node.PackageId,
                        node.Version,
                        npmInfo,
                        repoInfo,
                        activeVulns,
                        DependencyType.Transitive);

                    // Update tree node with the calculated health
                    node.HealthScore = health.Score;
                    node.Status = health.Status;

                    packages.Add(health);
                }
                else
                {
                    // Fallback: no npm info available - use minimal CRA calculation
                    var (craScore, craStatus) = CalculateTransitiveCraScore(activeVulns, node.License, node.PackageId, node.Version);

                    packages.Add(new PackageHealth
                    {
                        PackageId = node.PackageId,
                        Version = node.Version,
                        Score = activeVulns.Count > 0 ? 30 : 50,
                        Status = activeVulns.Count > 0 ? HealthStatus.Critical : HealthStatus.Watch,
                        CraScore = craScore,
                        CraStatus = craStatus,
                        Metrics = new PackageMetrics { VulnerabilityCount = activeVulns.Count },
                        License = node.License,
                        DependencyType = DependencyType.Transitive,
                        Ecosystem = node.Ecosystem,
                        Vulnerabilities = activeVulns.Select(v => v.Id).ToList()
                    });
                }
            }

            foreach (var child in node.Children)
            {
                Visit(child);
            }
        }

        foreach (var root in roots)
        {
            Visit(root);
        }

        return packages;
    }

    private static void CollectTransitivePackageIds(
        List<DependencyTreeNode> roots,
        HashSet<string> excludePackageIds,
        HashSet<string> transitiveIds)
    {
        void Visit(DependencyTreeNode node)
        {
            if (!excludePackageIds.Contains(node.PackageId))
            {
                transitiveIds.Add(node.PackageId);
            }

            foreach (var child in node.Children)
            {
                Visit(child);
            }
        }

        foreach (var root in roots)
        {
            Visit(root);
        }
    }

    private static void UpdateTreeVulnerabilities(
        List<DependencyTreeNode> roots,
        Dictionary<string, List<VulnerabilityInfo>> vulnerabilities)
    {
        void Visit(DependencyTreeNode node)
        {
            if (vulnerabilities.TryGetValue(node.PackageId, out var vulns) && vulns.Count > 0)
            {
                // Find the first vulnerability that actually affects this version
                var activeVuln = GetFirstActiveVulnerability(node.Version, vulns);
                if (activeVuln is not null)
                {
                    node.HasVulnerabilities = true;
                    node.VulnerabilityUrl = activeVuln.Url ?? $"https://osv.dev/vulnerability/{activeVuln.Id}";
                    node.VulnerabilitySummary = !string.IsNullOrWhiteSpace(activeVuln.Summary)
                        ? activeVuln.Summary
                        : activeVuln.Id;
                }
            }

            foreach (var child in node.Children)
            {
                Visit(child);
            }
        }

        foreach (var root in roots)
        {
            Visit(root);
        }
    }

    /// <summary>
    /// Get the first vulnerability that actually affects the given version.
    /// </summary>
    private static VulnerabilityInfo? GetFirstActiveVulnerability(string version, List<VulnerabilityInfo> vulnerabilities)
    {
        foreach (var vuln in vulnerabilities)
        {
            // Check if version is patched
            if (!string.IsNullOrEmpty(vuln.PatchedVersion))
            {
                try
                {
                    var current = NuGet.Versioning.NuGetVersion.Parse(version);
                    var patched = NuGet.Versioning.NuGetVersion.Parse(vuln.PatchedVersion);
                    if (current >= patched)
                    {
                        continue; // Patched, check next vulnerability
                    }
                }
                catch { /* Version parsing failed, check range */ }
            }

            // Check if version is in vulnerable range
            if (!string.IsNullOrEmpty(vuln.VulnerableVersionRange))
            {
                if (IsVersionInVulnerableRange(version, vuln.VulnerableVersionRange))
                {
                    return vuln; // Actually vulnerable
                }
            }
            else
            {
                // No range specified, conservatively return this vulnerability
                return vuln;
            }
        }

        return null;
    }

    /// <summary>
    /// Check if a specific version is actually affected by any of the vulnerabilities.
    /// Returns true only if the version is in a vulnerable range and NOT patched.
    /// </summary>
    private static bool IsVersionActuallyVulnerable(string version, List<VulnerabilityInfo> vulnerabilities)
    {
        foreach (var vuln in vulnerabilities)
        {
            // Check if version is patched
            if (!string.IsNullOrEmpty(vuln.PatchedVersion))
            {
                try
                {
                    var current = NuGet.Versioning.NuGetVersion.Parse(version);
                    var patched = NuGet.Versioning.NuGetVersion.Parse(vuln.PatchedVersion);
                    if (current >= patched)
                    {
                        // This vulnerability is patched in the current version
                        continue;
                    }
                }
                catch
                {
                    // Version parsing failed, check range instead
                }
            }

            // Check if version is in vulnerable range
            if (!string.IsNullOrEmpty(vuln.VulnerableVersionRange))
            {
                if (IsVersionInVulnerableRange(version, vuln.VulnerableVersionRange))
                {
                    return true; // Actually vulnerable
                }
            }
            else
            {
                // No range specified but has vulnerability - conservatively mark as vulnerable
                return true;
            }
        }

        return false; // All vulnerabilities are patched or don't affect this version
    }

    private static bool IsVersionInVulnerableRange(string version, string range)
    {
        try
        {
            var current = NuGet.Versioning.NuGetVersion.Parse(version);
            var parts = range.Split(',').Select(p => p.Trim()).ToArray();

            // Track whether we have any range constraints
            bool hasRangeConstraint = false;
            bool hasExactMatch = false;

            foreach (var part in parts)
            {
                if (part.StartsWith(">="))
                {
                    hasRangeConstraint = true;
                    var v = NuGet.Versioning.NuGetVersion.Parse(part[2..].Trim());
                    if (current < v) return false;
                }
                else if (part.StartsWith(">"))
                {
                    hasRangeConstraint = true;
                    var v = NuGet.Versioning.NuGetVersion.Parse(part[1..].Trim());
                    if (current <= v) return false;
                }
                else if (part.StartsWith("<="))
                {
                    hasRangeConstraint = true;
                    var v = NuGet.Versioning.NuGetVersion.Parse(part[2..].Trim());
                    if (current > v) return false;
                }
                else if (part.StartsWith("<"))
                {
                    hasRangeConstraint = true;
                    var v = NuGet.Versioning.NuGetVersion.Parse(part[1..].Trim());
                    if (current >= v) return false;
                }
                else if (!string.IsNullOrWhiteSpace(part))
                {
                    // Exact version match (e.g., "4.4.2" from OSV's versions list)
                    try
                    {
                        var v = NuGet.Versioning.NuGetVersion.Parse(part);
                        if (current == v)
                        {
                            hasExactMatch = true;
                        }
                    }
                    catch
                    {
                        // Not a parseable version, ignore
                    }
                }
            }

            // If we only have exact version matches, check if current matches any
            if (!hasRangeConstraint)
            {
                return hasExactMatch;
            }

            // Range constraints passed
            return true;
        }
        catch
        {
            // If we can't parse, assume affected (conservative for security)
            // May result in false positives - user should verify
            return true;
        }
    }

    /// <summary>
    /// Calculate CRA compliance score for transitive packages.
    /// Same logic as HealthScoreCalculator but simplified for packages without full metadata.
    /// </summary>
    private static (int Score, CraComplianceStatus Status) CalculateTransitiveCraScore(
        List<VulnerabilityInfo> vulnerabilities,
        string? license,
        string packageId,
        string version)
    {
        var score = 0;

        // Vulnerability assessment (60 points max)
        var criticalVulns = vulnerabilities.Count(v =>
            v.Severity?.Equals("CRITICAL", StringComparison.OrdinalIgnoreCase) == true);
        var highVulns = vulnerabilities.Count(v =>
            v.Severity?.Equals("HIGH", StringComparison.OrdinalIgnoreCase) == true);

        if (vulnerabilities.Count == 0)
        {
            score += 60;
        }
        else if (criticalVulns > 0)
        {
            score += 0;
        }
        else if (highVulns > 0)
        {
            score += 15;
        }
        else
        {
            score += 30;
        }

        // License identification (25 points max)
        if (!string.IsNullOrWhiteSpace(license))
        {
            var normalizedLicense = license.Trim().ToUpperInvariant();
            if (IsKnownSpdxLicense(normalizedLicense))
            {
                score += 25;
            }
            else
            {
                score += 15;
            }
        }

        // Package identifiability (15 points max)
        if (!string.IsNullOrWhiteSpace(packageId) && !string.IsNullOrWhiteSpace(version))
        {
            score += 15;
        }
        else if (!string.IsNullOrWhiteSpace(packageId))
        {
            score += 10;
        }

        var status = (score, criticalVulns, highVulns) switch
        {
            ( >= 90, 0, 0) => CraComplianceStatus.Compliant,
            ( >= 70, 0, _) => CraComplianceStatus.Review,
            (_, > 0, _) => CraComplianceStatus.NonCompliant,
            (_, _, > 0) => CraComplianceStatus.ActionRequired,
            ( < 50, _, _) => CraComplianceStatus.NonCompliant,
            _ => CraComplianceStatus.ActionRequired
        };

        return (score, status);
    }

    private static bool IsKnownSpdxLicense(string license)
    {
        return license switch
        {
            "MIT" or "MIT-0" => true,
            "APACHE-2.0" or "APACHE 2.0" or "APACHE2" => true,
            "BSD-2-CLAUSE" or "BSD-3-CLAUSE" or "0BSD" => true,
            "ISC" => true,
            "GPL-2.0" or "GPL-3.0" or "GPL-2.0-ONLY" or "GPL-3.0-ONLY" => true,
            "LGPL-2.1" or "LGPL-3.0" or "LGPL-2.1-ONLY" or "LGPL-3.0-ONLY" => true,
            "MPL-2.0" => true,
            "UNLICENSE" or "UNLICENSED" => true,
            "CC0-1.0" or "CC-BY-4.0" => true,
            "BSL-1.0" => true,
            "WTFPL" => true,
            "ZLIB" => true,
            "MS-PL" or "MS-RL" => true,
            _ => false
        };
    }

    private static async Task<int> ExecuteDotNetAsync(string path, CraOutputFormat format, string? outputPath, bool skipGitHub, bool deepScan)
    {
        var projectFiles = NuGetApiClient.FindProjectFiles(path).ToList();
        if (projectFiles.Count == 0)
        {
            AnsiConsole.MarkupLine("[yellow]No project files found.[/]");
            return 0;
        }

        using var nugetClient = new NuGetApiClient();
        var githubClient = skipGitHub ? null : new GitHubApiClient();
        var calculator = new HealthScoreCalculator();

        // Show GitHub status
        ShowGitHubStatus(githubClient, skipGitHub);

        // Collect all package references using dotnet list package for resolved versions
        var allReferences = new Dictionary<string, PackageReference>(StringComparer.OrdinalIgnoreCase);
        var transitiveReferences = new Dictionary<string, PackageReference>(StringComparer.OrdinalIgnoreCase);
        var usedFallbackParsing = false;
        var hasUnresolvedVersions = false;

        await AnsiConsole.Status()
            .StartAsync("Scanning packages (resolving MSBuild variables)...", async ctx =>
            {
                // Try dotnet list package first for resolved versions
                var (topLevel, transitive) = await NuGetApiClient.ParsePackagesWithDotnetAsync(path);

                if (topLevel.Count > 0)
                {
                    foreach (var r in topLevel)
                    {
                        if (!allReferences.ContainsKey(r.PackageId))
                        {
                            allReferences[r.PackageId] = r;
                            if (r.Version.Contains("$(")) hasUnresolvedVersions = true;
                        }
                    }
                    foreach (var r in transitive)
                    {
                        if (!transitiveReferences.ContainsKey(r.PackageId) && !allReferences.ContainsKey(r.PackageId))
                        {
                            transitiveReferences[r.PackageId] = r;
                        }
                    }
                }
                else
                {
                    // Fall back to XML parsing if dotnet command fails
                    usedFallbackParsing = true;
                    ctx.Status("Falling back to XML parsing...");
                    foreach (var projectFile in projectFiles)
                    {
                        var refs = await NuGetApiClient.ParseProjectFileAsync(projectFile);
                        foreach (var r in refs)
                        {
                            if (!allReferences.ContainsKey(r.PackageId))
                            {
                                allReferences[r.PackageId] = r;
                                if (r.Version.Contains("$(")) hasUnresolvedVersions = true;
                            }
                        }
                    }
                }
            });

        if (allReferences.Count == 0)
        {
            AnsiConsole.MarkupLine("[yellow]No package references found.[/]");
            return 0;
        }

        AnsiConsole.MarkupLine($"[dim]Found {allReferences.Count} direct packages and {transitiveReferences.Count} transitive dependencies[/]");

        // Warn about incomplete transitive dependencies
        var incompleteTransitive = usedFallbackParsing || transitiveReferences.Count == 0;
        if (incompleteTransitive || hasUnresolvedVersions)
        {
            AnsiConsole.WriteLine();
            AnsiConsole.MarkupLine("[yellow]⚠ SBOM Completeness Warning:[/]");
            if (incompleteTransitive)
            {
                AnsiConsole.MarkupLine("[dim]  Transitive dependencies could not be fully resolved.[/]");
            }
            if (hasUnresolvedVersions)
            {
                AnsiConsole.MarkupLine("[dim]  Some package versions contain unresolved MSBuild variables.[/]");
            }
            AnsiConsole.MarkupLine("[dim]  For complete CRA compliance, run:[/]");
            AnsiConsole.MarkupLine("[blue]    dotnet restore[/]");
            AnsiConsole.MarkupLine("[dim]  before generating the report.[/]");
            AnsiConsole.WriteLine();
        }

        // Phase 1: Fetch all NuGet info (including transitive)
        var nugetInfoMap = new Dictionary<string, NuGetPackageInfo>(StringComparer.OrdinalIgnoreCase);
        var allPackageIds = allReferences.Keys.Concat(transitiveReferences.Keys).Distinct(StringComparer.OrdinalIgnoreCase).ToList();

        await AnsiConsole.Progress()
            .StartAsync(async ctx =>
            {
                var task = ctx.AddTask($"Fetching NuGet info for {allPackageIds.Count} packages", maxValue: allPackageIds.Count);

                foreach (var packageId in allPackageIds)
                {
                    task.Description = $"NuGet: {packageId}";
                    var info = await nugetClient.GetPackageInfoAsync(packageId);
                    if (info is not null)
                    {
                        nugetInfoMap[packageId] = info;
                    }
                    task.Increment(1);
                }
            });

        // Phase 1b: Collect and fetch dependencies of packages (for drill-down navigation)
        var dependencyPackageIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var info in nugetInfoMap.Values)
        {
            foreach (var dep in info.Dependencies)
            {
                // Only add if not already a direct or transitive package
                if (!allReferences.ContainsKey(dep.PackageId) && !transitiveReferences.ContainsKey(dep.PackageId))
                {
                    dependencyPackageIds.Add(dep.PackageId);
                }
            }
        }

        if (dependencyPackageIds.Count > 0)
        {
            await AnsiConsole.Progress()
                .StartAsync(async ctx =>
                {
                    var task = ctx.AddTask($"Fetching NuGet info for {dependencyPackageIds.Count} package dependencies", maxValue: dependencyPackageIds.Count);

                    foreach (var packageId in dependencyPackageIds)
                    {
                        task.Description = $"Dependency: {packageId}";
                        if (!nugetInfoMap.ContainsKey(packageId))
                        {
                            var info = await nugetClient.GetPackageInfoAsync(packageId);
                            if (info is not null)
                            {
                                nugetInfoMap[packageId] = info;
                            }
                        }
                        task.Increment(1);
                    }
                });
        }

        // Phase 2: Batch fetch GitHub repo info (if not skipped)
        var repoInfoMap = new Dictionary<string, GitHubRepoInfo?>(StringComparer.OrdinalIgnoreCase);
        var allVulnerabilities = new Dictionary<string, List<VulnerabilityInfo>>(StringComparer.OrdinalIgnoreCase);

        // Include dependency packages in the list for GitHub lookups
        var allPackageIdsWithDeps = allPackageIds.Concat(dependencyPackageIds).Distinct(StringComparer.OrdinalIgnoreCase).ToList();

        if (githubClient is not null && !githubClient.IsRateLimited)
        {
            await AnsiConsole.Status()
                .StartAsync("Fetching GitHub repository info (batch)...", async ctx =>
                {
                    var repoUrls = nugetInfoMap.Values
                        .Select(n => n.RepositoryUrl ?? n.ProjectUrl)
                        .Where(u => u?.Contains("github.com", StringComparison.OrdinalIgnoreCase) == true)
                        .ToList();

                    if (repoUrls.Count > 0)
                    {
                        var results = await githubClient.GetRepositoriesBatchAsync(repoUrls!);

                        foreach (var (packageId, info) in nugetInfoMap)
                        {
                            var url = info.RepositoryUrl ?? info.ProjectUrl;
                            if (url is not null && results.TryGetValue(url, out var repoInfo))
                            {
                                repoInfoMap[packageId] = repoInfo;
                            }
                        }
                    }

                    if (githubClient.IsRateLimited)
                    {
                        ctx.Status("[yellow]GitHub rate limited - continuing with available data[/]");
                    }
                });

            // Phase 3: Batch fetch vulnerabilities (including transitive and dependencies)
            if (!githubClient.IsRateLimited && githubClient.HasToken)
            {
                await AnsiConsole.Status()
                    .StartAsync("Checking vulnerabilities (batch)...", async ctx =>
                    {
                        allVulnerabilities = await githubClient.GetVulnerabilitiesBatchAsync(allPackageIdsWithDeps);

                        if (githubClient.IsRateLimited)
                        {
                            ctx.Status("[yellow]GitHub rate limited - vulnerability data may be incomplete[/]");
                        }
                    });
            }
        }

        // Phase 4: Calculate health scores for direct packages
        var packages = new List<PackageHealth>();
        var transitivePackages = new List<PackageHealth>();

        foreach (var (packageId, reference) in allReferences)
        {
            if (!nugetInfoMap.TryGetValue(packageId, out var nugetInfo))
                continue;

            repoInfoMap.TryGetValue(packageId, out var repoInfo);
            var vulnerabilities = allVulnerabilities.GetValueOrDefault(packageId, []);

            var health = calculator.Calculate(
                packageId,
                reference.Version,
                nugetInfo,
                repoInfo,
                vulnerabilities);

            packages.Add(health);
        }

        // Calculate health scores for transitive packages
        foreach (var (packageId, reference) in transitiveReferences)
        {
            if (!nugetInfoMap.TryGetValue(packageId, out var nugetInfo))
                continue;

            repoInfoMap.TryGetValue(packageId, out var repoInfo);
            var vulnerabilities = allVulnerabilities.GetValueOrDefault(packageId, []);

            var health = calculator.Calculate(
                packageId,
                reference.Version,
                nugetInfo,
                repoInfo,
                vulnerabilities,
                DependencyType.Transitive);

            transitivePackages.Add(health);
        }

        // Calculate health scores for package dependencies (sub-dependencies for drill-down navigation)
        foreach (var packageId in dependencyPackageIds)
        {
            // Skip if already in transitive list
            if (transitivePackages.Any(p => p.PackageId.Equals(packageId, StringComparison.OrdinalIgnoreCase)))
                continue;

            if (!nugetInfoMap.TryGetValue(packageId, out var nugetInfo))
                continue;

            repoInfoMap.TryGetValue(packageId, out var repoInfo);
            var vulnerabilities = allVulnerabilities.GetValueOrDefault(packageId, []);

            var health = calculator.Calculate(
                packageId,
                nugetInfo.LatestVersion, // Use latest version since we don't have a specific version reference
                nugetInfo,
                repoInfo,
                vulnerabilities,
                DependencyType.SubDependency);

            transitivePackages.Add(health);
        }

        // Build dependency tree for .NET
        var dependencyTree = BuildDotNetDependencyTree(
            path,
            allReferences,
            transitiveReferences,
            packages,
            transitivePackages,
            allVulnerabilities);

        return await GenerateReportAsync(
            path,
            packages,
            transitivePackages,
            allVulnerabilities,
            dependencyTree,
            format,
            outputPath,
            incompleteTransitive,
            hasUnresolvedVersions);
    }

    private static async Task<int> ExecuteMixedAsync(string path, CraOutputFormat format, string? outputPath, bool skipGitHub, bool deepScan)
    {
        AnsiConsole.MarkupLine("[dim]Mixed project detected - analyzing both .NET and npm components[/]");

        using var nugetClient = new NuGetApiClient();
        using var npmClient = new NpmApiClient();
        var githubClient = skipGitHub ? null : new GitHubApiClient();
        var calculator = new HealthScoreCalculator();

        ShowGitHubStatus(githubClient, skipGitHub);

        var allPackages = new List<PackageHealth>();
        var allTransitivePackages = new List<PackageHealth>();
        var allVulnerabilities = new Dictionary<string, List<VulnerabilityInfo>>(StringComparer.OrdinalIgnoreCase);
        var dependencyTrees = new List<DependencyTree>();
        var incompleteTransitive = false;
        var hasUnresolvedVersions = false;

        // ===== Analyze .NET packages =====
        AnsiConsole.MarkupLine("\n[bold blue]Analyzing .NET packages...[/]");

        var projectFiles = NuGetApiClient.FindProjectFiles(path).ToList();
        if (projectFiles.Count > 0)
        {
            var allReferences = new Dictionary<string, PackageReference>(StringComparer.OrdinalIgnoreCase);
            var transitiveReferences = new Dictionary<string, PackageReference>(StringComparer.OrdinalIgnoreCase);
            var usedFallbackParsing = false;

            await AnsiConsole.Status()
                .StartAsync("Scanning .NET packages...", async ctx =>
                {
                    var (topLevel, transitive) = await NuGetApiClient.ParsePackagesWithDotnetAsync(path);

                    if (topLevel.Count > 0)
                    {
                        foreach (var r in topLevel)
                        {
                            if (!allReferences.ContainsKey(r.PackageId))
                            {
                                allReferences[r.PackageId] = r;
                                if (r.Version.Contains("$(")) hasUnresolvedVersions = true;
                            }
                        }
                        foreach (var r in transitive)
                        {
                            if (!transitiveReferences.ContainsKey(r.PackageId) && !allReferences.ContainsKey(r.PackageId))
                            {
                                transitiveReferences[r.PackageId] = r;
                            }
                        }
                    }
                    else
                    {
                        usedFallbackParsing = true;
                        ctx.Status("Falling back to XML parsing...");
                        foreach (var projectFile in projectFiles)
                        {
                            var refs = await NuGetApiClient.ParseProjectFileAsync(projectFile);
                            foreach (var r in refs)
                            {
                                if (!allReferences.ContainsKey(r.PackageId))
                                {
                                    allReferences[r.PackageId] = r;
                                    if (r.Version.Contains("$(")) hasUnresolvedVersions = true;
                                }
                            }
                        }
                    }
                });

            incompleteTransitive = usedFallbackParsing || transitiveReferences.Count == 0;

            if (allReferences.Count > 0)
            {
                AnsiConsole.MarkupLine($"[dim]Found {allReferences.Count} NuGet packages and {transitiveReferences.Count} transitive[/]");

                // Fetch NuGet info
                var nugetInfoMap = new Dictionary<string, NuGetPackageInfo>(StringComparer.OrdinalIgnoreCase);
                var allPackageIds = allReferences.Keys.Concat(transitiveReferences.Keys).Distinct(StringComparer.OrdinalIgnoreCase).ToList();

                await AnsiConsole.Progress()
                    .StartAsync(async ctx =>
                    {
                        var task = ctx.AddTask($"Fetching NuGet info", maxValue: allPackageIds.Count);
                        foreach (var packageId in allPackageIds)
                        {
                            task.Description = $"NuGet: {packageId}";
                            var info = await nugetClient.GetPackageInfoAsync(packageId);
                            if (info is not null) nugetInfoMap[packageId] = info;
                            task.Increment(1);
                        }
                    });

                // Fetch dependencies for drill-down
                var dependencyPackageIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                foreach (var info in nugetInfoMap.Values)
                {
                    foreach (var dep in info.Dependencies)
                    {
                        if (!allReferences.ContainsKey(dep.PackageId) && !transitiveReferences.ContainsKey(dep.PackageId))
                            dependencyPackageIds.Add(dep.PackageId);
                    }
                }

                if (dependencyPackageIds.Count > 0)
                {
                    await AnsiConsole.Progress()
                        .StartAsync(async ctx =>
                        {
                            var task = ctx.AddTask($"Fetching NuGet dependencies", maxValue: dependencyPackageIds.Count);
                            foreach (var packageId in dependencyPackageIds)
                            {
                                if (!nugetInfoMap.ContainsKey(packageId))
                                {
                                    var info = await nugetClient.GetPackageInfoAsync(packageId);
                                    if (info is not null) nugetInfoMap[packageId] = info;
                                }
                                task.Increment(1);
                            }
                        });
                }

                // Check NuGet vulnerabilities via OSV (free, no auth required)
                var nugetRepoInfoMap = new Dictionary<string, GitHubRepoInfo?>(StringComparer.OrdinalIgnoreCase);
                var allNuGetPackageIds = allPackageIds.Concat(dependencyPackageIds).Distinct(StringComparer.OrdinalIgnoreCase).ToList();

                using var osvNuGetClient = new OsvApiClient();
                await AnsiConsole.Status()
                    .StartAsync($"Checking NuGet vulnerabilities via OSV ({allNuGetPackageIds.Count} packages)...", async _ =>
                    {
                        var vulns = await osvNuGetClient.QueryNuGetPackagesAsync(allNuGetPackageIds);
                        foreach (var (name, v) in vulns)
                            allVulnerabilities[name] = v;
                    });

                // Fetch GitHub repo info for NuGet packages (optional, for stars/commits)
                if (githubClient is not null && !githubClient.IsRateLimited)
                {
                    await AnsiConsole.Status()
                        .StartAsync("Fetching GitHub info for NuGet packages...", async _ =>
                        {
                            var repoUrls = nugetInfoMap.Values
                                .Select(n => n.RepositoryUrl ?? n.ProjectUrl)
                                .Where(u => u?.Contains("github.com", StringComparison.OrdinalIgnoreCase) == true)
                                .ToList();

                            if (repoUrls.Count > 0)
                            {
                                var results = await githubClient.GetRepositoriesBatchAsync(repoUrls!);
                                foreach (var (packageId, info) in nugetInfoMap)
                                {
                                    var url = info.RepositoryUrl ?? info.ProjectUrl;
                                    if (url is not null && results.TryGetValue(url, out var repoInfo))
                                        nugetRepoInfoMap[packageId] = repoInfo;
                                }
                            }
                        });
                }

                // Calculate health for NuGet packages
                foreach (var (packageId, reference) in allReferences)
                {
                    if (!nugetInfoMap.TryGetValue(packageId, out var nugetInfo)) continue;
                    nugetRepoInfoMap.TryGetValue(packageId, out var repoInfo);
                    var vulnerabilities = allVulnerabilities.GetValueOrDefault(packageId, []);
                    allPackages.Add(calculator.Calculate(packageId, reference.Version, nugetInfo, repoInfo, vulnerabilities));
                }

                foreach (var (packageId, reference) in transitiveReferences)
                {
                    if (!nugetInfoMap.TryGetValue(packageId, out var nugetInfo)) continue;
                    nugetRepoInfoMap.TryGetValue(packageId, out var repoInfo);
                    var vulnerabilities = allVulnerabilities.GetValueOrDefault(packageId, []);
                    allTransitivePackages.Add(calculator.Calculate(packageId, reference.Version, nugetInfo, repoInfo, vulnerabilities, DependencyType.Transitive));
                }

                foreach (var packageId in dependencyPackageIds)
                {
                    if (allTransitivePackages.Any(p => p.PackageId.Equals(packageId, StringComparison.OrdinalIgnoreCase))) continue;
                    if (!nugetInfoMap.TryGetValue(packageId, out var nugetInfo)) continue;
                    nugetRepoInfoMap.TryGetValue(packageId, out var repoInfo);
                    var vulnerabilities = allVulnerabilities.GetValueOrDefault(packageId, []);
                    allTransitivePackages.Add(calculator.Calculate(packageId, nugetInfo.LatestVersion, nugetInfo, repoInfo, vulnerabilities, DependencyType.SubDependency));
                }

                // Build .NET dependency tree
                var dotnetTree = BuildDotNetDependencyTree(path, allReferences, transitiveReferences,
                    allPackages.Where(p => allReferences.ContainsKey(p.PackageId)).ToList(),
                    allTransitivePackages, allVulnerabilities);
                dependencyTrees.Add(dotnetTree);
            }
        }

        // ===== Analyze npm packages =====
        AnsiConsole.MarkupLine("\n[bold green]Analyzing npm packages...[/]");

        var packageJsonFiles = NpmApiClient.FindPackageJsonFiles(path).ToList();
        if (packageJsonFiles.Count > 0)
        {
            var packageJsonPath = packageJsonFiles[0];
            AnsiConsole.MarkupLine($"[dim]Using: {packageJsonPath}[/]");

            var packageJson = await NpmApiClient.ParsePackageJsonAsync(packageJsonPath);
            if (packageJson is not null)
            {
                var allDeps = packageJson.Dependencies
                    .Concat(packageJson.DevDependencies)
                    .ToDictionary(kv => kv.Key, kv => kv.Value, StringComparer.OrdinalIgnoreCase);

                if (allDeps.Count > 0)
                {
                    AnsiConsole.MarkupLine($"[dim]Found {packageJson.Dependencies.Count} npm dependencies and {packageJson.DevDependencies.Count} dev dependencies[/]");

                    // Build npm dependency tree
                    DependencyTree? npmTree = null;
                    await AnsiConsole.Status()
                        .StartAsync("Building npm dependency tree...", async _ =>
                        {
                            npmTree = await npmClient.BuildDependencyTreeAsync(packageJsonPath, maxDepth: 10);
                        });

                    // Extract transitive package IDs from tree BEFORE fetching
                    var directNpmPackageIds = new HashSet<string>(allDeps.Keys, StringComparer.OrdinalIgnoreCase);
                    var transitiveNpmPackageIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                    if (npmTree is not null)
                    {
                        CollectTransitivePackageIds(npmTree.Roots, directNpmPackageIds, transitiveNpmPackageIds);
                    }

                    // Fetch npm info (include transitive if deep scan)
                    var npmInfoMap = new Dictionary<string, NpmPackageInfo>(StringComparer.OrdinalIgnoreCase);
                    var npmPackagesToFetch = deepScan
                        ? allDeps.Keys.Concat(transitiveNpmPackageIds).Distinct(StringComparer.OrdinalIgnoreCase).ToList()
                        : allDeps.Keys.ToList();

                    await AnsiConsole.Progress()
                        .StartAsync(async ctx =>
                        {
                            var task = ctx.AddTask($"Fetching npm info for {npmPackagesToFetch.Count} packages", maxValue: npmPackagesToFetch.Count);
                            foreach (var packageName in npmPackagesToFetch)
                            {
                                task.Description = $"npm: {packageName}";
                                var info = await npmClient.GetPackageInfoAsync(packageName);
                                if (info is not null) npmInfoMap[packageName] = info;
                                task.Increment(1);
                            }
                        });

                    // Check npm vulnerabilities via OSV (free, no auth required)
                    var allNpmPackageIds = allDeps.Keys.Concat(transitiveNpmPackageIds).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
                    using var osvNpmClient = new OsvApiClient();
                    await AnsiConsole.Status()
                        .StartAsync($"Checking npm vulnerabilities via OSV ({allNpmPackageIds.Count} packages)...", async _ =>
                        {
                            var vulns = await osvNpmClient.QueryNpmPackagesAsync(allNpmPackageIds);
                            foreach (var (name, v) in vulns)
                            {
                                if (!allVulnerabilities.ContainsKey(name))
                                    allVulnerabilities[name] = v;
                            }
                        });

                    // Fetch GitHub repo info for npm packages (optional, for stars/commits)
                    var npmRepoInfoMap = new Dictionary<string, GitHubRepoInfo?>(StringComparer.OrdinalIgnoreCase);

                    if (githubClient is not null && !githubClient.IsRateLimited)
                    {
                        await AnsiConsole.Status()
                            .StartAsync("Fetching GitHub info for npm packages...", async _ =>
                            {
                                var repoUrls = npmInfoMap.Values
                                    .Select(n => n.RepositoryUrl)
                                    .Where(u => u?.Contains("github.com", StringComparison.OrdinalIgnoreCase) == true)
                                    .ToList();

                                if (repoUrls.Count > 0)
                                {
                                    var results = await githubClient.GetRepositoriesBatchAsync(repoUrls!);
                                    foreach (var (packageName, info) in npmInfoMap)
                                    {
                                        if (info.RepositoryUrl is not null && results.TryGetValue(info.RepositoryUrl, out var repoInfo))
                                            npmRepoInfoMap[packageName] = repoInfo;
                                    }
                                }
                            });
                    }

                    // Calculate health for npm packages
                    foreach (var (packageName, _) in allDeps)
                    {
                        if (!npmInfoMap.TryGetValue(packageName, out var npmInfo)) continue;
                        npmRepoInfoMap.TryGetValue(packageName, out var repoInfo);
                        var vulnerabilities = allVulnerabilities.GetValueOrDefault(packageName, []);

                        var health = calculator.Calculate(packageName, npmInfo.LatestVersion, npmInfo, repoInfo, vulnerabilities);
                        allPackages.Add(health);

                        UpdateTreeNodeHealth(npmTree, packageName, health.Score, health.Status);
                    }

                    if (npmTree is not null)
                    {
                        // Update tree nodes with vulnerability info for transitives
                        UpdateTreeVulnerabilities(npmTree.Roots, allVulnerabilities);
                        PropagateVulnerabilityStatus(npmTree.Roots);
                        npmTree.VulnerableCount = CountVulnerableNodes(npmTree.Roots);
                        DetectVersionConflicts(npmTree);
                        dependencyTrees.Add(npmTree);

                        // Extract npm transitive packages from tree for SBOM
                        if (deepScan)
                        {
                            // Deep scan: calculate full health scores for transitive packages
                            var npmTransitiveFromTree = ExtractTransitivePackagesWithFullHealth(
                                npmTree.Roots, directNpmPackageIds, allVulnerabilities,
                                npmInfoMap, npmRepoInfoMap, calculator);
                            allTransitivePackages.AddRange(npmTransitiveFromTree);
                            AnsiConsole.MarkupLine($"[dim]Including {npmTransitiveFromTree.Count} transitive npm packages with full health data[/]");
                        }
                        else
                        {
                            // Minimal scan: only CRA scores (no full health metrics)
                            var npmTransitiveFromTree = ExtractTransitivePackagesFromTree(npmTree.Roots, directNpmPackageIds, allVulnerabilities);
                            allTransitivePackages.AddRange(npmTransitiveFromTree);
                            AnsiConsole.MarkupLine($"[dim]Including {npmTransitiveFromTree.Count} transitive npm packages in SBOM[/]");
                        }
                    }
                }
            }
        }

        if (allPackages.Count == 0)
        {
            AnsiConsole.MarkupLine("[yellow]No packages found.[/]");
            return 0;
        }

        return await GenerateMixedReportAsync(
            path,
            allPackages,
            allTransitivePackages,
            allVulnerabilities,
            dependencyTrees,
            format,
            outputPath,
            incompleteTransitive,
            hasUnresolvedVersions);
    }

    private static async Task<int> GenerateMixedReportAsync(
        string path,
        List<PackageHealth> packages,
        List<PackageHealth> transitivePackages,
        Dictionary<string, List<VulnerabilityInfo>> allVulnerabilities,
        List<DependencyTree> dependencyTrees,
        CraOutputFormat format,
        string? outputPath,
        bool incompleteTransitive,
        bool hasUnresolvedVersions)
    {
        var projectScore = HealthScoreCalculator.CalculateProjectScore(packages);
        var projectStatus = projectScore switch
        {
            >= 80 => HealthStatus.Healthy,
            >= 60 => HealthStatus.Watch,
            >= 40 => HealthStatus.Warning,
            _ => HealthStatus.Critical
        };

        var healthReport = new ProjectReport
        {
            ProjectPath = path,
            GeneratedAt = DateTime.UtcNow,
            OverallScore = projectScore,
            OverallStatus = projectStatus,
            Packages = packages.OrderBy(p => p.Score).ToList(),
            Summary = new ProjectSummary
            {
                TotalPackages = packages.Count,
                HealthyCount = packages.Count(p => p.Status == HealthStatus.Healthy),
                WatchCount = packages.Count(p => p.Status == HealthStatus.Watch),
                WarningCount = packages.Count(p => p.Status == HealthStatus.Warning),
                CriticalCount = packages.Count(p => p.Status == HealthStatus.Critical),
                VulnerableCount = packages.Count(p => p.Vulnerabilities.Count > 0)
            }
        };

        var reportGenerator = new CraReportGenerator();
        reportGenerator.SetHealthData(packages);
        reportGenerator.SetTransitiveData(transitivePackages);
        reportGenerator.SetCompletenessWarnings(incompleteTransitive, hasUnresolvedVersions);

        // Add all dependency trees
        foreach (var tree in dependencyTrees)
        {
            reportGenerator.AddDependencyTree(tree);
        }

        var craReport = reportGenerator.Generate(healthReport, allVulnerabilities);

        if (string.IsNullOrEmpty(outputPath))
        {
            var projectName = Path.GetFileNameWithoutExtension(path);
            outputPath = format == CraOutputFormat.Json
                ? $"{projectName}-cra-report.json"
                : $"{projectName}-cra-report.html";
        }

        var output = format == CraOutputFormat.Json
            ? reportGenerator.GenerateJson(craReport)
            : reportGenerator.GenerateHtml(craReport);

        await File.WriteAllTextAsync(outputPath, output);

        // Display summary
        AnsiConsole.WriteLine();
        AnsiConsole.Write(new Rule("[bold]CRA Compliance Report Generated[/]").LeftJustified());

        var statusColor = craReport.OverallComplianceStatus switch
        {
            CraComplianceStatus.Compliant => "green",
            CraComplianceStatus.ActionRequired => "yellow",
            _ => "red"
        };

        AnsiConsole.MarkupLine($"[bold]Overall Status:[/] [{statusColor}]{craReport.OverallComplianceStatus}[/]");
        AnsiConsole.MarkupLine($"[bold]Health Score:[/] {craReport.HealthScore}/100");
        var totalPackages = craReport.PackageCount + craReport.TransitivePackageCount;
        AnsiConsole.MarkupLine($"[bold]Packages Analyzed:[/] {totalPackages} [dim]({craReport.PackageCount} direct + {craReport.TransitivePackageCount} transitive)[/]");
        AnsiConsole.MarkupLine($"[bold]Vulnerabilities Found:[/] {craReport.VulnerabilityCount}");

        if (dependencyTrees.Count > 0)
        {
            var ecosystems = string.Join(" + ", dependencyTrees.Select(t => $"{t.ProjectType} ({t.TotalPackages})"));
            AnsiConsole.MarkupLine($"[bold]Dependency Trees:[/] {ecosystems}");
        }

        AnsiConsole.WriteLine();

        var complianceTable = new Table()
            .Border(TableBorder.Rounded)
            .AddColumn("Requirement")
            .AddColumn("Status");

        foreach (var item in craReport.ComplianceItems)
        {
            var itemStatusColor = item.Status switch
            {
                CraComplianceStatus.Compliant => "green",
                CraComplianceStatus.ActionRequired => "yellow",
                _ => "red"
            };
            complianceTable.AddRow(item.Requirement, $"[{itemStatusColor}]{item.Status}[/]");
        }

        AnsiConsole.Write(complianceTable);

        AnsiConsole.MarkupLine($"\n[green]Report written to {outputPath}[/]");

        return craReport.OverallComplianceStatus == CraComplianceStatus.NonCompliant ? 1 : 0;
    }

    private static DependencyTree BuildDotNetDependencyTree(
        string projectPath,
        Dictionary<string, PackageReference> directRefs,
        Dictionary<string, PackageReference> transitiveRefs,
        List<PackageHealth> directPackages,
        List<PackageHealth> transitivePackages,
        Dictionary<string, List<VulnerabilityInfo>> vulnerabilities)
    {
        var healthLookup = directPackages
            .Concat(transitivePackages)
            .GroupBy(p => p.PackageId, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key, g => g.First(), StringComparer.OrdinalIgnoreCase);

        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var roots = new List<DependencyTreeNode>();

        // Build tree from direct dependencies
        foreach (var (packageId, reference) in directRefs)
        {
            var node = BuildDotNetTreeNode(packageId, reference.Version, 0, 5, healthLookup, vulnerabilities, seen);
            if (node is not null)
            {
                roots.Add(node);
            }
        }

        // Propagate vulnerability status up the tree
        PropagateVulnerabilityStatus(roots);

        var tree = new DependencyTree
        {
            ProjectPath = projectPath,
            ProjectType = ProjectType.DotNet,
            Roots = roots,
            TotalPackages = seen.Count,
            MaxDepth = CalculateMaxDepth(roots),
            VulnerableCount = CountVulnerableNodes(roots)
        };

        // Detect version conflicts
        DetectVersionConflicts(tree);

        return tree;
    }

    private static DependencyTreeNode? BuildDotNetTreeNode(
        string packageId,
        string version,
        int depth,
        int maxDepth,
        Dictionary<string, PackageHealth> healthLookup,
        Dictionary<string, List<VulnerabilityInfo>> vulnerabilities,
        HashSet<string> seen)
    {
        if (depth > maxDepth) return null;

        var key = $"{packageId}@{version}";
        var isDuplicate = !seen.Add(key);

        healthLookup.TryGetValue(packageId, out var health);
        var vulnList = vulnerabilities.GetValueOrDefault(packageId, []);
        var activeVuln = vulnList.Count > 0 ? GetFirstActiveVulnerability(version, vulnList) : null;
        var hasVuln = activeVuln is not null;

        var node = new DependencyTreeNode
        {
            PackageId = packageId,
            Version = version,
            Depth = depth,
            DependencyType = depth == 0 ? DependencyType.Direct : DependencyType.Transitive,
            IsDuplicate = isDuplicate,
            HealthScore = health?.Score,
            Status = health?.Status,
            HasVulnerabilities = hasVuln,
            VulnerabilityUrl = activeVuln?.Url ?? (hasVuln ? $"https://osv.dev/vulnerability/{activeVuln!.Id}" : null),
            VulnerabilitySummary = hasVuln ? (!string.IsNullOrWhiteSpace(activeVuln!.Summary) ? activeVuln.Summary : activeVuln.Id) : null,
            License = health?.License
        };

        // Add children from dependencies (if not duplicate and we have health data)
        if (!isDuplicate && health?.Dependencies is not null && depth < maxDepth)
        {
            foreach (var dep in health.Dependencies)
            {
                var childVersion = dep.VersionRange ?? "latest";
                var child = BuildDotNetTreeNode(dep.PackageId, childVersion, depth + 1, maxDepth, healthLookup, vulnerabilities, seen);
                if (child is not null)
                {
                    node.Children.Add(child);
                }
            }
        }

        return node;
    }

    private static void UpdateTreeNodeHealth(DependencyTree? tree, string packageId, int score, HealthStatus status)
    {
        if (tree is null) return;

        void Update(DependencyTreeNode node)
        {
            if (node.PackageId.Equals(packageId, StringComparison.OrdinalIgnoreCase))
            {
                node.HealthScore = score;
                node.Status = status;
                // Note: HasVulnerabilities is set by UpdateTreeVulnerabilities with proper version checking
            }
            foreach (var child in node.Children)
            {
                Update(child);
            }
        }

        foreach (var root in tree.Roots)
        {
            Update(root);
        }
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

    private static int CountVulnerableNodes(List<DependencyTreeNode> roots)
    {
        var count = 0;

        void Visit(DependencyTreeNode node)
        {
            if (node.HasVulnerabilities) count++;
            foreach (var child in node.Children)
            {
                Visit(child);
            }
        }

        foreach (var root in roots)
        {
            Visit(root);
        }

        return count;
    }

    /// <summary>
    /// Propagate vulnerability status up the tree.
    /// After calling this, any node with a vulnerable descendant will have HasVulnerableDescendant = true.
    /// </summary>
    private static void PropagateVulnerabilityStatus(List<DependencyTreeNode> roots)
    {
        // Returns true if this node or any descendant has vulnerabilities
        bool Visit(DependencyTreeNode node)
        {
            var hasVulnerableChild = false;

            foreach (var child in node.Children)
            {
                if (Visit(child))
                {
                    hasVulnerableChild = true;
                }
            }

            node.HasVulnerableDescendant = hasVulnerableChild;

            // Return true if this node has vulnerabilities OR any child does
            return node.HasVulnerabilities || hasVulnerableChild;
        }

        foreach (var root in roots)
        {
            Visit(root);
        }
    }

    /// <summary>
    /// Detect version conflicts in the dependency tree.
    /// Updates nodes with HasVersionConflict and ConflictingVersions,
    /// and populates the tree's Issues list.
    /// </summary>
    private static void DetectVersionConflicts(DependencyTree tree)
    {
        // Collect all versions for each package
        var packageVersions = new Dictionary<string, HashSet<string>>(StringComparer.OrdinalIgnoreCase);

        void CollectVersions(DependencyTreeNode node)
        {
            if (!packageVersions.TryGetValue(node.PackageId, out var versions))
            {
                versions = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                packageVersions[node.PackageId] = versions;
            }
            versions.Add(node.Version);

            foreach (var child in node.Children)
            {
                CollectVersions(child);
            }
        }

        foreach (var root in tree.Roots)
        {
            CollectVersions(root);
        }

        // Find packages with multiple versions
        var conflictingPackages = packageVersions
            .Where(kv => kv.Value.Count > 1)
            .ToDictionary(kv => kv.Key, kv => kv.Value.ToList(), StringComparer.OrdinalIgnoreCase);

        if (conflictingPackages.Count == 0)
            return;

        // Mark nodes with conflicts and create issues
        void MarkConflicts(DependencyTreeNode node)
        {
            if (conflictingPackages.TryGetValue(node.PackageId, out var versions))
            {
                node.HasVersionConflict = true;
                node.ConflictingVersions = versions.Where(v => !v.Equals(node.Version, StringComparison.OrdinalIgnoreCase)).ToList();
            }

            foreach (var child in node.Children)
            {
                MarkConflicts(child);
            }
        }

        foreach (var root in tree.Roots)
        {
            MarkConflicts(root);
        }

        // Create issues for each conflicting package
        foreach (var (packageId, versions) in conflictingPackages)
        {
            var sortedVersions = versions
                .Select(v =>
                {
                    NuGet.Versioning.NuGetVersion.TryParse(v, out var parsed);
                    return (Original: v, Parsed: parsed);
                })
                .OrderByDescending(x => x.Parsed)
                .Select(x => x.Original)
                .ToList();

            var issue = new DependencyIssue
            {
                Type = DependencyIssueType.VersionConflict,
                PackageId = packageId,
                Versions = sortedVersions,
                Description = $"{packageId} has {versions.Count} different versions: {string.Join(", ", sortedVersions)}",
                Severity = "Warning",
                Recommendation = $"Consider aligning all dependencies to use {sortedVersions[0]} (latest)"
            };
            tree.Issues.Add(issue);
        }

        tree.VersionConflictCount = conflictingPackages.Count;
    }

    private static void ShowGitHubStatus(GitHubApiClient? githubClient, bool skipGitHub)
    {
        // Vulnerabilities are now fetched from OSV (free, no auth required)
        // GitHub is only used for optional repo info (stars, commits)
        if (!skipGitHub && githubClient is not null && !githubClient.HasToken)
        {
            AnsiConsole.MarkupLine("[dim]No GITHUB_TOKEN found. Repository stats (stars, commits) will be limited.[/]");
            AnsiConsole.MarkupLine("[dim]Vulnerability data is fetched from OSV (no auth required).[/]");
            AnsiConsole.WriteLine();
        }
        else if (skipGitHub)
        {
            AnsiConsole.MarkupLine("[dim]GitHub API calls skipped. Repository stats will not be available.[/]");
            AnsiConsole.MarkupLine("[dim]Vulnerability data is still fetched from OSV.[/]");
            AnsiConsole.WriteLine();
        }
    }

    private static async Task FetchGitHubRepoInfoAsync(
        GitHubApiClient githubClient,
        List<string> repoUrls,
        Dictionary<string, NpmPackageInfo> npmInfoMap,
        Dictionary<string, GitHubRepoInfo?> repoInfoMap)
    {
        await AnsiConsole.Status()
            .StartAsync("Fetching GitHub repository info (batch)...", async ctx =>
            {
                var validUrls = repoUrls
                    .Where(u => u.Contains("github.com", StringComparison.OrdinalIgnoreCase))
                    .ToList();

                if (validUrls.Count > 0)
                {
                    var results = await githubClient.GetRepositoriesBatchAsync(validUrls);

                    foreach (var (packageName, info) in npmInfoMap)
                    {
                        var url = info.RepositoryUrl;
                        if (url is not null && results.TryGetValue(url, out var repoInfo))
                        {
                            repoInfoMap[packageName] = repoInfo;
                        }
                    }
                }

                if (githubClient.IsRateLimited)
                {
                    ctx.Status("[yellow]GitHub rate limited - continuing with available data[/]");
                }
            });
    }

    private static async Task FetchGitHubDataAsync(
        GitHubApiClient githubClient,
        List<string> repoUrls,
        Dictionary<string, NpmPackageInfo> npmInfoMap,
        List<string> packageNames,
        Dictionary<string, GitHubRepoInfo?> repoInfoMap,
        Dictionary<string, List<VulnerabilityInfo>> allVulnerabilities)
    {
        await AnsiConsole.Status()
            .StartAsync("Fetching GitHub repository info (batch)...", async ctx =>
            {
                var validUrls = repoUrls
                    .Where(u => u.Contains("github.com", StringComparison.OrdinalIgnoreCase))
                    .ToList();

                if (validUrls.Count > 0)
                {
                    var results = await githubClient.GetRepositoriesBatchAsync(validUrls);

                    foreach (var (packageName, info) in npmInfoMap)
                    {
                        var url = info.RepositoryUrl;
                        if (url is not null && results.TryGetValue(url, out var repoInfo))
                        {
                            repoInfoMap[packageName] = repoInfo;
                        }
                    }
                }

                if (githubClient.IsRateLimited)
                {
                    ctx.Status("[yellow]GitHub rate limited - continuing with available data[/]");
                }
            });

        // Fetch vulnerabilities
        if (!githubClient.IsRateLimited && githubClient.HasToken)
        {
            await AnsiConsole.Status()
                .StartAsync("Checking vulnerabilities (batch)...", async ctx =>
                {
                    var results = await githubClient.GetVulnerabilitiesBatchAsync(packageNames);
                    foreach (var (name, vulns) in results)
                    {
                        allVulnerabilities[name] = vulns;
                    }

                    if (githubClient.IsRateLimited)
                    {
                        ctx.Status("[yellow]GitHub rate limited - vulnerability data may be incomplete[/]");
                    }
                });
        }
    }

    private static async Task<int> GenerateReportAsync(
        string path,
        List<PackageHealth> packages,
        List<PackageHealth> transitivePackages,
        Dictionary<string, List<VulnerabilityInfo>> allVulnerabilities,
        DependencyTree? dependencyTree,
        CraOutputFormat format,
        string? outputPath,
        bool incompleteTransitive,
        bool hasUnresolvedVersions)
    {
        // Calculate project score
        var projectScore = HealthScoreCalculator.CalculateProjectScore(packages);
        var projectStatus = projectScore switch
        {
            >= 80 => HealthStatus.Healthy,
            >= 60 => HealthStatus.Watch,
            >= 40 => HealthStatus.Warning,
            _ => HealthStatus.Critical
        };

        var healthReport = new ProjectReport
        {
            ProjectPath = path,
            GeneratedAt = DateTime.UtcNow,
            OverallScore = projectScore,
            OverallStatus = projectStatus,
            Packages = packages.OrderBy(p => p.Score).ToList(),
            Summary = new ProjectSummary
            {
                TotalPackages = packages.Count,
                HealthyCount = packages.Count(p => p.Status == HealthStatus.Healthy),
                WatchCount = packages.Count(p => p.Status == HealthStatus.Watch),
                WarningCount = packages.Count(p => p.Status == HealthStatus.Warning),
                CriticalCount = packages.Count(p => p.Status == HealthStatus.Critical),
                VulnerableCount = packages.Count(p => p.Vulnerabilities.Count > 0)
            }
        };

        var reportGenerator = new CraReportGenerator();
        reportGenerator.SetHealthData(packages);
        reportGenerator.SetTransitiveData(transitivePackages);
        reportGenerator.SetCompletenessWarnings(incompleteTransitive, hasUnresolvedVersions);
        reportGenerator.SetDependencyTree(dependencyTree);
        var craReport = reportGenerator.Generate(healthReport, allVulnerabilities);

        // Determine output path
        if (string.IsNullOrEmpty(outputPath))
        {
            var projectName = Path.GetFileNameWithoutExtension(path);
            outputPath = format == CraOutputFormat.Json
                ? $"{projectName}-cra-report.json"
                : $"{projectName}-cra-report.html";
        }

        string output;
        if (format == CraOutputFormat.Json)
        {
            output = reportGenerator.GenerateJson(craReport);
        }
        else
        {
            output = reportGenerator.GenerateHtml(craReport);
        }

        await File.WriteAllTextAsync(outputPath, output);

        // Display summary
        AnsiConsole.WriteLine();
        AnsiConsole.Write(new Rule("[bold]CRA Compliance Report Generated[/]").LeftJustified());

        var statusColor = craReport.OverallComplianceStatus switch
        {
            CraComplianceStatus.Compliant => "green",
            CraComplianceStatus.ActionRequired => "yellow",
            _ => "red"
        };

        AnsiConsole.MarkupLine($"[bold]Overall Status:[/] [{statusColor}]{craReport.OverallComplianceStatus}[/]");
        AnsiConsole.MarkupLine($"[bold]Health Score:[/] {craReport.HealthScore}/100");
        var totalPackages = craReport.PackageCount + craReport.TransitivePackageCount;
        AnsiConsole.MarkupLine($"[bold]Packages Analyzed:[/] {totalPackages} [dim]({craReport.PackageCount} direct + {craReport.TransitivePackageCount} transitive)[/]");
        AnsiConsole.MarkupLine($"[bold]Vulnerabilities Found:[/] {craReport.VulnerabilityCount}");

        if (dependencyTree is not null)
        {
            AnsiConsole.MarkupLine($"[bold]Dependency Tree:[/] {dependencyTree.TotalPackages} packages, max depth {dependencyTree.MaxDepth}");
        }

        AnsiConsole.WriteLine();

        var complianceTable = new Table()
            .Border(TableBorder.Rounded)
            .AddColumn("Requirement")
            .AddColumn("Status");

        foreach (var item in craReport.ComplianceItems)
        {
            var itemStatusColor = item.Status switch
            {
                CraComplianceStatus.Compliant => "green",
                CraComplianceStatus.ActionRequired => "yellow",
                _ => "red"
            };
            complianceTable.AddRow(item.Requirement, $"[{itemStatusColor}]{item.Status}[/]");
        }

        AnsiConsole.Write(complianceTable);

        AnsiConsole.MarkupLine($"\n[green]Report written to {outputPath}[/]");

        return craReport.OverallComplianceStatus == CraComplianceStatus.NonCompliant ? 1 : 0;
    }
}

public enum CraOutputFormat
{
    Html,
    Json
}
