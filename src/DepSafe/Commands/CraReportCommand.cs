using System.Collections.Concurrent;
using System.Collections.Frozen;
using System.CommandLine;
using System.CommandLine.Invocation;
using System.Text.Json;
using DepSafe.Compliance;
using DepSafe.DataSources;
using DepSafe.Models;
using DepSafe.Scoring;
using DepSafe.Signing;
using Spectre.Console;

namespace DepSafe.Commands;

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

        var licensesOption = new Option<LicenseOutputFormat?>(
            ["--licenses", "-l"],
            "Generate license attribution file (txt, html, or md)");

        var sbomOption = new Option<SbomFormat?>(
            ["--sbom", "-s"],
            "Export SBOM in specified format (cyclonedx or spdx)");

        var checkTyposquatOption = new Option<bool>(
            ["--check-typosquat"],
            "Run typosquatting detection on all dependencies");

        var signOption = new Option<bool>(
            ["--sign"],
            "Sign all generated artifacts with sigil");

        var signKeyOption = new Option<string?>(
            ["--sign-key"],
            "Path to the signing key for sigil (uses default if not specified)");

        var releaseGateOption = new Option<bool>(
            ["--release-gate"],
            "Evaluate release readiness with blocking/advisory classification");

        var evidencePackOption = new Option<bool>(
            ["--evidence-pack"],
            "Bundle all compliance artifacts into a timestamped evidence directory with manifest");

        var auditModeOption = new Option<bool>(
            ["--audit-mode"],
            "Simulate CRA conformity assessment with zero-tolerance findings");

        var command = new Command("cra-report", "Generate comprehensive CRA compliance report")
        {
            pathArg,
            formatOption,
            outputOption,
            skipGitHubOption,
            deepOption,
            licensesOption,
            sbomOption,
            checkTyposquatOption,
            signOption,
            signKeyOption,
            releaseGateOption,
            evidencePackOption,
            auditModeOption
        };

        var binder = new CraReportOptionsBinder(pathArg, formatOption, outputOption, skipGitHubOption, deepOption, licensesOption, sbomOption, checkTyposquatOption, signOption, signKeyOption, releaseGateOption, evidencePackOption, auditModeOption);
        command.SetHandler(async context =>
        {
            var options = binder.Bind(context.BindingContext);
            var ct = context.GetCancellationToken();
            context.ExitCode = await ExecuteAsync(options, ct);
        });

        return command;
    }

    private static Result<ProjectType> DetectProjectType(string path)
    {
        var hasNetProjects = NuGetApiClient.FindProjectFiles(path).Any();
        var hasPackageJson = NpmApiClient.FindPackageJsonFiles(path).Any();

        return (hasNetProjects, hasPackageJson) switch
        {
            (true, true) => ProjectType.Mixed,
            (true, false) => ProjectType.DotNet,
            (false, true) => ProjectType.Npm,
            _ => Result.Fail<ProjectType>("No project files found (no .csproj/.sln or package.json)", ErrorKind.NotFound)
        };
    }

    private static async Task<Result<CraConfig>> LoadCraConfigAsync(string path, CancellationToken ct = default)
    {
        // Look for .cra-config.json in project root
        var searchDir = File.Exists(path) ? Path.GetDirectoryName(path)! : path;
        var configPath = Path.Combine(searchDir, ".cra-config.json");

        if (!File.Exists(configPath))
        {
            return Result.Fail<CraConfig>("No .cra-config.json found", ErrorKind.NotFound);
        }

        try
        {
            var json = await File.ReadAllTextAsync(configPath, ct);
            var config = JsonSerializer.Deserialize<CraConfig>(json, JsonDefaults.CaseInsensitive);
            if (config is null)
                return Result.Fail<CraConfig>("Failed to deserialize .cra-config.json", ErrorKind.ParseError);
            return config;
        }
        catch (JsonException ex)
        {
            AnsiConsole.MarkupLine($"[yellow]Warning: Failed to parse .cra-config.json: {ex.Message}[/]");
            return Result.Fail<CraConfig>($"Failed to parse .cra-config.json: {ex.Message}", ErrorKind.ParseError);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            AnsiConsole.MarkupLine($"[yellow]Warning: Failed to read .cra-config.json: {ex.Message}[/]");
            return Result.Fail<CraConfig>($"Failed to read .cra-config.json: {ex.Message}", ErrorKind.Unknown);
        }
    }

    private static string? GetLicenseOverride(CraConfig? config, string packageId)
    {
        if (config?.LicenseOverrides is null)
            return null;

        return config.LicenseOverrides.TryGetValue(packageId, out var license) ? license : null;
    }

    private static async Task<int> ExecuteAsync(CraReportOptions options, CancellationToken ct)
    {
        var startTime = DateTime.UtcNow;
        var path = string.IsNullOrEmpty(options.Path) ? Directory.GetCurrentDirectory() : Path.GetFullPath(options.Path);
        var format = options.Format;
        var outputPath = options.Output;
        var skipGitHub = options.SkipGitHub;
        var deepScan = options.Deep;
        var licensesFormat = options.Licenses;
        var sbomFormat = options.Sbom;
        var checkTyposquat = options.CheckTyposquat;
        var sign = options.Sign;
        var signKey = options.SignKey;
        var releaseGate = options.ReleaseGate;
        var evidencePack = options.EvidencePack;
        var auditMode = options.AuditMode;

        if (!File.Exists(path) && !Directory.Exists(path))
        {
            AnsiConsole.MarkupLine($"[red]Path not found: {Markup.Escape(path)}[/]");
            return 1;
        }

        // Validate output path: block relative path traversal (e.g., ../../etc/passwd)
        // but allow absolute paths since the user explicitly chose them.
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
        var projectTypeResult = DetectProjectType(path);
        if (projectTypeResult.IsFailure)
        {
            AnsiConsole.MarkupLine("[yellow]No project files found (no .csproj/.sln or package.json).[/]");
            return 0;
        }
        var projectType = projectTypeResult.Value;

        AnsiConsole.MarkupLine($"[dim]Detected project type: {projectType}[/]");
        if (deepScan)
        {
            AnsiConsole.MarkupLine("[dim]Deep scan enabled - fetching full metadata for all packages[/]");
        }

        // Load CRA config if present
        var configResult = await LoadCraConfigAsync(path, ct);
        var config = configResult.IsSuccess ? configResult.Value : null;
        if (config is not null && config.LicenseOverrides.Count > 0)
        {
            AnsiConsole.MarkupLine($"[dim]Loaded .cra-config.json with {config.LicenseOverrides.Count} license override(s)[/]");
        }

        // Run typosquatting analysis before report generation so results are included in HTML
        List<TyposquatResult>? typosquatResults = null;
        if (checkTyposquat)
        {
            typosquatResults = await TyposquatCommand.RunAnalysisAsync(path, offline: false, ct);
        }

        // Process based on project type
        var result = projectType switch
        {
            ProjectType.Npm => await ExecuteNpmAsync(path, format, outputPath, skipGitHub, deepScan, licensesFormat, sbomFormat, config, startTime, typosquatResults, sign, signKey, releaseGate, evidencePack, auditMode, ct),
            ProjectType.DotNet => await ExecuteDotNetAsync(path, format, outputPath, skipGitHub, deepScan, licensesFormat, sbomFormat, config, startTime, typosquatResults, sign, signKey, releaseGate, evidencePack, auditMode, ct),
            ProjectType.Mixed => await ExecuteMixedAsync(path, format, outputPath, skipGitHub, deepScan, licensesFormat, sbomFormat, config, startTime, typosquatResults, sign, signKey, releaseGate, evidencePack, auditMode, ct),
            _ => 0
        };

        // CLI output for typosquatting warnings
        if (typosquatResults is { Count: > 0 })
        {
            AnsiConsole.WriteLine();
            AnsiConsole.Write(new Rule("[yellow bold]Typosquatting Warnings[/]").LeftJustified());
            foreach (var tr in typosquatResults)
            {
                var riskColor = tr.RiskLevel switch
                {
                    TyposquatRiskLevel.Critical => "red",
                    TyposquatRiskLevel.High => "orange3",
                    TyposquatRiskLevel.Medium => "yellow",
                    _ => "dim"
                };
                AnsiConsole.MarkupLine($"  [{riskColor}]{tr.RiskLevel}[/]  {Markup.Escape(tr.PackageName)} -> {Markup.Escape(tr.SimilarTo)} ({Markup.Escape(tr.Detail)}, confidence: {tr.Confidence}%)");
            }
        }

        return result;
    }

    private static async Task<int> ExecuteNpmAsync(string path, CraOutputFormat format, string? outputPath, bool skipGitHub, bool deepScan, LicenseOutputFormat? licensesFormat, SbomFormat? sbomFormat, CraConfig? config, DateTime startTime, List<TyposquatResult>? typosquatResults = null, bool sign = false, string? signKey = null, bool releaseGate = false, bool evidencePack = false, bool auditMode = false, CancellationToken ct = default)
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
        using var githubClient = skipGitHub ? null : new GitHubApiClient();
        var calculator = new HealthScoreCalculator
        {
            LicenseOverrides = config?.LicenseOverrides
        };

        // Show GitHub status
        ShowGitHubStatus(githubClient, skipGitHub);

        // Parse package.json
        var packageJsonResult = await NpmApiClient.ParsePackageJsonAsync(packageJsonPath, ct);
        if (packageJsonResult.IsFailure)
        {
            AnsiConsole.MarkupLine($"[red]{Markup.Escape(packageJsonResult.Error)}[/]");
            return 1;
        }

        var packageJson = packageJsonResult.Value;
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
                dependencyTree = await npmClient.BuildDependencyTreeAsync(packageJsonPath, maxDepth: 10, ct);
            });

        // Collect transitive package IDs from tree for vulnerability scanning
        var directPackageIds = new HashSet<string>(allDeps.Keys, StringComparer.OrdinalIgnoreCase);
        var transitiveNpmPackageIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (dependencyTree is not null)
        {
            CollectTransitivePackageIds(dependencyTree.Roots, directPackageIds, transitiveNpmPackageIds);
        }

        // Compute all package IDs once (direct + transitive)
        var allNpmPackageIds = allDeps.Keys.Concat(transitiveNpmPackageIds).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        var packagesToFetch = deepScan ? allNpmPackageIds : allDeps.Keys.ToList();

        // Phase 1: Fetch npm info for direct packages (and transitive if deep scan)
        var npmInfoMap = new ConcurrentDictionary<string, NpmPackageInfo>(StringComparer.OrdinalIgnoreCase);

        await AnsiConsole.Progress()
            .StartAsync(async ctx =>
            {
                var task = ctx.AddTask($"Fetching npm info for {packagesToFetch.Count} packages", maxValue: packagesToFetch.Count);

                // Fetch in parallel with concurrency limit for 3-5x speedup
                using var semaphore = new SemaphoreSlim(10);
                var tasks = packagesToFetch.Select(async packageName =>
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

        // Phase 2: Fetch vulnerabilities from OSV (free, no auth required) and GitHub repo info
        var repoInfoMap = new Dictionary<string, GitHubRepoInfo?>(allNpmPackageIds.Count, StringComparer.OrdinalIgnoreCase);
        var allVulnerabilities = new Dictionary<string, List<VulnerabilityInfo>>(allNpmPackageIds.Count, StringComparer.OrdinalIgnoreCase);

        // Fetch vulnerabilities from OSV (always available, no auth)
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

        // Optionally fetch GitHub repo info (for stars, commits, etc.)
        if (githubClient is not null && !githubClient.IsRateLimited)
        {
            await FetchGitHubRepoInfoAsync(
                githubClient,
                npmInfoMap.Values.Select(n => n.RepositoryUrl).Where(u => u is not null).ToList()!,
                npmInfoMap,
                repoInfoMap,
                ct);
        }

        // Phase 3: Calculate health scores
        var packages = new List<PackageHealth>();

        // Build lookup of installed versions from dependency tree
        var installedVersions = new Dictionary<string, string>(dependencyTree?.Roots.Count ?? 0, StringComparer.OrdinalIgnoreCase);
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

        foreach (var (packageName, versionRange) in allDeps)
        {
            if (!npmInfoMap.TryGetValue(packageName, out var npmInfo))
                continue;

            repoInfoMap.TryGetValue(packageName, out var repoInfo);
            if (!allVulnerabilities.TryGetValue(packageName, out var vulnerabilities))
                vulnerabilities = [];

            // Use installed version from lock file, fall back to latest if not found
            var installedVersion = installedVersions.GetValueOrDefault(packageName, npmInfo.LatestVersion);

            var health = calculator.Calculate(
                packageName,
                installedVersion,
                npmInfo,
                repoInfo,
                vulnerabilities);

            // Wire integrity hash from lock file
            if (integrityLookup.TryGetValue(packageName, out var integrity))
                health.ContentIntegrity = integrity;

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
                    npmInfoMap, repoInfoMap, calculator, integrityLookup);
                transitivePackages.AddRange(transitiveFromTree);
                AnsiConsole.MarkupLine($"[dim]Including {transitivePackages.Count} transitive npm packages with full health data[/]");
            }
            else
            {
                // Minimal scan: only CRA scores (no full health metrics)
                var transitiveFromTree = ExtractTransitivePackagesFromTree(dependencyTree.Roots, directPackageIds, allVulnerabilities, integrityLookup);
                transitivePackages.AddRange(transitiveFromTree);
                AnsiConsole.MarkupLine($"[dim]Including {transitivePackages.Count} transitive npm packages in SBOM[/]");
            }
        }

        // Collect CRA compliance data from npm packages (single pass for efficiency)
        var deprecatedPackages = new List<string>();
        foreach (var pkg in npmInfoMap.Values)
        {
            if (pkg.IsDeprecated) deprecatedPackages.Add(pkg.Name);
        }
        int pkgsWithSecurityPolicy = 0, pkgsWithRepo = 0;
        foreach (var info in repoInfoMap.Values)
        {
            if (info is not null)
            {
                pkgsWithRepo++;
                if (info.HasSecurityPolicy) pkgsWithSecurityPolicy++;
            }
        }

        // Build available versions for upgrade path analysis
        var availableVersions = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
        foreach (var (name, info) in npmInfoMap)
        {
            availableVersions[name] = info.Versions
                .Where(v => !v.IsDeprecated)
                .Select(v => v.Version)
                .ToList();
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
            false,
            startTime,
            licensesFormat,
            sbomFormat,
            deprecatedPackages,
            pkgsWithSecurityPolicy,
            pkgsWithRepo,
            typosquatResults,
            repoInfoMap,
            config,
            sign,
            signKey,
            releaseGate,
            evidencePack,
            auditMode,
            availableVersions,
            ct);
    }

    private static List<PackageHealth> ExtractTransitivePackagesFromTree(
        List<DependencyTreeNode> roots,
        HashSet<string> excludePackageIds)
    {
        return ExtractTransitivePackagesFromTree(roots, excludePackageIds, new Dictionary<string, List<VulnerabilityInfo>>(), null);
    }

    private static List<PackageHealth> ExtractTransitivePackagesFromTree(
        List<DependencyTreeNode> roots,
        HashSet<string> excludePackageIds,
        Dictionary<string, List<VulnerabilityInfo>> vulnerabilities,
        Dictionary<string, string>? integrityLookup = null)
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
                // Use tree node's vulnerability info (already calculated by UpdateTreeVulnerabilities)
                var hasVulns = node.HasVulnerabilities;
                var vulnId = !string.IsNullOrEmpty(node.VulnerabilitySummary) ? node.VulnerabilitySummary : null;

                // Also check the vulnerabilities dict for additional context
                if (!vulnerabilities.TryGetValue(node.PackageId, out var pkgVulns))
                    pkgVulns = [];
                var activeVulns = hasVulns
                    ? pkgVulns.Where(v => IsVulnerabilityActiveForVersion(node.Version, v)).ToList()
                    : [];

                // If tree says vulnerable but we found no vulns in dict, create a placeholder
                if (hasVulns && activeVulns.Count == 0 && vulnId != null)
                {
                    activeVulns = [new VulnerabilityInfo
                    {
                        Id = vulnId,
                        Summary = vulnId,
                        Severity = "UNKNOWN",
                        PackageId = node.PackageId,
                        VulnerableVersionRange = node.Version
                    }];
                }

                var (craScore, craStatus) = CalculateTransitiveCraScore(activeVulns, node.License, node.PackageId, node.Version);

                var pkg = new PackageHealth
                {
                    PackageId = node.PackageId,
                    Version = node.Version,
                    Score = node.HealthScore ?? (hasVulns ? 30 : 50),
                    Status = node.Status ?? (hasVulns ? HealthStatus.Critical : HealthStatus.Watch),
                    CraScore = craScore,
                    CraStatus = craStatus,
                    Metrics = new PackageMetrics { VulnerabilityCount = hasVulns ? Math.Max(1, activeVulns.Count) : 0 },
                    License = node.License,
                    DependencyType = DependencyType.Transitive,
                    Ecosystem = node.Ecosystem,
                    Vulnerabilities = activeVulns.Select(v => v.Id).ToList(),
                    Authors = ExtractNpmScopeAuthor(node.PackageId)
                };

                if (integrityLookup?.TryGetValue(node.PackageId, out var integrity) == true)
                    pkg.ContentIntegrity = integrity;

                packages.Add(pkg);
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
        IDictionary<string, NpmPackageInfo> npmInfoMap,
        Dictionary<string, GitHubRepoInfo?> repoInfoMap,
        HealthScoreCalculator calculator,
        Dictionary<string, string>? integrityLookup = null)
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
                // Use tree node's vulnerability info (already calculated by UpdateTreeVulnerabilities)
                var hasVulns = node.HasVulnerabilities;
                var vulnId = !string.IsNullOrEmpty(node.VulnerabilitySummary) ? node.VulnerabilitySummary : null;

                if (!vulnerabilities.TryGetValue(node.PackageId, out var pkgVulns))
                    pkgVulns = [];
                var activeVulns = hasVulns
                    ? pkgVulns.Where(v => IsVulnerabilityActiveForVersion(node.Version, v)).ToList()
                    : [];

                // If tree says vulnerable but we found no vulns in dict, create a placeholder
                if (hasVulns && activeVulns.Count == 0 && vulnId != null)
                {
                    activeVulns = [new VulnerabilityInfo
                    {
                        Id = vulnId,
                        Summary = vulnId,
                        Severity = "UNKNOWN",
                        PackageId = node.PackageId,
                        VulnerableVersionRange = node.Version
                    }];
                }

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

                    if (integrityLookup?.TryGetValue(node.PackageId, out var integ) == true)
                        health.ContentIntegrity = integ;

                    packages.Add(health);
                }
                else
                {
                    // Fallback: no npm info available - use minimal CRA calculation
                    var (craScore, craStatus) = CalculateTransitiveCraScore(activeVulns, node.License, node.PackageId, node.Version);

                    var fallbackPkg = new PackageHealth
                    {
                        PackageId = node.PackageId,
                        Version = node.Version,
                        Score = hasVulns ? 30 : 50,
                        Status = hasVulns ? HealthStatus.Critical : HealthStatus.Watch,
                        CraScore = craScore,
                        CraStatus = craStatus,
                        Metrics = new PackageMetrics { VulnerabilityCount = hasVulns ? Math.Max(1, activeVulns.Count) : 0 },
                        License = node.License,
                        DependencyType = DependencyType.Transitive,
                        Ecosystem = node.Ecosystem,
                        Vulnerabilities = activeVulns.Select(v => v.Id).ToList(),
                        Authors = ExtractNpmScopeAuthor(node.PackageId)
                    };

                    if (integrityLookup?.TryGetValue(node.PackageId, out var integFb) == true)
                        fallbackPkg.ContentIntegrity = integFb;

                    packages.Add(fallbackPkg);
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

        foreach (var root in roots)
        {
            Visit(root);
        }
    }

    private static void UpdateTreeVulnerabilities(
        List<DependencyTreeNode> roots,
        Dictionary<string, List<VulnerabilityInfo>> vulnerabilities)
    {
        var visited = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        void Visit(DependencyTreeNode node)
        {
            var key = $"{node.PackageId}@{node.Version}";
            if (!visited.Add(key)) return;

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
            // FIRST check if version is in vulnerable range
            bool inVulnerableRange;
            if (!string.IsNullOrEmpty(vuln.VulnerableVersionRange))
            {
                inVulnerableRange = IsVersionInVulnerableRange(version, vuln.VulnerableVersionRange);
            }
            else
            {
                // No range specified, conservatively assume vulnerable
                inVulnerableRange = true;
            }

            if (!inVulnerableRange)
            {
                continue; // Not in vulnerable range, check next vulnerability
            }

            // THEN check if version is patched (only matters if we're in the vulnerable range)
            if (!string.IsNullOrEmpty(vuln.PatchedVersion) &&
                NuGet.Versioning.NuGetVersion.TryParse(version, out var current) &&
                NuGet.Versioning.NuGetVersion.TryParse(vuln.PatchedVersion, out var patched) &&
                current >= patched)
            {
                continue; // Patched, check next vulnerability
            }

            // Version is in vulnerable range and not patched
            return vuln;
        }

        return null;
    }

    /// <summary>
    /// Check if a specific version is actually affected by any of the vulnerabilities.
    /// Returns true only if the version is in a vulnerable range and NOT patched.
    /// </summary>
    private static bool IsVersionActuallyVulnerable(string version, List<VulnerabilityInfo> vulnerabilities)
        => GetFirstActiveVulnerability(version, vulnerabilities) is not null;

    /// <summary>
    /// Check if a specific version is affected by a single vulnerability.
    /// More efficient than creating a single-element list.
    /// </summary>
    private static bool IsVulnerabilityActiveForVersion(string version, VulnerabilityInfo vuln)
    {
        // Check if version is in vulnerable range
        bool inVulnerableRange;
        if (!string.IsNullOrEmpty(vuln.VulnerableVersionRange))
        {
            inVulnerableRange = IsVersionInVulnerableRange(version, vuln.VulnerableVersionRange);
        }
        else
        {
            inVulnerableRange = true; // No range specified, conservatively assume vulnerable
        }

        if (!inVulnerableRange) return false;

        // Check if version is patched
        if (!string.IsNullOrEmpty(vuln.PatchedVersion) &&
            NuGet.Versioning.NuGetVersion.TryParse(version, out var current) &&
            NuGet.Versioning.NuGetVersion.TryParse(vuln.PatchedVersion, out var patched) &&
            current >= patched)
        {
            return false; // Patched
        }

        return true;
    }

    private static bool IsVersionInVulnerableRange(string version, string range) =>
        Scoring.HealthScoreCalculator.IsVersionInVulnerableRange(version, range);

    /// <summary>
    /// Extract a parseable version from a NuGet version range string.
    /// E.g., "[10.0.2, )" -> "10.0.2", "[1.0.0]" -> "1.0.0"
    /// </summary>
    private static string? ExtractVersionFromRange(string? versionRange)
    {
        if (string.IsNullOrWhiteSpace(versionRange))
            return null;

        var range = versionRange.Trim();

        // Remove brackets: [ ] ( )
        range = range.TrimStart('[', '(').TrimEnd(']', ')');

        // Handle comma-separated ranges like "10.0.2, " or ", 10.0.2"
        var parts = range.Split(',');
        foreach (var part in parts)
        {
            var trimmed = part.Trim();
            if (!string.IsNullOrEmpty(trimmed))
            {
                // Try to parse as a version
                if (NuGet.Versioning.NuGetVersion.TryParse(trimmed, out _))
                {
                    return trimmed;
                }
            }
        }

        // If range itself is a version, return it
        if (NuGet.Versioning.NuGetVersion.TryParse(range, out _))
        {
            return range;
        }

        // Couldn't extract a version
        return versionRange;
    }

    /// <summary>
    /// Extract author from npm scoped package name (e.g., @tanstack/router → tanstack).
    /// Returns empty list for non-scoped packages.
    /// </summary>
    private static List<string> ExtractNpmScopeAuthor(string packageId)
    {
        if (packageId.StartsWith('@') && packageId.Contains('/'))
        {
            var scope = packageId[1..packageId.IndexOf('/')];
            return [scope];
        }
        return [];
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
            var normalizedLicense = license.Trim();
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

    private static readonly FrozenSet<string> KnownSpdxLicenses = FrozenSet.ToFrozenSet(
    [
        "MIT", "MIT-0",
        "APACHE-2.0", "APACHE 2.0", "APACHE2",
        "BSD-2-CLAUSE", "BSD-3-CLAUSE", "0BSD",
        "ISC",
        "GPL-2.0", "GPL-3.0", "GPL-2.0-ONLY", "GPL-3.0-ONLY",
        "LGPL-2.1", "LGPL-3.0", "LGPL-2.1-ONLY", "LGPL-3.0-ONLY",
        "MPL-2.0",
        "UNLICENSE", "UNLICENSED",
        "CC0-1.0", "CC-BY-4.0",
        "BSL-1.0",
        "WTFPL",
        "ZLIB",
        "MS-PL", "MS-RL"
    ], StringComparer.OrdinalIgnoreCase);

    private static bool IsKnownSpdxLicense(string license) => KnownSpdxLicenses.Contains(license);

    private static async Task<int> ExecuteDotNetAsync(string path, CraOutputFormat format, string? outputPath, bool skipGitHub, bool deepScan, LicenseOutputFormat? licensesFormat, SbomFormat? sbomFormat, CraConfig? config, DateTime startTime, List<TyposquatResult>? typosquatResults = null, bool sign = false, string? signKey = null, bool releaseGate = false, bool evidencePack = false, bool auditMode = false, CancellationToken ct = default)
    {
        var projectFiles = NuGetApiClient.FindProjectFiles(path).ToList();
        if (projectFiles.Count == 0)
        {
            AnsiConsole.MarkupLine("[yellow]No project files found.[/]");
            return 0;
        }

        using var nugetClient = new NuGetApiClient();
        using var githubClient = skipGitHub ? null : new GitHubApiClient();
        var calculator = new HealthScoreCalculator
        {
            LicenseOverrides = config?.LicenseOverrides
        };

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
                var dotnetResult = await NuGetApiClient.ParsePackagesWithDotnetAsync(path, ct);
                var (topLevel, transitive) = dotnetResult.ValueOr(([], []));

                if (topLevel.Count > 0)
                {
                    foreach (var r in topLevel)
                    {
                        if (allReferences.TryAdd(r.PackageId, r) && r.Version.Contains("$("))
                            hasUnresolvedVersions = true;
                    }
                    foreach (var r in transitive)
                    {
                        if (!allReferences.ContainsKey(r.PackageId))
                            transitiveReferences.TryAdd(r.PackageId, r);
                    }
                }
                else
                {
                    // Fall back to XML parsing if dotnet command fails
                    usedFallbackParsing = true;
                    ctx.Status("Falling back to XML parsing...");
                    foreach (var projectFile in projectFiles)
                    {
                        var refsResult = await NuGetApiClient.ParseProjectFileAsync(projectFile, ct);
                        foreach (var r in refsResult.ValueOr([]))
                        {
                            if (allReferences.TryAdd(r.PackageId, r) && r.Version.Contains("$("))
                                hasUnresolvedVersions = true;
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
        // Only warn when fallback parsing also found nothing — packages.config is already a complete flat list
        var incompleteTransitive = usedFallbackParsing && allReferences.Count == 0;
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
        var nugetInfoMap = new ConcurrentDictionary<string, NuGetPackageInfo>(StringComparer.OrdinalIgnoreCase);
        var allPackageIds = allReferences.Keys.Concat(transitiveReferences.Keys).Distinct(StringComparer.OrdinalIgnoreCase).ToList();

        await AnsiConsole.Progress()
            .StartAsync(async ctx =>
            {
                var task = ctx.AddTask($"Fetching NuGet info for {allPackageIds.Count} packages", maxValue: allPackageIds.Count);

                // Fetch in parallel with concurrency limit for 3-5x speedup
                using var semaphore = new SemaphoreSlim(10);
                var tasks = allPackageIds.Select(async packageId =>
                {
                    await semaphore.WaitAsync(ct);
                    try
                    {
                        var result = await nugetClient.GetPackageInfoAsync(packageId, ct);
                        if (result.IsSuccess)
                        {
                            nugetInfoMap[packageId] = result.Value;
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

                    // Fetch in parallel with concurrency limit for 3-5x speedup
                    using var semaphore = new SemaphoreSlim(10);
                    var tasks = dependencyPackageIds.Select(async packageId =>
                    {
                        await semaphore.WaitAsync(ct);
                        try
                        {
                            if (!nugetInfoMap.ContainsKey(packageId))
                            {
                                var result = await nugetClient.GetPackageInfoAsync(packageId, ct);
                                if (result.IsSuccess)
                                {
                                    nugetInfoMap[packageId] = result.Value;
                                }
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
        }

        // Phase 2: Batch fetch GitHub repo info (if not skipped)
        // Include dependency packages in the list for GitHub lookups
        var allPackageIdsWithDeps = allPackageIds.Concat(dependencyPackageIds).ToList();
        var repoInfoMap = new Dictionary<string, GitHubRepoInfo?>(allPackageIdsWithDeps.Count, StringComparer.OrdinalIgnoreCase);
        var allVulnerabilities = new Dictionary<string, List<VulnerabilityInfo>>(allPackageIdsWithDeps.Count, StringComparer.OrdinalIgnoreCase);

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
                        var results = await githubClient.GetRepositoriesBatchAsync(repoUrls!, ct);

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
                        allVulnerabilities = await githubClient.GetVulnerabilitiesBatchAsync(allPackageIdsWithDeps, ct);

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
            if (!allVulnerabilities.TryGetValue(packageId, out var vulnerabilities))
                vulnerabilities = [];

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
            if (!allVulnerabilities.TryGetValue(packageId, out var vulnerabilities))
                vulnerabilities = [];

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
        var transitivePackageIds = new HashSet<string>(
            transitivePackages.Select(p => p.PackageId), StringComparer.OrdinalIgnoreCase);
        foreach (var packageId in dependencyPackageIds)
        {
            // Skip if already in transitive list
            if (transitivePackageIds.Contains(packageId))
                continue;

            if (!nugetInfoMap.TryGetValue(packageId, out var nugetInfo))
                continue;

            repoInfoMap.TryGetValue(packageId, out var repoInfo);
            if (!allVulnerabilities.TryGetValue(packageId, out var vulnerabilities))
                vulnerabilities = [];

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

        // Collect CRA compliance data from .NET packages (single pass for efficiency)
        var deprecatedPackages = new List<string>();
        foreach (var pkg in nugetInfoMap.Values)
        {
            if (pkg.IsDeprecated) deprecatedPackages.Add(pkg.PackageId);
        }
        int pkgsWithSecurityPolicy = 0, pkgsWithRepo = 0;
        foreach (var info in repoInfoMap.Values)
        {
            if (info is not null)
            {
                pkgsWithRepo++;
                if (info.HasSecurityPolicy) pkgsWithSecurityPolicy++;
            }
        }

        // Build available versions for upgrade path analysis
        var availableVersions = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
        foreach (var (id, info) in nugetInfoMap)
        {
            availableVersions[id] = info.Versions
                .Where(v => v.IsListed)
                .Select(v => v.Version)
                .ToList();
        }

        return await GenerateReportAsync(
            path,
            packages,
            transitivePackages,
            allVulnerabilities,
            dependencyTree,
            format,
            outputPath,
            incompleteTransitive,
            hasUnresolvedVersions,
            startTime,
            licensesFormat,
            sbomFormat,
            deprecatedPackages,
            pkgsWithSecurityPolicy,
            pkgsWithRepo,
            typosquatResults,
            repoInfoMap,
            config,
            sign,
            signKey,
            releaseGate,
            evidencePack,
            auditMode,
            availableVersions,
            ct);
    }

    private static async Task<int> ExecuteMixedAsync(string path, CraOutputFormat format, string? outputPath, bool skipGitHub, bool deepScan, LicenseOutputFormat? licensesFormat, SbomFormat? sbomFormat, CraConfig? config, DateTime startTime, List<TyposquatResult>? typosquatResults = null, bool sign = false, string? signKey = null, bool releaseGate = false, bool evidencePack = false, bool auditMode = false, CancellationToken ct = default)
    {
        AnsiConsole.MarkupLine("[dim]Mixed project detected - analyzing both .NET and npm components[/]");

        using var nugetClient = new NuGetApiClient();
        using var npmClient = new NpmApiClient();
        using var githubClient = skipGitHub ? null : new GitHubApiClient();
        var calculator = new HealthScoreCalculator
        {
            LicenseOverrides = config?.LicenseOverrides
        };

        ShowGitHubStatus(githubClient, skipGitHub);

        var allPackages = new List<PackageHealth>();
        var allTransitivePackages = new List<PackageHealth>();
        var allVulnerabilities = new Dictionary<string, List<VulnerabilityInfo>>(StringComparer.OrdinalIgnoreCase);
        var dependencyTrees = new List<DependencyTree>();
        var incompleteTransitive = false;
        var hasUnresolvedVersions = false;

        // CRA compliance data collectors
        var allDeprecatedPackages = new List<string>();
        var totalPackagesWithSecurityPolicy = 0;
        var totalPackagesWithRepo = 0;
        var allRepoInfoMap = new Dictionary<string, GitHubRepoInfo?>(StringComparer.OrdinalIgnoreCase);

        // Available versions for upgrade path analysis (populated from NuGet/npm info maps)
        var availableVersions = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);

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
                    var dotnetResult = await NuGetApiClient.ParsePackagesWithDotnetAsync(path, ct);
                    var (topLevel, transitive) = dotnetResult.ValueOr(([], []));

                    if (topLevel.Count > 0)
                    {
                        foreach (var r in topLevel)
                        {
                            if (allReferences.TryAdd(r.PackageId, r) && r.Version.Contains("$("))
                                hasUnresolvedVersions = true;
                        }
                        foreach (var r in transitive)
                        {
                            if (!allReferences.ContainsKey(r.PackageId))
                                transitiveReferences.TryAdd(r.PackageId, r);
                        }
                    }
                    else
                    {
                        usedFallbackParsing = true;
                        ctx.Status("Falling back to XML parsing...");
                        foreach (var projectFile in projectFiles)
                        {
                            var refsResult = await NuGetApiClient.ParseProjectFileAsync(projectFile, ct);
                            foreach (var r in refsResult.ValueOr([]))
                            {
                                if (allReferences.TryAdd(r.PackageId, r) && r.Version.Contains("$("))
                                    hasUnresolvedVersions = true;
                            }
                        }
                    }
                });

            incompleteTransitive = usedFallbackParsing && allReferences.Count == 0;

            if (allReferences.Count > 0)
            {
                AnsiConsole.MarkupLine($"[dim]Found {allReferences.Count} NuGet packages and {transitiveReferences.Count} transitive[/]");

                // Fetch NuGet info
                var nugetInfoMap = new ConcurrentDictionary<string, NuGetPackageInfo>(StringComparer.OrdinalIgnoreCase);
                var allPackageIds = allReferences.Keys.Concat(transitiveReferences.Keys).Distinct(StringComparer.OrdinalIgnoreCase).ToList();

                await AnsiConsole.Progress()
                    .StartAsync(async ctx =>
                    {
                        var task = ctx.AddTask($"Fetching NuGet info", maxValue: allPackageIds.Count);

                        // Fetch in parallel with concurrency limit for 3-5x speedup
                        using var semaphore = new SemaphoreSlim(10);
                        var tasks = allPackageIds.Select(async packageId =>
                        {
                            await semaphore.WaitAsync(ct);
                            try
                            {
                                var result = await nugetClient.GetPackageInfoAsync(packageId, ct);
                                if (result.IsSuccess)
                                {
                                    nugetInfoMap[packageId] = result.Value;
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

                            // Fetch in parallel with concurrency limit for 3-5x speedup
                            using var semaphore = new SemaphoreSlim(10);
                            var tasks = dependencyPackageIds.Select(async packageId =>
                            {
                                await semaphore.WaitAsync(ct);
                                try
                                {
                                    if (!nugetInfoMap.ContainsKey(packageId))
                                    {
                                        var result = await nugetClient.GetPackageInfoAsync(packageId, ct);
                                        if (result.IsSuccess)
                                        {
                                            nugetInfoMap[packageId] = result.Value;
                                        }
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
                }

                // Check NuGet vulnerabilities via OSV (free, no auth required)
                var nugetRepoInfoMap = new Dictionary<string, GitHubRepoInfo?>(StringComparer.OrdinalIgnoreCase);
                var allNuGetPackageIds = allPackageIds.Concat(dependencyPackageIds).ToList();

                using var osvNuGetClient = new OsvApiClient();
                await AnsiConsole.Status()
                    .StartAsync($"Checking NuGet vulnerabilities via OSV ({allNuGetPackageIds.Count} packages)...", async _ =>
                    {
                        var vulns = await osvNuGetClient.QueryNuGetPackagesAsync(allNuGetPackageIds, ct);
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
                                var results = await githubClient.GetRepositoriesBatchAsync(repoUrls!, ct);
                                foreach (var (packageId, info) in nugetInfoMap)
                                {
                                    var url = info.RepositoryUrl ?? info.ProjectUrl;
                                    if (url is not null && results.TryGetValue(url, out var repoInfo))
                                        nugetRepoInfoMap[packageId] = repoInfo;
                                }
                            }
                        });
                }

                // Collect CRA compliance data from NuGet packages
                allDeprecatedPackages.AddRange(nugetInfoMap.Values.Where(n => n.IsDeprecated).Select(n => n.PackageId));
                totalPackagesWithSecurityPolicy += nugetRepoInfoMap.Values.Count(r => r?.HasSecurityPolicy == true);
                totalPackagesWithRepo += nugetRepoInfoMap.Values.Count(r => r is not null);
                foreach (var kvp in nugetRepoInfoMap) allRepoInfoMap[kvp.Key] = kvp.Value;

                // Calculate health for NuGet packages
                foreach (var (packageId, reference) in allReferences)
                {
                    if (!nugetInfoMap.TryGetValue(packageId, out var nugetInfo)) continue;
                    nugetRepoInfoMap.TryGetValue(packageId, out var repoInfo);
                    if (!allVulnerabilities.TryGetValue(packageId, out var vulnerabilities))
                        vulnerabilities = [];
                    allPackages.Add(calculator.Calculate(packageId, reference.Version, nugetInfo, repoInfo, vulnerabilities));
                }

                foreach (var (packageId, reference) in transitiveReferences)
                {
                    if (!nugetInfoMap.TryGetValue(packageId, out var nugetInfo)) continue;
                    nugetRepoInfoMap.TryGetValue(packageId, out var repoInfo);
                    if (!allVulnerabilities.TryGetValue(packageId, out var vulnerabilities))
                        vulnerabilities = [];
                    allTransitivePackages.Add(calculator.Calculate(packageId, reference.Version, nugetInfo, repoInfo, vulnerabilities, DependencyType.Transitive));
                }

                // Build HashSet for O(1) lookups instead of O(n) Any() per iteration
                var transitivePackageIds = new HashSet<string>(
                    allTransitivePackages.Select(p => p.PackageId),
                    StringComparer.OrdinalIgnoreCase);

                foreach (var packageId in dependencyPackageIds)
                {
                    if (transitivePackageIds.Contains(packageId)) continue;
                    if (!nugetInfoMap.TryGetValue(packageId, out var nugetInfo)) continue;
                    nugetRepoInfoMap.TryGetValue(packageId, out var repoInfo);
                    if (!allVulnerabilities.TryGetValue(packageId, out var vulnerabilities))
                        vulnerabilities = [];
                    allTransitivePackages.Add(calculator.Calculate(packageId, nugetInfo.LatestVersion, nugetInfo, repoInfo, vulnerabilities, DependencyType.SubDependency));
                    transitivePackageIds.Add(packageId); // Keep in sync for subsequent iterations
                }

                // Build .NET dependency tree
                var dotnetTree = BuildDotNetDependencyTree(path, allReferences, transitiveReferences,
                    allPackages.Where(p => allReferences.ContainsKey(p.PackageId)).ToList(),
                    allTransitivePackages, allVulnerabilities);
                dependencyTrees.Add(dotnetTree);

                // Collect NuGet available versions for upgrade path analysis
                foreach (var (id, info) in nugetInfoMap)
                {
                    availableVersions[id] = info.Versions
                        .Where(v => v.IsListed)
                        .Select(v => v.Version)
                        .ToList();
                }
            }
        }

        // ===== Analyze npm packages =====
        AnsiConsole.MarkupLine("\n[bold green]Analyzing npm packages...[/]");

        var packageJsonFiles = NpmApiClient.FindPackageJsonFiles(path).ToList();
        if (packageJsonFiles.Count > 0)
        {
            var packageJsonPath = packageJsonFiles[0];
            AnsiConsole.MarkupLine($"[dim]Using: {packageJsonPath}[/]");

            var packageJsonResult = await NpmApiClient.ParsePackageJsonAsync(packageJsonPath, ct);
            if (packageJsonResult.IsSuccess)
            {
                var packageJson = packageJsonResult.Value;
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
                            npmTree = await npmClient.BuildDependencyTreeAsync(packageJsonPath, maxDepth: 10, ct);
                        });

                    // Extract transitive package IDs from tree BEFORE fetching
                    var directNpmPackageIds = new HashSet<string>(allDeps.Keys, StringComparer.OrdinalIgnoreCase);
                    var transitiveNpmPackageIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                    if (npmTree is not null)
                    {
                        CollectTransitivePackageIds(npmTree.Roots, directNpmPackageIds, transitiveNpmPackageIds);
                    }

                    // Compute all npm package IDs once (direct + transitive)
                    var allNpmPackageIds = allDeps.Keys.Concat(transitiveNpmPackageIds).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
                    var npmPackagesToFetch = deepScan ? allNpmPackageIds : allDeps.Keys.ToList();

                    // Fetch npm info in parallel (include transitive if deep scan)
                    var npmInfoMap = new ConcurrentDictionary<string, NpmPackageInfo>(StringComparer.OrdinalIgnoreCase);

                    await AnsiConsole.Progress()
                        .StartAsync(async ctx =>
                        {
                            var task = ctx.AddTask($"Fetching npm info for {npmPackagesToFetch.Count} packages", maxValue: npmPackagesToFetch.Count);
                            using var semaphore = new SemaphoreSlim(10);
                            var tasks = npmPackagesToFetch.Select(async packageName =>
                            {
                                await semaphore.WaitAsync(ct);
                                try
                                {
                                    var result = await npmClient.GetPackageInfoAsync(packageName, ct);
                                    if (result.IsSuccess) npmInfoMap[packageName] = result.Value;
                                }
                                finally
                                {
                                    semaphore.Release();
                                    task.Increment(1);
                                }
                            });
                            await Task.WhenAll(tasks);
                        });

                    // Check npm vulnerabilities via OSV (free, no auth required)
                    using var osvNpmClient = new OsvApiClient();
                    await AnsiConsole.Status()
                        .StartAsync($"Checking npm vulnerabilities via OSV ({allNpmPackageIds.Count} packages)...", async _ =>
                        {
                            var vulns = await osvNpmClient.QueryNpmPackagesAsync(allNpmPackageIds, ct);
                            foreach (var (name, v) in vulns)
                            {
                                allVulnerabilities.TryAdd(name, v);
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
                                    var results = await githubClient.GetRepositoriesBatchAsync(repoUrls!, ct);
                                    foreach (var (packageName, info) in npmInfoMap)
                                    {
                                        if (info.RepositoryUrl is not null && results.TryGetValue(info.RepositoryUrl, out var repoInfo))
                                            npmRepoInfoMap[packageName] = repoInfo;
                                    }
                                }
                            });
                    }

                    // Collect CRA compliance data from npm packages
                    allDeprecatedPackages.AddRange(npmInfoMap.Values.Where(n => n.IsDeprecated).Select(n => n.Name));
                    totalPackagesWithSecurityPolicy += npmRepoInfoMap.Values.Count(r => r?.HasSecurityPolicy == true);
                    totalPackagesWithRepo += npmRepoInfoMap.Values.Count(r => r is not null);
                    foreach (var kvp in npmRepoInfoMap) allRepoInfoMap[kvp.Key] = kvp.Value;

                    // Build lookup of installed versions from npm dependency tree
                    var npmInstalledVersions = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                    if (npmTree is not null)
                    {
                        foreach (var root in npmTree.Roots)
                        {
                            npmInstalledVersions[root.PackageId] = root.Version;
                        }
                    }

                    // Parse lock file for integrity hashes
                    var npmLockPath = Path.Combine(Path.GetDirectoryName(packageJsonPath) ?? ".", "package-lock.json");
                    var npmLockDepsResult = await NpmApiClient.ParsePackageLockAsync(npmLockPath, ct);
                    var npmLockDeps = npmLockDepsResult.ValueOr([]);
                    var npmIntegrityLookup = npmLockDeps
                        .Where(d => !string.IsNullOrEmpty(d.Integrity))
                        .GroupBy(d => d.Name, StringComparer.OrdinalIgnoreCase)
                        .ToDictionary(g => g.Key, g => g.First().Integrity!, StringComparer.OrdinalIgnoreCase);

                    // Calculate health for npm packages
                    foreach (var (packageName, _) in allDeps)
                    {
                        if (!npmInfoMap.TryGetValue(packageName, out var npmInfo)) continue;
                        npmRepoInfoMap.TryGetValue(packageName, out var repoInfo);
                        if (!allVulnerabilities.TryGetValue(packageName, out var vulnerabilities))
                            vulnerabilities = [];

                        // Use installed version from lock file, fall back to latest if not found
                        var installedVersion = npmInstalledVersions.GetValueOrDefault(packageName, npmInfo.LatestVersion);

                        var health = calculator.Calculate(packageName, installedVersion, npmInfo, repoInfo, vulnerabilities);

                        // Wire integrity hash from lock file
                        if (npmIntegrityLookup.TryGetValue(packageName, out var npmIntegrity))
                            health.ContentIntegrity = npmIntegrity;

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
                                npmInfoMap, npmRepoInfoMap, calculator, npmIntegrityLookup);
                            allTransitivePackages.AddRange(npmTransitiveFromTree);
                            AnsiConsole.MarkupLine($"[dim]Including {npmTransitiveFromTree.Count} transitive npm packages with full health data[/]");
                        }
                        else
                        {
                            // Minimal scan: only CRA scores (no full health metrics)
                            var npmTransitiveFromTree = ExtractTransitivePackagesFromTree(npmTree.Roots, directNpmPackageIds, allVulnerabilities, npmIntegrityLookup);
                            allTransitivePackages.AddRange(npmTransitiveFromTree);
                            AnsiConsole.MarkupLine($"[dim]Including {npmTransitiveFromTree.Count} transitive npm packages in SBOM[/]");
                        }
                    }

                    // Collect npm available versions for upgrade path analysis
                    foreach (var (name, info) in npmInfoMap)
                    {
                        availableVersions[name] = info.Versions
                            .Where(v => !v.IsDeprecated)
                            .Select(v => v.Version)
                            .ToList();
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
            hasUnresolvedVersions,
            startTime,
            licensesFormat,
            sbomFormat,
            allDeprecatedPackages,
            totalPackagesWithSecurityPolicy,
            totalPackagesWithRepo,
            typosquatResults,
            allRepoInfoMap,
            config,
            sign,
            signKey,
            releaseGate,
            evidencePack,
            auditMode,
            availableVersions,
            ct);
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
        bool hasUnresolvedVersions,
        DateTime startTime,
        LicenseOutputFormat? licensesFormat = null,
        SbomFormat? sbomFormat = null,
        List<string>? deprecatedPackages = null,
        int packagesWithSecurityPolicy = 0,
        int packagesWithRepo = 0,
        List<TyposquatResult>? typosquatResults = null,
        Dictionary<string, GitHubRepoInfo?>? repoInfoMap = null,
        CraConfig? config = null,
        bool sign = false,
        string? signKey = null,
        bool releaseGate = false,
        bool evidencePack = false,
        bool auditMode = false,
        Dictionary<string, List<string>>? availableVersions = null,
        CancellationToken ct = default)
    {
        // Build combined package list and lookups once — avoids repeated Concat/ToDictionary allocations
        var allPackages = packages.Concat(transitivePackages).ToList();
        var packageVersionLookup = new Dictionary<string, string>(allPackages.Count, StringComparer.OrdinalIgnoreCase);
        var packageLookup = new Dictionary<string, PackageHealth>(allPackages.Count, StringComparer.OrdinalIgnoreCase);
        foreach (var p in allPackages)
        {
            packageVersionLookup.TryAdd(p.PackageId, p.Version);
            packageLookup.TryAdd(p.PackageId, p);
        }

        var projectScore = HealthScoreCalculator.CalculateProjectScore(packages);
        var projectStatus = projectScore switch
        {
            >= 80 => HealthStatus.Healthy,
            >= 60 => HealthStatus.Watch,
            >= 40 => HealthStatus.Warning,
            _ => HealthStatus.Critical
        };

        // Single pass to count status categories (O(n) instead of O(5n))
        int healthyCount = 0, watchCount = 0, warningCount = 0, criticalCount = 0, vulnerableCount = 0;
        foreach (var p in packages)
        {
            switch (p.Status)
            {
                case HealthStatus.Healthy: healthyCount++; break;
                case HealthStatus.Watch: watchCount++; break;
                case HealthStatus.Warning: warningCount++; break;
                case HealthStatus.Critical: criticalCount++; break;
            }
            if (p.Vulnerabilities.Count > 0) vulnerableCount++;
        }

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
                HealthyCount = healthyCount,
                WatchCount = watchCount,
                WarningCount = warningCount,
                CriticalCount = criticalCount,
                VulnerableCount = vulnerableCount
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

        // Set additional CRA compliance data (passed from caller)
        reportGenerator.SetDeprecatedPackages(deprecatedPackages ?? []);
        reportGenerator.SetSecurityPolicyStats(packagesWithSecurityPolicy, packagesWithRepo);

        // Set maintenance data (F1/F2) - compute from repoInfoMap
        {
            var archived = new List<string>();
            var stale = new List<string>();
            var unmaintained = new List<string>();
            var totalWithRepo = 0;
            if (repoInfoMap is not null)
            {
                foreach (var (packageId, info) in repoInfoMap)
                {
                    if (info is null) continue;
                    totalWithRepo++;
                    if (info.IsArchived) { archived.Add(packageId); unmaintained.Add(packageId); }
                    else
                    {
                        var daysSinceCommit = (DateTime.UtcNow - info.LastCommitDate).TotalDays;
                        if (daysSinceCommit > 365) stale.Add(packageId);
                        if (daysSinceCommit > 730) unmaintained.Add(packageId);
                    }
                }
            }
            reportGenerator.SetMaintenanceData(archived, stale, unmaintained, totalWithRepo);
        }

        // Set documentation data (F3) - check project files
        {
            var projectDir = File.Exists(path) ? Path.GetDirectoryName(path)! : path;
            var hasReadme = File.Exists(Path.Combine(projectDir, "README.md")) ||
                            File.Exists(Path.Combine(projectDir, "readme.md"));
            var hasSecurityContact = File.Exists(Path.Combine(projectDir, "SECURITY.md")) ||
                                     File.Exists(Path.Combine(projectDir, ".well-known", "security.txt")) ||
                                     !string.IsNullOrEmpty(config?.SecurityContact);
            var hasSupportPeriod = !string.IsNullOrEmpty(config?.SupportPeriodEnd);
            var hasChangelog = File.Exists(Path.Combine(projectDir, "CHANGELOG.md")) ||
                              File.Exists(Path.Combine(projectDir, "CHANGES.md"));
            reportGenerator.SetProjectDocumentation(hasReadme, hasSecurityContact, hasSupportPeriod, hasChangelog);
        }

        // Set remediation data (F5) - cross-reference vulnerabilities with patches
        {
            var remediationData = new List<(string PackageId, string VulnId, int DaysSince, string PatchVersion)>();

            foreach (var (packageId, vulns) in allVulnerabilities)
            {
                if (!packageVersionLookup.TryGetValue(packageId, out var installedVersion))
                    continue;

                foreach (var vuln in vulns)
                {
                    if (string.IsNullOrEmpty(vuln.PatchedVersion) || vuln.PublishedAt is null)
                        continue;

                    if (!IsVersionInVulnerableRange(installedVersion, vuln))
                        continue;

                    var daysSince = (int)(DateTime.UtcNow - vuln.PublishedAt.Value).TotalDays;
                    remediationData.Add((packageId, vuln.Id, daysSince, vuln.PatchedVersion));
                }
            }
            reportGenerator.SetRemediationData(remediationData);
        }

        // Set attack surface data (F7)
        {
            var attackSurface = AttackSurfaceAnalyzer.Analyze(packages, transitivePackages, dependencyTrees);
            reportGenerator.SetAttackSurfaceData(attackSurface);
        }

        // CISA KEV check (map CVEs to packages, but only if current version is affected)
        using var kevService = new CisaKevService();
        await kevService.LoadCatalogAsync(ct);

        var kevCvePackages = allVulnerabilities
            .SelectMany(kv => kv.Value.SelectMany(v => v.Cves.Select(cve => (Cve: cve, PackageId: kv.Key, Vuln: v))))
            .Where(x => kevService.IsKnownExploited(x.Cve))
            .Where(x =>
            {
                if (!packageVersionLookup.TryGetValue(x.PackageId, out var installedVersion))
                    return false;
                return IsVersionInVulnerableRange(installedVersion, x.Vuln);
            })
            .Select(x => (x.Cve, x.PackageId))
            .DistinctBy(x => x.Cve)
            .ToList();
        reportGenerator.SetKnownExploitedVulnerabilities(kevCvePackages);

        // Mark packages with KEV vulnerabilities
        var kevPackageIds = new HashSet<string>(kevCvePackages.Select(k => k.PackageId), StringComparer.OrdinalIgnoreCase);
        var kevCvesByPackage = kevCvePackages.ToLookup(k => k.PackageId, k => k.Cve, StringComparer.OrdinalIgnoreCase);
        foreach (var pkg in allPackages.Where(p => kevPackageIds.Contains(p.PackageId)))
        {
            pkg.HasKevVulnerability = true;

            // Add KEV recommendation with CVE details
            var cves = kevCvesByPackage[pkg.PackageId].ToList();
            pkg.KevCves = cves;
            var cveList = string.Join(", ", cves);
            pkg.Recommendations.Insert(0, $"CRITICAL: This package has an actively exploited vulnerability ({cveList}) listed in CISA KEV. Update immediately or find an alternative.");
        }

        // EPSS enrichment - fetch exploit probability scores
        var allCves = allVulnerabilities.Values
            .SelectMany(v => v.SelectMany(vi => vi.Cves))
            .Where(c => !string.IsNullOrEmpty(c))
            .Distinct()
            .ToList();

        if (allCves.Count > 0)
        {
            using var epssService = new EpssService();
            var epssScores = await AnsiConsole.Status()
                .StartAsync("Fetching EPSS exploit probability scores...", async _ =>
                    await epssService.GetScoresAsync(allCves, ct));

            EnrichWithEpssScores(allVulnerabilities, packages, transitivePackages, epssScores);
            reportGenerator.SetEpssScores(epssScores);
        }

        // Populate patch timeliness data from remediation info for enhanced CRA scoring
        {
            foreach (var (packageId, vulns) in allVulnerabilities)
            {
                if (!packageVersionLookup.TryGetValue(packageId, out var installedVersion))
                    continue;

                var patchCount = 0;
                int? oldestDays = null;

                foreach (var vuln in vulns)
                {
                    if (string.IsNullOrEmpty(vuln.PatchedVersion) || vuln.PublishedAt is null)
                        continue;
                    if (!IsVersionInVulnerableRange(installedVersion, vuln))
                        continue;

                    patchCount++;
                    var days = (int)(DateTime.UtcNow - vuln.PublishedAt.Value).TotalDays;
                    if (!oldestDays.HasValue || days > oldestDays.Value)
                        oldestDays = days;
                }

                if (patchCount > 0 && packageLookup.TryGetValue(packageId, out var target))
                {
                    target.PatchAvailableNotAppliedCount = patchCount;
                    target.OldestUnpatchedVulnDays = oldestDays;
                }
            }
        }

        // Recalculate enhanced CRA scores after all enrichment (KEV, EPSS, integrity, patch data)
        foreach (var pkg in allPackages)
        {
            HealthScoreCalculator.RecalculateEnhancedCraScore(pkg);
        }

        // Crypto compliance check
        var allPackageTuples = allPackages
            .Select(p => (p.PackageId, p.Version))
            .ToList();
        var cryptoResult = CryptoComplianceChecker.Check(allPackageTuples);
        reportGenerator.SetCryptoCompliance(cryptoResult);
        if (typosquatResults is not null)
            reportGenerator.SetTyposquatResults(typosquatResults);

        // Package provenance check (F9)
        {
            using var provenanceChecker = new PackageProvenanceChecker();
            var allProvenanceResults = new List<ProvenanceResult>();

            var nugetPackages = allPackages
                .Where(p => p.Ecosystem == PackageEcosystem.NuGet)
                .Select(p => (p.PackageId, p.Version))
                .ToList();
            if (nugetPackages.Count > 0)
            {
                var nugetResults = await AnsiConsole.Status()
                    .StartAsync("Checking NuGet package provenance...", async _ =>
                        await provenanceChecker.CheckNuGetProvenanceAsync(nugetPackages, ct));
                allProvenanceResults.AddRange(nugetResults);
            }

            var npmPackages = allPackages
                .Where(p => p.Ecosystem == PackageEcosystem.Npm)
                .Select(p => (p.PackageId, p.Version))
                .ToList();
            if (npmPackages.Count > 0)
            {
                var npmResults = await AnsiConsole.Status()
                    .StartAsync("Checking npm package provenance...", async _ =>
                        await provenanceChecker.CheckNpmProvenanceAsync(npmPackages, ct));
                allProvenanceResults.AddRange(npmResults);
            }

            if (allProvenanceResults.Count > 0)
                reportGenerator.SetProvenanceResults(allProvenanceResults);
        }

        // Art. 14 Reporting Obligation Analysis
        {
            var kevCveSet = new HashSet<string>(kevCvePackages.Select(k => k.Cve), StringComparer.OrdinalIgnoreCase);
            var epssLookup = allVulnerabilities.Values
                .SelectMany(v => v.SelectMany(vi => vi.Cves.Where(c => vi.EpssProbability.HasValue)
                    .Select(c => new EpssScore { Cve = c, Probability = vi.EpssProbability!.Value, Percentile = vi.EpssPercentile ?? 0.0 })))
                .GroupBy(s => s.Cve, StringComparer.OrdinalIgnoreCase)
                .ToDictionary(g => g.Key, g => g.OrderByDescending(s => s.Probability).First(), StringComparer.OrdinalIgnoreCase);

            var reportingObligations = ReportingObligationAnalyzer.Analyze(allPackages, allVulnerabilities, kevCveSet, epssLookup);
            reportGenerator.SetReportingObligations(reportingObligations);
        }

        // Generate SBOM/VEX once, validate SBOM, then build final report
        var (sbom, vex) = reportGenerator.GenerateArtifacts(healthReport, allVulnerabilities);
        reportGenerator.SetSbomValidation(SbomValidator.Validate(sbom));
        var craReport = reportGenerator.Generate(healthReport, allVulnerabilities, sbom, vex, startTime);

        // Remediation Roadmap (needs CRA score from report for prioritization)
        List<RemediationRoadmapItem> roadmap;
        {
            roadmap = RemediationPrioritizer.PrioritizeUpdates(allPackages, allVulnerabilities, craReport.CraReadinessScore, craReport.ComplianceItems, availableVersions);
            reportGenerator.SetRemediationRoadmap(roadmap);
        }

        // Audit simulation (when --audit-mode active)
        if (auditMode)
        {
            var projectDir = File.Exists(path) ? Path.GetDirectoryName(path)! : path;
            var auditHasSecurityPolicy = File.Exists(Path.Combine(projectDir, "SECURITY.md")) ||
                                          File.Exists(Path.Combine(projectDir, ".well-known", "security.txt"));
            var auditHasReadme = File.Exists(Path.Combine(projectDir, "README.md")) ||
                                  File.Exists(Path.Combine(projectDir, "readme.md"));
            var auditHasChangelog = File.Exists(Path.Combine(projectDir, "CHANGELOG.md")) ||
                                     File.Exists(Path.Combine(projectDir, "CHANGES.md"));

            var auditResult = AuditSimulator.Analyze(
                allPackages,
                allVulnerabilities,
                craReport,
                reportGenerator.GetSbomValidation(),
                reportGenerator.GetProvenanceResults(),
                reportGenerator.GetAttackSurface(),
                auditHasSecurityPolicy,
                packagesWithSecurityPolicy,
                packagesWithRepo,
                config,
                auditHasReadme,
                auditHasChangelog);
            reportGenerator.SetAuditFindings(auditResult);
        }

        reportGenerator.SetMaintainerTrustData(allPackages);

        // Phase 1 actionable findings for HTML dashboard
        {
            var budget = SecurityBudgetOptimizer.Optimize(roadmap);
            reportGenerator.SetSecurityBudget(budget);

            var readiness = ReleaseReadinessEvaluator.Evaluate(craReport, [], auditMode ? reportGenerator.GetAuditSimulation() : null);
            reportGenerator.SetReleaseReadiness(readiness);

            LicensePolicyResult? licenseResult = null;
            if (config is not null && (config.AllowedLicenses.Count > 0 || config.BlockedLicenses.Count > 0))
                licenseResult = LicensePolicyEvaluator.Evaluate(allPackages, config);
            reportGenerator.SetPolicyViolations(licenseResult, config);
        }

        if (string.IsNullOrEmpty(outputPath))
        {
            var projectName = Path.GetFileNameWithoutExtension(path);
            outputPath = format == CraOutputFormat.Json
                ? $"{projectName}-cra-report.json"
                : $"{projectName}-cra-report.html";
        }

        // Generate license attribution if requested (before HTML so we can link to it)
        string? licenseFilePath = null;
        if (licensesFormat.HasValue)
        {
            licenseFilePath = await GenerateLicenseAttributionAsync(packages, transitivePackages, licensesFormat.Value, path, ct);
        }

        // Generate SBOM if requested
        string? sbomFilePath = null;
        if (sbomFormat.HasValue)
        {
            sbomFilePath = await GenerateSbomAsync(packages, transitivePackages, sbomFormat.Value, path, ct);
        }

        var output = format == CraOutputFormat.Json
            ? reportGenerator.GenerateJson(craReport)
            : reportGenerator.GenerateHtml(craReport, licenseFilePath);

        await File.WriteAllTextAsync(outputPath, output, ct);

        // Sign artifacts if requested
        await SignArtifactsAsync(sign, signKey, outputPath, licenseFilePath, sbomFilePath, ct);

        // Generate evidence pack if requested
        if (evidencePack)
        {
            await GenerateEvidencePackAsync(path, packages, transitivePackages, reportGenerator, craReport, licenseFilePath, ct);
        }

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

        if (sbomFilePath is not null)
        {
            AnsiConsole.MarkupLine($"[bold]SBOM:[/] {sbomFilePath}");
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

        AnsiConsole.MarkupLine($"\n[bold]CRA Readiness Score:[/] {craReport.CraReadinessScore}/100");

        DisplaySecurityBudgetSummary(roadmap);

        AnsiConsole.MarkupLine($"\n[green]Report written to {outputPath}[/]");

        var auditResultForExit = auditMode ? reportGenerator.GetAuditSimulation() : null;
        var (exitCode, violations) = EvaluateExitCode(craReport, config, allPackages, auditResultForExit);

        if (releaseGate)
            exitCode = DisplayReleaseReadiness(craReport, violations, exitCode, auditResultForExit);

        return exitCode;
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
        if (!vulnerabilities.TryGetValue(packageId, out var vulnList))
            vulnList = [];
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
                var childVersion = ExtractVersionFromRange(dep.VersionRange) ?? "latest";
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
        var visited = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        void Visit(DependencyTreeNode node)
        {
            var key = $"{node.PackageId}@{node.Version}";
            if (!visited.Add(key)) return;

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
        var visited = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        void Visit(DependencyTreeNode node)
        {
            var key = $"{node.PackageId}@{node.Version}";
            if (!visited.Add(key)) return;

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
        var visited = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        // Returns true if this node or any descendant has vulnerabilities
        bool Visit(DependencyTreeNode node)
        {
            var key = $"{node.PackageId}@{node.Version}";
            if (!visited.Add(key))
                return node.HasVulnerabilities || node.HasVulnerableDescendant;

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
        var visitedCollect = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        void CollectVersions(DependencyTreeNode node)
        {
            var key = $"{node.PackageId}@{node.Version}";
            if (!visitedCollect.Add(key)) return;

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
        var visitedMark = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        void MarkConflicts(DependencyTreeNode node)
        {
            var key = $"{node.PackageId}@{node.Version}";
            if (!visitedMark.Add(key)) return;

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

    private static void EnrichWithEpssScores(
        Dictionary<string, List<VulnerabilityInfo>> allVulnerabilities,
        List<PackageHealth> packages,
        List<PackageHealth> transitivePackages,
        Dictionary<string, EpssScore> epssScores)
    {
        // Enrich individual vulnerabilities
        foreach (var (_, vulns) in allVulnerabilities)
        {
            foreach (var vuln in vulns)
            {
                EpssScore? maxEpss = null;
                foreach (var c in vuln.Cves)
                {
                    if (epssScores.TryGetValue(c, out var score) && (maxEpss is null || score.Probability > maxEpss.Probability))
                        maxEpss = score;
                }

                if (maxEpss is not null)
                {
                    vuln.EpssProbability = maxEpss.Probability;
                    vuln.EpssPercentile = maxEpss.Percentile;
                }
            }
        }

        // Enrich packages with max EPSS across their ACTIVE vulnerabilities only
        // (not all CVEs ever reported against the package name)
        foreach (var pkg in packages.Concat(transitivePackages))
        {
            if (pkg.Vulnerabilities.Count == 0 || !allVulnerabilities.TryGetValue(pkg.PackageId, out var pkgVulns))
                continue;

            // Only consider vulnerabilities that affect the installed version
            var activeVulnIds = new HashSet<string>(pkg.Vulnerabilities, StringComparer.OrdinalIgnoreCase);
            var maxPkgEpss = pkgVulns
                .Where(v => v.EpssProbability.HasValue && activeVulnIds.Contains(v.Id))
                .MaxBy(v => v.EpssProbability);

            if (maxPkgEpss is not null)
            {
                pkg.MaxEpssProbability = maxPkgEpss.EpssProbability;
                pkg.MaxEpssPercentile = maxPkgEpss.EpssPercentile;

                // Flag high EPSS packages for CRA compliance
                if (maxPkgEpss.EpssProbability >= 0.1 && pkg.CraStatus < CraComplianceStatus.ActionRequired)
                {
                    pkg.CraStatus = CraComplianceStatus.ActionRequired;
                }
            }
        }
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
        IDictionary<string, NpmPackageInfo> npmInfoMap,
        Dictionary<string, GitHubRepoInfo?> repoInfoMap,
        CancellationToken ct = default)
    {
        await AnsiConsole.Status()
            .StartAsync("Fetching GitHub repository info (batch)...", async ctx =>
            {
                var validUrls = repoUrls
                    .Where(u => u.Contains("github.com", StringComparison.OrdinalIgnoreCase))
                    .ToList();

                if (validUrls.Count > 0)
                {
                    var results = await githubClient.GetRepositoriesBatchAsync(validUrls, ct);

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

    private static async Task<int> GenerateReportAsync(
        string path,
        List<PackageHealth> packages,
        List<PackageHealth> transitivePackages,
        Dictionary<string, List<VulnerabilityInfo>> allVulnerabilities,
        DependencyTree? dependencyTree,
        CraOutputFormat format,
        string? outputPath,
        bool incompleteTransitive,
        bool hasUnresolvedVersions,
        DateTime startTime,
        LicenseOutputFormat? licensesFormat = null,
        SbomFormat? sbomFormat = null,
        List<string>? deprecatedPackages = null,
        int packagesWithSecurityPolicy = 0,
        int packagesWithRepo = 0,
        List<TyposquatResult>? typosquatResults = null,
        Dictionary<string, GitHubRepoInfo?>? repoInfoMap = null,
        CraConfig? config = null,
        bool sign = false,
        string? signKey = null,
        bool releaseGate = false,
        bool evidencePack = false,
        bool auditMode = false,
        Dictionary<string, List<string>>? availableVersions = null,
        CancellationToken ct = default)
    {
        // Build combined package list and lookups once — avoids repeated Concat/ToDictionary allocations
        var allPackages = packages.Concat(transitivePackages).ToList();
        var packageVersionLookup = new Dictionary<string, string>(allPackages.Count, StringComparer.OrdinalIgnoreCase);
        var packageLookup = new Dictionary<string, PackageHealth>(allPackages.Count, StringComparer.OrdinalIgnoreCase);
        foreach (var p in allPackages)
        {
            packageVersionLookup.TryAdd(p.PackageId, p.Version);
            packageLookup.TryAdd(p.PackageId, p);
        }

        // Calculate project score
        var projectScore = HealthScoreCalculator.CalculateProjectScore(packages);
        var projectStatus = projectScore switch
        {
            >= 80 => HealthStatus.Healthy,
            >= 60 => HealthStatus.Watch,
            >= 40 => HealthStatus.Warning,
            _ => HealthStatus.Critical
        };

        // Single pass to count status categories (O(n) instead of O(5n))
        int healthyCount = 0, watchCount = 0, warningCount = 0, criticalCount = 0, vulnerableCount = 0;
        foreach (var p in packages)
        {
            switch (p.Status)
            {
                case HealthStatus.Healthy: healthyCount++; break;
                case HealthStatus.Watch: watchCount++; break;
                case HealthStatus.Warning: warningCount++; break;
                case HealthStatus.Critical: criticalCount++; break;
            }
            if (p.Vulnerabilities.Count > 0) vulnerableCount++;
        }

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
                HealthyCount = healthyCount,
                WatchCount = watchCount,
                WarningCount = warningCount,
                CriticalCount = criticalCount,
                VulnerableCount = vulnerableCount
            }
        };

        var reportGenerator = new CraReportGenerator();
        reportGenerator.SetHealthData(packages);
        reportGenerator.SetTransitiveData(transitivePackages);
        reportGenerator.SetCompletenessWarnings(incompleteTransitive, hasUnresolvedVersions);
        reportGenerator.SetDependencyTree(dependencyTree);

        // Set additional CRA compliance data (passed from caller)
        reportGenerator.SetDeprecatedPackages(deprecatedPackages ?? []);
        reportGenerator.SetSecurityPolicyStats(packagesWithSecurityPolicy, packagesWithRepo);

        // Set maintenance data (F1/F2) - compute from repoInfoMap
        {
            var archived = new List<string>();
            var stale = new List<string>();
            var unmaintained = new List<string>();
            var totalWithRepo = 0;
            if (repoInfoMap is not null)
            {
                foreach (var (packageId, info) in repoInfoMap)
                {
                    if (info is null) continue;
                    totalWithRepo++;
                    if (info.IsArchived) { archived.Add(packageId); unmaintained.Add(packageId); }
                    else
                    {
                        var daysSinceCommit = (DateTime.UtcNow - info.LastCommitDate).TotalDays;
                        if (daysSinceCommit > 365) stale.Add(packageId);
                        if (daysSinceCommit > 730) unmaintained.Add(packageId);
                    }
                }
            }
            reportGenerator.SetMaintenanceData(archived, stale, unmaintained, totalWithRepo);
        }

        // Set documentation data (F3) - check project files
        {
            var projectDir = File.Exists(path) ? Path.GetDirectoryName(path)! : path;
            var hasReadme = File.Exists(Path.Combine(projectDir, "README.md")) ||
                            File.Exists(Path.Combine(projectDir, "readme.md"));
            var hasSecurityContact = File.Exists(Path.Combine(projectDir, "SECURITY.md")) ||
                                     File.Exists(Path.Combine(projectDir, ".well-known", "security.txt")) ||
                                     !string.IsNullOrEmpty(config?.SecurityContact);
            var hasSupportPeriod = !string.IsNullOrEmpty(config?.SupportPeriodEnd);
            var hasChangelog = File.Exists(Path.Combine(projectDir, "CHANGELOG.md")) ||
                              File.Exists(Path.Combine(projectDir, "CHANGES.md"));
            reportGenerator.SetProjectDocumentation(hasReadme, hasSecurityContact, hasSupportPeriod, hasChangelog);
        }

        // Set remediation data (F5) - cross-reference vulnerabilities with patches
        {
            var remediationData = new List<(string PackageId, string VulnId, int DaysSince, string PatchVersion)>();

            foreach (var (packageId, vulns) in allVulnerabilities)
            {
                if (!packageVersionLookup.TryGetValue(packageId, out var installedVersion))
                    continue;

                foreach (var vuln in vulns)
                {
                    if (string.IsNullOrEmpty(vuln.PatchedVersion) || vuln.PublishedAt is null)
                        continue;

                    // Check if the installed version is still in the vulnerable range
                    if (!IsVersionInVulnerableRange(installedVersion, vuln))
                        continue;

                    var daysSince = (int)(DateTime.UtcNow - vuln.PublishedAt.Value).TotalDays;
                    remediationData.Add((packageId, vuln.Id, daysSince, vuln.PatchedVersion));
                }
            }
            reportGenerator.SetRemediationData(remediationData);
        }

        // Set attack surface data (F7)
        {
            var trees = dependencyTree is not null ? new List<DependencyTree> { dependencyTree } : new List<DependencyTree>();
            var attackSurface = AttackSurfaceAnalyzer.Analyze(packages, transitivePackages, trees);
            reportGenerator.SetAttackSurfaceData(attackSurface);
        }

        // CISA KEV check (map CVEs to packages, but only if current version is affected)
        using var kevService = new CisaKevService();
        await kevService.LoadCatalogAsync(ct);

        var kevCvePackages = allVulnerabilities
            .SelectMany(kv => kv.Value.SelectMany(v => v.Cves.Select(cve => (Cve: cve, PackageId: kv.Key, Vuln: v))))
            .Where(x => kevService.IsKnownExploited(x.Cve))
            .Where(x =>
            {
                // Only flag if installed version is actually in the vulnerable range
                if (!packageVersionLookup.TryGetValue(x.PackageId, out var installedVersion))
                    return false;
                return IsVersionInVulnerableRange(installedVersion, x.Vuln);
            })
            .Select(x => (x.Cve, x.PackageId))
            .DistinctBy(x => x.Cve)
            .ToList();
        reportGenerator.SetKnownExploitedVulnerabilities(kevCvePackages);

        // Mark packages with KEV vulnerabilities
        var kevPackageIds = new HashSet<string>(kevCvePackages.Select(k => k.PackageId), StringComparer.OrdinalIgnoreCase);
        var kevCvesByPackage = kevCvePackages.ToLookup(k => k.PackageId, k => k.Cve, StringComparer.OrdinalIgnoreCase);
        foreach (var pkg in allPackages.Where(p => kevPackageIds.Contains(p.PackageId)))
        {
            pkg.HasKevVulnerability = true;

            // Add KEV recommendation with CVE details
            var cves = kevCvesByPackage[pkg.PackageId].ToList();
            pkg.KevCves = cves;
            var cveList = string.Join(", ", cves);
            pkg.Recommendations.Insert(0, $"CRITICAL: This package has an actively exploited vulnerability ({cveList}) listed in CISA KEV. Update immediately or find an alternative.");
        }

        // EPSS enrichment - fetch exploit probability scores
        var allCves = allVulnerabilities.Values
            .SelectMany(v => v.SelectMany(vi => vi.Cves))
            .Where(c => !string.IsNullOrEmpty(c))
            .Distinct()
            .ToList();

        if (allCves.Count > 0)
        {
            using var epssService = new EpssService();
            var epssScores = await AnsiConsole.Status()
                .StartAsync("Fetching EPSS exploit probability scores...", async _ =>
                    await epssService.GetScoresAsync(allCves, ct));

            EnrichWithEpssScores(allVulnerabilities, packages, transitivePackages, epssScores);
            reportGenerator.SetEpssScores(epssScores);
        }

        // Populate patch timeliness data from remediation info for enhanced CRA scoring
        {
            foreach (var (packageId, vulns) in allVulnerabilities)
            {
                if (!packageVersionLookup.TryGetValue(packageId, out var installedVersion))
                    continue;

                var patchCount = 0;
                int? oldestDays = null;

                foreach (var vuln in vulns)
                {
                    if (string.IsNullOrEmpty(vuln.PatchedVersion) || vuln.PublishedAt is null)
                        continue;
                    if (!IsVersionInVulnerableRange(installedVersion, vuln))
                        continue;

                    patchCount++;
                    var days = (int)(DateTime.UtcNow - vuln.PublishedAt.Value).TotalDays;
                    if (!oldestDays.HasValue || days > oldestDays.Value)
                        oldestDays = days;
                }

                if (patchCount > 0 && packageLookup.TryGetValue(packageId, out var target))
                {
                    target.PatchAvailableNotAppliedCount = patchCount;
                    target.OldestUnpatchedVulnDays = oldestDays;
                }
            }
        }

        // Recalculate enhanced CRA scores after all enrichment (KEV, EPSS, integrity, patch data)
        foreach (var pkg in allPackages)
        {
            HealthScoreCalculator.RecalculateEnhancedCraScore(pkg);
        }

        // 4. Crypto compliance check
        var allPackageTuples = allPackages
            .Select(p => (p.PackageId, p.Version))
            .ToList();
        var cryptoResult = CryptoComplianceChecker.Check(allPackageTuples);
        reportGenerator.SetCryptoCompliance(cryptoResult);
        if (typosquatResults is not null)
            reportGenerator.SetTyposquatResults(typosquatResults);

        // Package provenance check (F9)
        {
            using var provenanceChecker = new PackageProvenanceChecker();
            var allProvenanceResults = new List<ProvenanceResult>();

            var nugetPackages = allPackages
                .Where(p => p.Ecosystem == PackageEcosystem.NuGet)
                .Select(p => (p.PackageId, p.Version))
                .ToList();
            if (nugetPackages.Count > 0)
            {
                var nugetResults = await AnsiConsole.Status()
                    .StartAsync("Checking NuGet package provenance...", async _ =>
                        await provenanceChecker.CheckNuGetProvenanceAsync(nugetPackages, ct));
                allProvenanceResults.AddRange(nugetResults);
            }

            var npmPackages = allPackages
                .Where(p => p.Ecosystem == PackageEcosystem.Npm)
                .Select(p => (p.PackageId, p.Version))
                .ToList();
            if (npmPackages.Count > 0)
            {
                var npmResults = await AnsiConsole.Status()
                    .StartAsync("Checking npm package provenance...", async _ =>
                        await provenanceChecker.CheckNpmProvenanceAsync(npmPackages, ct));
                allProvenanceResults.AddRange(npmResults);
            }

            if (allProvenanceResults.Count > 0)
                reportGenerator.SetProvenanceResults(allProvenanceResults);
        }

        // Art. 14 Reporting Obligation Analysis
        {
            var kevCveSet = new HashSet<string>(kevCvePackages.Select(k => k.Cve), StringComparer.OrdinalIgnoreCase);
            var epssLookup = allVulnerabilities.Values
                .SelectMany(v => v.SelectMany(vi => vi.Cves.Where(c => vi.EpssProbability.HasValue)
                    .Select(c => new EpssScore { Cve = c, Probability = vi.EpssProbability!.Value, Percentile = vi.EpssPercentile ?? 0.0 })))
                .GroupBy(s => s.Cve, StringComparer.OrdinalIgnoreCase)
                .ToDictionary(g => g.Key, g => g.OrderByDescending(s => s.Probability).First(), StringComparer.OrdinalIgnoreCase);

            var reportingObligations = ReportingObligationAnalyzer.Analyze(allPackages, allVulnerabilities, kevCveSet, epssLookup);
            reportGenerator.SetReportingObligations(reportingObligations);
        }

        // Generate SBOM/VEX once, validate SBOM, then build final report
        var (sbom, vex) = reportGenerator.GenerateArtifacts(healthReport, allVulnerabilities);
        reportGenerator.SetSbomValidation(SbomValidator.Validate(sbom));
        var craReport = reportGenerator.Generate(healthReport, allVulnerabilities, sbom, vex, startTime);

        // Remediation Roadmap (needs CRA score from report for prioritization)
        List<RemediationRoadmapItem> roadmap;
        {
            roadmap = RemediationPrioritizer.PrioritizeUpdates(allPackages, allVulnerabilities, craReport.CraReadinessScore, craReport.ComplianceItems, availableVersions);
            reportGenerator.SetRemediationRoadmap(roadmap);
        }

        // Audit simulation (when --audit-mode active)
        if (auditMode)
        {
            var projectDir = File.Exists(path) ? Path.GetDirectoryName(path)! : path;
            var auditHasSecurityPolicy = File.Exists(Path.Combine(projectDir, "SECURITY.md")) ||
                                          File.Exists(Path.Combine(projectDir, ".well-known", "security.txt"));
            var auditHasReadme = File.Exists(Path.Combine(projectDir, "README.md")) ||
                                  File.Exists(Path.Combine(projectDir, "readme.md"));
            var auditHasChangelog = File.Exists(Path.Combine(projectDir, "CHANGELOG.md")) ||
                                     File.Exists(Path.Combine(projectDir, "CHANGES.md"));

            var auditResult = AuditSimulator.Analyze(
                allPackages,
                allVulnerabilities,
                craReport,
                reportGenerator.GetSbomValidation(),
                reportGenerator.GetProvenanceResults(),
                reportGenerator.GetAttackSurface(),
                auditHasSecurityPolicy,
                packagesWithSecurityPolicy,
                packagesWithRepo,
                config,
                auditHasReadme,
                auditHasChangelog);
            reportGenerator.SetAuditFindings(auditResult);
        }

        reportGenerator.SetMaintainerTrustData(allPackages);

        // Phase 1 actionable findings for HTML dashboard
        {
            var budget = SecurityBudgetOptimizer.Optimize(roadmap);
            reportGenerator.SetSecurityBudget(budget);

            var readiness = ReleaseReadinessEvaluator.Evaluate(craReport, [], auditMode ? reportGenerator.GetAuditSimulation() : null);
            reportGenerator.SetReleaseReadiness(readiness);

            LicensePolicyResult? licenseResult = null;
            if (config is not null && (config.AllowedLicenses.Count > 0 || config.BlockedLicenses.Count > 0))
                licenseResult = LicensePolicyEvaluator.Evaluate(allPackages, config);
            reportGenerator.SetPolicyViolations(licenseResult, config);
        }

        // Determine output path
        if (string.IsNullOrEmpty(outputPath))
        {
            var projectName = Path.GetFileNameWithoutExtension(path);
            outputPath = format == CraOutputFormat.Json
                ? $"{projectName}-cra-report.json"
                : $"{projectName}-cra-report.html";
        }

        // Generate license attribution if requested (before HTML so we can link to it)
        string? licenseFilePath = null;
        if (licensesFormat.HasValue)
        {
            licenseFilePath = await GenerateLicenseAttributionAsync(packages, transitivePackages, licensesFormat.Value, path, ct);
        }

        // Generate SBOM if requested
        string? sbomFilePath = null;
        if (sbomFormat.HasValue)
        {
            sbomFilePath = await GenerateSbomAsync(packages, transitivePackages, sbomFormat.Value, path, ct);
        }

        string output;
        if (format == CraOutputFormat.Json)
        {
            output = reportGenerator.GenerateJson(craReport);
        }
        else
        {
            output = reportGenerator.GenerateHtml(craReport, licenseFilePath);
        }

        await File.WriteAllTextAsync(outputPath, output, ct);

        // Sign artifacts if requested
        await SignArtifactsAsync(sign, signKey, outputPath, licenseFilePath, sbomFilePath, ct);

        // Generate evidence pack if requested
        if (evidencePack)
        {
            await GenerateEvidencePackAsync(path, packages, transitivePackages, reportGenerator, craReport, licenseFilePath, ct);
        }

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

        if (sbomFilePath is not null)
        {
            AnsiConsole.MarkupLine($"[bold]SBOM:[/] {sbomFilePath}");
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

        AnsiConsole.MarkupLine($"\n[bold]CRA Readiness Score:[/] {craReport.CraReadinessScore}/100");

        DisplaySecurityBudgetSummary(roadmap);

        AnsiConsole.MarkupLine($"\n[green]Report written to {outputPath}[/]");

        var auditResultForExit = auditMode ? reportGenerator.GetAuditSimulation() : null;
        var (exitCode, violations) = EvaluateExitCode(craReport, config, allPackages, auditResultForExit);

        if (releaseGate)
            exitCode = DisplayReleaseReadiness(craReport, violations, exitCode, auditResultForExit);

        return exitCode;
    }

    /// <summary>
    /// Evaluate CI/CD exit code based on report data and config thresholds.
    /// Returns exit code (0=pass, 1=non-compliant, 2=policy violation) and the list of violations.
    /// </summary>
    private static (int ExitCode, List<string> Violations) EvaluateExitCode(
        CraReport report,
        CraConfig? config,
        IReadOnlyList<PackageHealth>? packages = null,
        AuditSimulationResult? auditResult = null)
    {
        var violations = new List<string>();

        // Check config-driven thresholds (exit code 2 = policy violation)
        if (config is not null)
        {
            if (config.FailOnKev)
            {
                var kevItem = report.ComplianceItems.FirstOrDefault(i =>
                    i.Requirement.Contains("CISA KEV", StringComparison.OrdinalIgnoreCase));
                if (kevItem?.Status == CraComplianceStatus.NonCompliant)
                    violations.Add("CISA KEV vulnerability detected");
            }

            if (config.FailOnEpssThreshold.HasValue)
            {
                var epssItem = report.ComplianceItems.FirstOrDefault(i =>
                    i.Requirement.Contains("EPSS", StringComparison.OrdinalIgnoreCase));
                if (epssItem?.Status != CraComplianceStatus.Compliant)
                    violations.Add($"EPSS threshold exceeded ({config.FailOnEpssThreshold.Value:P0})");
            }

            if (config.FailOnVulnerabilityCount.HasValue && report.VulnerabilityCount > config.FailOnVulnerabilityCount.Value)
                violations.Add($"Vulnerability count {report.VulnerabilityCount} exceeds threshold {config.FailOnVulnerabilityCount.Value}");

            if (config.FailOnCraReadinessBelow.HasValue && report.CraReadinessScore < config.FailOnCraReadinessBelow.Value)
                violations.Add($"CRA readiness score {report.CraReadinessScore} below threshold {config.FailOnCraReadinessBelow.Value}");

            if (config.FailOnReportableVulnerabilities && report.ReportableVulnerabilityCount > 0)
                violations.Add($"CRA Art. 14 reportable vulnerabilities detected ({report.ReportableVulnerabilityCount})");

            if (config.FailOnUnpatchedDaysOver.HasValue && report.MaxUnpatchedVulnerabilityDays.HasValue
                && report.MaxUnpatchedVulnerabilityDays.Value > config.FailOnUnpatchedDaysOver.Value)
                violations.Add($"Unpatched vulnerability age {report.MaxUnpatchedVulnerabilityDays.Value} days exceeds threshold {config.FailOnUnpatchedDaysOver.Value}");

            if (config.FailOnUnmaintainedPackages && report.HasUnmaintainedPackages)
                violations.Add("Unmaintained packages detected (no activity 2+ years)");

            if (config.FailOnSbomCompletenessBelow.HasValue && report.SbomCompletenessPercentage.HasValue
                && report.SbomCompletenessPercentage.Value < config.FailOnSbomCompletenessBelow.Value)
                violations.Add($"SBOM completeness {report.SbomCompletenessPercentage.Value}% below threshold {config.FailOnSbomCompletenessBelow.Value}%");

            if (config.FailOnAttackSurfaceDepthOver.HasValue && report.MaxDependencyDepth.HasValue
                && report.MaxDependencyDepth.Value > config.FailOnAttackSurfaceDepthOver.Value)
                violations.Add($"Dependency tree depth {report.MaxDependencyDepth.Value} exceeds threshold {config.FailOnAttackSurfaceDepthOver.Value}");

            // License policy checks
            if (packages is not null && (config.AllowedLicenses.Count > 0 || config.BlockedLicenses.Count > 0))
            {
                var licenseResult = LicensePolicyEvaluator.Evaluate(packages, config);
                foreach (var v in licenseResult.Violations)
                    violations.Add($"License policy: {v.PackageId} — {v.Reason}");
            }

            // Deprecated packages gate
            if (config.FailOnDeprecatedPackages && report.DeprecatedPackages.Count > 0)
                violations.Add($"Deprecated packages detected: {string.Join(", ", report.DeprecatedPackages)}");

            // Minimum health score gate
            if (config.MinHealthScore.HasValue && report.MinPackageHealthScore.HasValue
                && report.MinPackageHealthScore.Value < config.MinHealthScore.Value)
                violations.Add($"Package '{report.MinHealthScorePackage}' health score {report.MinPackageHealthScore.Value} below minimum {config.MinHealthScore.Value}");
        }

        // Audit simulation findings (Critical + High = violations)
        if (auditResult is not null)
        {
            foreach (var finding in auditResult.Findings.Where(f => f.Severity is AuditSeverity.Critical or AuditSeverity.High))
            {
                violations.Add($"Audit: {finding.ArticleReference} \u2014 {finding.Requirement}");
            }
        }

        if (violations.Count > 0)
        {
            AnsiConsole.MarkupLine("\n[red bold]CI/CD Policy Violations:[/]");
            foreach (var v in violations)
                AnsiConsole.MarkupLine($"  [red]\u2022 {v}[/]");
            return (2, violations);
        }

        var exitCode = report.OverallComplianceStatus == CraComplianceStatus.NonCompliant ? 1 : 0;
        return (exitCode, violations);
    }

    private static int DisplayReleaseReadiness(CraReport report, List<string> violations, int currentExitCode, AuditSimulationResult? auditResult = null)
    {
        var readiness = ReleaseReadinessEvaluator.Evaluate(report, violations, auditResult);

        AnsiConsole.WriteLine();
        AnsiConsole.Write(new Rule("[bold]Release Readiness Gate[/]").LeftJustified());

        if (readiness.IsReady)
        {
            AnsiConsole.MarkupLine("[green bold]GO[/] \u2014 No blocking issues found");
        }
        else
        {
            AnsiConsole.MarkupLine("[red bold]NO-GO[/] \u2014 Blocking issues must be resolved before release");
            AnsiConsole.WriteLine();
            AnsiConsole.MarkupLine("[red bold]Blockers:[/]");
            foreach (var blocker in readiness.BlockingItems)
                AnsiConsole.MarkupLine($"  [red]\u2022 {Markup.Escape(blocker.Requirement)}:[/] {Markup.Escape(blocker.Reason)}");
        }

        if (readiness.AdvisoryItems.Count > 0)
        {
            AnsiConsole.WriteLine();
            AnsiConsole.MarkupLine("[yellow bold]Advisory:[/]");
            foreach (var advisory in readiness.AdvisoryItems)
                AnsiConsole.MarkupLine($"  [yellow]\u2022 {Markup.Escape(advisory)}[/]");
        }

        // Override exit code to 2 if there are blocking issues
        return readiness.IsReady ? currentExitCode : Math.Max(currentExitCode, 2);
    }

    private static void DisplaySecurityBudgetSummary(List<RemediationRoadmapItem> roadmap)
    {
        if (roadmap.Count == 0)
            return;

        var budget = SecurityBudgetOptimizer.Optimize(roadmap);
        var highRoiItems = budget.Items.Where(i => i.Tier == RemediationTier.HighROI).ToList();

        if (highRoiItems.Count == 0)
            return;

        AnsiConsole.WriteLine();
        AnsiConsole.Write(new Rule("[bold]Security Budget Optimizer[/]").LeftJustified());
        AnsiConsole.MarkupLine($"[bold]Fix {highRoiItems.Count} item(s) to reduce [green]{budget.HighROIPercentage:F0}%[/] of risk[/]");

        var table = new Table()
            .Border(TableBorder.Simple)
            .AddColumn("Package")
            .AddColumn("Effort")
            .AddColumn("ROI Score")
            .AddColumn("Cumulative");

        foreach (var item in highRoiItems)
        {
            var effortColor = item.Item.Effort switch
            {
                UpgradeEffort.Patch => "green",
                UpgradeEffort.Minor => "yellow",
                _ => "red"
            };
            table.AddRow(
                item.Item.PackageId,
                $"[{effortColor}]{item.Item.Effort}[/]",
                $"{item.RoiScore:F0}",
                $"{item.CumulativeRiskReductionPercent:F0}%");
        }

        AnsiConsole.Write(table);

        var lowRoiCount = budget.Items.Count - highRoiItems.Count;
        if (lowRoiCount > 0)
            AnsiConsole.MarkupLine($"[dim]+{lowRoiCount} lower-ROI item(s) reducing remaining {100 - budget.HighROIPercentage:F0}% of risk[/]");
    }

    private static async Task<string> GenerateLicenseAttributionAsync(
        List<PackageHealth> packages,
        List<PackageHealth> transitivePackages,
        LicenseOutputFormat format,
        string basePath,
        CancellationToken ct = default)
    {
        var allPackages = packages.Concat(transitivePackages)
            .DistinctBy(p => p.PackageId)
            .OrderBy(p => p.PackageId)
            .ToList();

        var (fileName, content) = format switch
        {
            LicenseOutputFormat.Txt => GenerateTxtAttribution(allPackages),
            LicenseOutputFormat.Html => GenerateHtmlAttribution(allPackages),
            LicenseOutputFormat.Md => GenerateMdAttribution(allPackages),
            _ => GenerateTxtAttribution(allPackages)
        };

        var outputDir = File.Exists(basePath) ? Path.GetDirectoryName(basePath)! : basePath;
        var outputPath = Path.Combine(outputDir, fileName);

        await File.WriteAllTextAsync(outputPath, content, ct);
        AnsiConsole.MarkupLine($"[green]License attribution written to {outputPath}[/]");
        return outputPath;
    }

    private static (string FileName, string Content) GenerateTxtAttribution(List<PackageHealth> packages)
    {
        var sb = new System.Text.StringBuilder();
        sb.AppendLine("THIRD-PARTY SOFTWARE NOTICES AND INFORMATION");
        sb.AppendLine("=============================================");
        sb.AppendLine();
        sb.AppendLine($"This project incorporates components from the projects listed below.");
        sb.AppendLine($"Generated by DepSafe on {DateTime.UtcNow:yyyy-MM-dd HH:mm:ss} UTC");
        sb.AppendLine();
        sb.AppendLine(new string('=', 80));
        sb.AppendLine();

        foreach (var pkg in packages)
        {
            sb.AppendLine($"{pkg.PackageId} ({pkg.Version})");
            sb.AppendLine(new string('-', 40));
            sb.AppendLine($"License: {pkg.License ?? "Unknown"}");
            if (!string.IsNullOrEmpty(pkg.RepositoryUrl))
                sb.AppendLine($"Repository: {pkg.RepositoryUrl}");
            sb.AppendLine();
        }

        return ("THIRD-PARTY-NOTICES.txt", sb.ToString());
    }

    private static (string FileName, string Content) GenerateHtmlAttribution(List<PackageHealth> packages)
    {
        var sb = new System.Text.StringBuilder();
        sb.AppendLine("<!DOCTYPE html>");
        sb.AppendLine("<html lang=\"en\">");
        sb.AppendLine("<head>");
        sb.AppendLine("  <meta charset=\"UTF-8\">");
        sb.AppendLine("  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">");
        sb.AppendLine("  <title>Third-Party Licenses</title>");
        sb.AppendLine("  <style>");
        sb.AppendLine("    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 900px; margin: 0 auto; padding: 20px; }");
        sb.AppendLine("    h1 { border-bottom: 2px solid #333; padding-bottom: 10px; }");
        sb.AppendLine("    .package { border: 1px solid #ddd; border-radius: 8px; padding: 15px; margin: 15px 0; }");
        sb.AppendLine("    .package h3 { margin-top: 0; color: #0366d6; }");
        sb.AppendLine("    .license-badge { display: inline-block; background: #28a745; color: white; padding: 2px 8px; border-radius: 4px; font-size: 0.85em; }");
        sb.AppendLine("    .unknown { background: #6c757d; }");
        sb.AppendLine("    .meta { color: #666; font-size: 0.9em; }");
        sb.AppendLine("    a { color: #0366d6; text-decoration: none; }");
        sb.AppendLine("    a:hover { text-decoration: underline; }");
        sb.AppendLine("    .footer { margin-top: 30px; padding-top: 20px; border-top: 1px solid #ddd; color: #666; font-size: 0.85em; }");
        sb.AppendLine("  </style>");
        sb.AppendLine("</head>");
        sb.AppendLine("<body>");
        sb.AppendLine("  <h1>Third-Party Software Licenses</h1>");
        sb.AppendLine($"  <p>This project incorporates {packages.Count} third-party components.</p>");

        foreach (var pkg in packages)
        {
            var licenseClass = string.IsNullOrEmpty(pkg.License) ? "license-badge unknown" : "license-badge";
            sb.AppendLine("  <div class=\"package\">");
            sb.AppendLine($"    <h3>{System.Web.HttpUtility.HtmlEncode(pkg.PackageId)} <span class=\"meta\">v{System.Web.HttpUtility.HtmlEncode(pkg.Version)}</span></h3>");
            sb.AppendLine($"    <span class=\"{licenseClass}\">{System.Web.HttpUtility.HtmlEncode(pkg.License ?? "Unknown")}</span>");

            if (pkg.RepositoryUrl is not null && (pkg.RepositoryUrl.StartsWith("https://", StringComparison.OrdinalIgnoreCase) || pkg.RepositoryUrl.StartsWith("http://", StringComparison.OrdinalIgnoreCase)))
            {
                sb.AppendLine("    <p class=\"meta\">");
                sb.AppendLine($"      <a href=\"{System.Web.HttpUtility.HtmlEncode(pkg.RepositoryUrl)}\" target=\"_blank\">Repository</a>");
                sb.AppendLine("    </p>");
            }
            sb.AppendLine("  </div>");
        }

        sb.AppendLine("  <div class=\"footer\">");
        sb.AppendLine($"    Generated by DepSafe on {DateTime.UtcNow:yyyy-MM-dd HH:mm:ss} UTC");
        sb.AppendLine("  </div>");
        sb.AppendLine("</body>");
        sb.AppendLine("</html>");

        return ("LICENSES.html", sb.ToString());
    }

    private static (string FileName, string Content) GenerateMdAttribution(List<PackageHealth> packages)
    {
        var sb = new System.Text.StringBuilder();
        sb.AppendLine("# Third-Party Software Attribution");
        sb.AppendLine();
        sb.AppendLine($"This project incorporates {packages.Count} third-party components.");
        sb.AppendLine();
        sb.AppendLine("## Packages");
        sb.AppendLine();

        // Group by license for summary
        var licenseGroups = packages
            .GroupBy(p => p.License ?? "Unknown")
            .Select(g => (License: g.Key, Count: g.Count()))
            .OrderByDescending(g => g.Count)
            .ToList();

        sb.AppendLine("### License Summary");
        sb.AppendLine();
        sb.AppendLine("| License | Count |");
        sb.AppendLine("|---------|-------|");
        foreach (var (license, count) in licenseGroups)
        {
            sb.AppendLine($"| {license} | {count} |");
        }
        sb.AppendLine();
        sb.AppendLine("### Package Details");
        sb.AppendLine();

        foreach (var pkg in packages)
        {
            sb.AppendLine($"#### {pkg.PackageId}");
            sb.AppendLine();
            sb.AppendLine($"- **Version:** {pkg.Version}");
            sb.AppendLine($"- **License:** {pkg.License ?? "Unknown"}");
            if (!string.IsNullOrEmpty(pkg.RepositoryUrl))
                sb.AppendLine($"- **Repository:** [{pkg.RepositoryUrl}]({pkg.RepositoryUrl})");
            sb.AppendLine();
        }

        sb.AppendLine("---");
        sb.AppendLine($"*Generated by DepSafe on {DateTime.UtcNow:yyyy-MM-dd HH:mm:ss} UTC*");

        return ("ATTRIBUTION.md", sb.ToString());
    }

    private static async Task<string> GenerateSbomAsync(
        List<PackageHealth> packages,
        List<PackageHealth> transitivePackages,
        SbomFormat format,
        string basePath,
        CancellationToken ct = default)
    {
        var allPackages = packages.Concat(transitivePackages)
            .DistinctBy(p => $"{p.PackageId}@{p.Version}")
            .OrderBy(p => p.PackageId)
            .ToList();

        var projectName = Path.GetFileNameWithoutExtension(basePath);
        var asmVersion = System.Reflection.Assembly.GetExecutingAssembly().GetName().Version;
        var toolVersion = asmVersion is not null ? $"{asmVersion.Major}.{asmVersion.Minor}.{asmVersion.Build}" : "1.0.0";
        var sbomGenerator = new SbomGenerator("DepSafe", toolVersion);

        var outputDir = File.Exists(basePath) ? Path.GetDirectoryName(basePath)! : basePath;
        string fileName;
        string content;

        if (format == SbomFormat.CycloneDx)
        {
            var bom = sbomGenerator.GenerateCycloneDx(projectName, allPackages);
            content = JsonSerializer.Serialize(bom, JsonDefaults.IndentedIgnoreNull);
            fileName = $"{projectName}-sbom.cdx.json";
        }
        else
        {
            var sbom = sbomGenerator.Generate(projectName, allPackages);
            content = JsonSerializer.Serialize(sbom, JsonDefaults.IndentedIgnoreNull);
            fileName = $"{projectName}-sbom.spdx.json";
        }

        var outputPath = Path.Combine(outputDir, fileName);
        await File.WriteAllTextAsync(outputPath, content, ct);
        AnsiConsole.MarkupLine($"[green]SBOM written to {outputPath}[/]");
        return outputPath;
    }

    /// <summary>
    /// Check if a package version is in the vulnerable range of a vulnerability.
    /// </summary>
    private static bool IsVersionInVulnerableRange(string installedVersion, VulnerabilityInfo vuln)
    {
        if (string.IsNullOrEmpty(vuln.VulnerableVersionRange))
            return true; // Conservative: assume affected if no range specified

        // Use canonical range parser
        if (!Scoring.HealthScoreCalculator.IsVersionInVulnerableRange(installedVersion, vuln.VulnerableVersionRange))
            return false;

        // Additional check: if current >= patched version, not affected
        if (!string.IsNullOrEmpty(vuln.PatchedVersion))
        {
            try
            {
                var current = NuGet.Versioning.NuGetVersion.Parse(installedVersion);
                var patched = NuGet.Versioning.NuGetVersion.Parse(vuln.PatchedVersion);
                if (current >= patched) return false;
            }
            catch
            {
                // If parsing fails, fall through to affected
            }
        }

        return true;
    }

    private static async Task SignArtifactsAsync(
        bool sign,
        string? signKey,
        string outputPath,
        string? licenseFilePath,
        string? sbomFilePath,
        CancellationToken ct)
    {
        if (!sign)
            return;

        var sigilService = await SigningHelper.TryCreateAsync(ct);
        if (sigilService is null)
            return;

        var artifactPaths = new List<string> { outputPath };
        if (licenseFilePath is not null) artifactPaths.Add(licenseFilePath);
        if (sbomFilePath is not null) artifactPaths.Add(sbomFilePath);

        foreach (var artifact in artifactPaths)
            await SigningHelper.TrySignArtifactAsync(sigilService, artifact, signKey, ct);
    }

    private static async Task GenerateEvidencePackAsync(
        string path,
        List<PackageHealth> packages,
        List<PackageHealth> transitivePackages,
        CraReportGenerator reportGenerator,
        CraReport craReport,
        string? licenseFilePath,
        CancellationToken ct)
    {
        var projectName = Path.GetFileNameWithoutExtension(path) ?? "project";
        var baseOutputDir = File.Exists(path) ? Path.GetDirectoryName(path)! : path;

        var reportHtml = reportGenerator.GenerateHtml(craReport, licenseFilePath);
        var reportJson = reportGenerator.GenerateJson(craReport);

        string? sbomJson = null;
        if (craReport.Sbom is not null)
        {
            sbomJson = JsonSerializer.Serialize(craReport.Sbom, JsonDefaults.IndentedIgnoreNull);
        }

        string? vexJson = null;
        if (craReport.Vex is not null)
        {
            vexJson = JsonSerializer.Serialize(craReport.Vex, JsonDefaults.IndentedIgnoreNull);
        }

        string? licenseAttribution = null;
        if (licenseFilePath is not null && File.Exists(licenseFilePath))
        {
            licenseAttribution = await File.ReadAllTextAsync(licenseFilePath, ct).ConfigureAwait(false);
        }
        else
        {
            // Generate license attribution text even if not explicitly requested
            var allPackages = packages.Concat(transitivePackages)
                .DistinctBy(p => p.PackageId)
                .OrderBy(p => p.PackageId)
                .ToList();
            var (_, content) = GenerateTxtAttribution(allPackages);
            licenseAttribution = content;
        }

        var (outputDir, manifest) = await EvidencePackWriter.WriteAsync(
            projectPath: path,
            projectName: projectName,
            baseOutputDir: baseOutputDir,
            reportHtml: reportHtml,
            reportJson: reportJson,
            sbomJson: sbomJson,
            vexJson: vexJson,
            licenseAttribution: licenseAttribution,
            ct: ct).ConfigureAwait(false);

        AnsiConsole.MarkupLine($"\n[green]Evidence pack written to {Markup.Escape(outputDir)}[/]");
        AnsiConsole.MarkupLine($"[dim]  {manifest.Artifacts.Count} artifact(s) with SHA-256 checksums in manifest.json[/]");
    }
}
