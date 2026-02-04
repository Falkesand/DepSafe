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

        var command = new Command("cra-report", "Generate comprehensive CRA compliance report")
        {
            pathArg,
            formatOption,
            outputOption,
            skipGitHubOption
        };

        command.SetHandler(ExecuteAsync, pathArg, formatOption, outputOption, skipGitHubOption);

        return command;
    }

    private static async Task<int> ExecuteAsync(string? path, CraOutputFormat format, string? outputPath, bool skipGitHub)
    {
        path = string.IsNullOrEmpty(path) ? Directory.GetCurrentDirectory() : Path.GetFullPath(path);

        if (!File.Exists(path) && !Directory.Exists(path))
        {
            AnsiConsole.MarkupLine($"[red]Path not found: {path}[/]");
            return 1;
        }

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
        if (!skipGitHub && githubClient is not null)
        {
            if (!githubClient.HasToken)
            {
                AnsiConsole.MarkupLine("[yellow]No GITHUB_TOKEN found. CRA report requires GitHub API for complete vulnerability data.[/]");
                AnsiConsole.MarkupLine("[dim]Set GITHUB_TOKEN environment variable for comprehensive compliance reporting.[/]");
                AnsiConsole.WriteLine();
            }
        }
        else if (skipGitHub)
        {
            AnsiConsole.MarkupLine("[yellow]Warning: --skip-github specified. Vulnerability data will be incomplete.[/]");
            AnsiConsole.MarkupLine("[dim]CRA compliance report may show incomplete vulnerability status.[/]");
            AnsiConsole.WriteLine();
        }

        // Collect all package references using dotnet list package for resolved versions
        var allReferences = new Dictionary<string, PackageReference>(StringComparer.OrdinalIgnoreCase);
        var transitiveReferences = new Dictionary<string, PackageReference>(StringComparer.OrdinalIgnoreCase);

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
                    ctx.Status("Falling back to XML parsing...");
                    foreach (var projectFile in projectFiles)
                    {
                        var refs = await NuGetApiClient.ParseProjectFileAsync(projectFile);
                        foreach (var r in refs)
                        {
                            if (!allReferences.ContainsKey(r.PackageId))
                            {
                                allReferences[r.PackageId] = r;
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
                        var results = await githubClient.GetRepositoriesBatchAsync(repoUrls);

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
        AnsiConsole.MarkupLine($"[bold]Packages Analyzed:[/] {craReport.PackageCount}");
        AnsiConsole.MarkupLine($"[bold]Vulnerabilities Found:[/] {craReport.VulnerabilityCount}");

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
