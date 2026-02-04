using System.CommandLine;
using System.Text.Json;
using DepSafe.DataSources;
using DepSafe.Models;
using DepSafe.Scoring;
using Spectre.Console;

namespace DepSafe.Commands;

public static class AnalyzeCommand
{
    public static Command Create()
    {
        var pathArg = new Argument<string?>(
            "path",
            () => ".",
            "Path to project, solution, or directory to analyze");

        var formatOption = new Option<OutputFormat>(
            ["--format", "-f"],
            () => OutputFormat.Table,
            "Output format");

        var failBelowOption = new Option<int?>(
            ["--fail-below"],
            "Exit with error if project score falls below this threshold");

        var skipGitHubOption = new Option<bool>(
            ["--skip-github"],
            "Skip GitHub API calls (faster, but no repo activity or vulnerability data)");

        var command = new Command("analyze", "Analyze package health for a project or solution")
        {
            pathArg,
            formatOption,
            failBelowOption,
            skipGitHubOption
        };

        command.SetHandler(ExecuteAsync, pathArg, formatOption, failBelowOption, skipGitHubOption);

        return command;
    }

    private static async Task<int> ExecuteAsync(string? path, OutputFormat format, int? failBelow, bool skipGitHub)
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
                AnsiConsole.MarkupLine("[yellow]No GITHUB_TOKEN found. GitHub API rate limited to 60 requests/hour.[/]");
                AnsiConsole.MarkupLine("[dim]Set GITHUB_TOKEN environment variable for 5000 requests/hour.[/]");
                AnsiConsole.WriteLine();
            }
        }
        else if (skipGitHub)
        {
            AnsiConsole.MarkupLine("[dim]Skipping GitHub API (--skip-github). No repo activity or vulnerability data.[/]");
            AnsiConsole.WriteLine();
        }

        // Collect all package references
        var allReferences = new Dictionary<string, PackageReference>(StringComparer.OrdinalIgnoreCase);

        await AnsiConsole.Status()
            .StartAsync("Scanning project files...", async ctx =>
            {
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
            });

        if (allReferences.Count == 0)
        {
            AnsiConsole.MarkupLine("[yellow]No package references found.[/]");
            return 0;
        }

        // Phase 1: Fetch all NuGet info
        var nugetInfoMap = new Dictionary<string, NuGetPackageInfo>(StringComparer.OrdinalIgnoreCase);

        await AnsiConsole.Progress()
            .StartAsync(async ctx =>
            {
                var task = ctx.AddTask($"Fetching NuGet info for {allReferences.Count} packages", maxValue: allReferences.Count);

                foreach (var (packageId, _) in allReferences)
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

        // Phase 2: Batch fetch GitHub repo info (if not skipped)
        var repoInfoMap = new Dictionary<string, GitHubRepoInfo?>(StringComparer.OrdinalIgnoreCase);
        var vulnMap = new Dictionary<string, List<VulnerabilityInfo>>(StringComparer.OrdinalIgnoreCase);

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

                        // Map back to package IDs
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

            // Phase 3: Batch fetch vulnerabilities
            if (!githubClient.IsRateLimited && githubClient.HasToken)
            {
                await AnsiConsole.Status()
                    .StartAsync("Checking vulnerabilities (batch)...", async ctx =>
                    {
                        vulnMap = await githubClient.GetVulnerabilitiesBatchAsync(allReferences.Keys);

                        if (githubClient.IsRateLimited)
                        {
                            ctx.Status("[yellow]GitHub rate limited - continuing with available data[/]");
                        }
                    });
            }
        }

        // Phase 4: Calculate health scores
        var packages = new List<PackageHealth>();

        foreach (var (packageId, reference) in allReferences)
        {
            if (!nugetInfoMap.TryGetValue(packageId, out var nugetInfo))
                continue;

            repoInfoMap.TryGetValue(packageId, out var repoInfo);
            var vulnerabilities = vulnMap.GetValueOrDefault(packageId, []);

            var health = calculator.Calculate(
                packageId,
                reference.Version,
                nugetInfo,
                repoInfo,
                vulnerabilities);

            packages.Add(health);
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

        var report = new ProjectReport
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

        // Output based on format
        switch (format)
        {
            case OutputFormat.Json:
                OutputJson(report);
                break;
            case OutputFormat.Markdown:
                OutputMarkdown(report);
                break;
            default:
                OutputTable(report, githubClient?.IsRateLimited == true, skipGitHub);
                break;
        }

        // Return exit code based on threshold
        if (failBelow.HasValue && projectScore < failBelow.Value)
        {
            AnsiConsole.MarkupLine($"\n[red]Project score {projectScore} is below threshold {failBelow.Value}[/]");
            return 1;
        }

        return 0;
    }

    private static void OutputTable(ProjectReport report, bool wasRateLimited = false, bool skippedGitHub = false)
    {
        AnsiConsole.WriteLine();
        AnsiConsole.Write(new Rule($"[bold]Package Health Report[/]").LeftJustified());
        AnsiConsole.MarkupLine($"[dim]{report.ProjectPath}[/]");
        AnsiConsole.WriteLine();

        var table = new Table()
            .Border(TableBorder.Rounded)
            .AddColumn("Package")
            .AddColumn("Version")
            .AddColumn(new TableColumn("Score").Centered())
            .AddColumn("Status");

        foreach (var pkg in report.Packages)
        {
            var statusMarkup = pkg.Status switch
            {
                HealthStatus.Healthy => "[green]✓ Healthy[/]",
                HealthStatus.Watch => "[yellow]◉ Watch[/]",
                HealthStatus.Warning => "[orange3]⚠ Warning[/]",
                HealthStatus.Critical => "[red]✗ Critical[/]",
                _ => pkg.Status.ToString()
            };

            var scoreColor = pkg.Score switch
            {
                >= 80 => "green",
                >= 60 => "yellow",
                >= 40 => "orange3",
                _ => "red"
            };

            table.AddRow(
                pkg.PackageId,
                pkg.Version,
                $"[{scoreColor}]{pkg.Score}[/]",
                statusMarkup);
        }

        AnsiConsole.Write(table);

        // Summary
        var statusColor = report.OverallStatus switch
        {
            HealthStatus.Healthy => "green",
            HealthStatus.Watch => "yellow",
            HealthStatus.Warning => "orange3",
            _ => "red"
        };

        AnsiConsole.WriteLine();
        AnsiConsole.MarkupLine($"[bold]Project Score: [{statusColor}]{report.OverallScore}/100[/] ({report.OverallStatus})[/]");

        var summaryTable = new Table()
            .Border(TableBorder.None)
            .HideHeaders()
            .AddColumn("")
            .AddColumn("");

        summaryTable.AddRow("[green]Healthy[/]", report.Summary.HealthyCount.ToString());
        summaryTable.AddRow("[yellow]Watch[/]", report.Summary.WatchCount.ToString());
        summaryTable.AddRow("[orange3]Warning[/]", report.Summary.WarningCount.ToString());
        summaryTable.AddRow("[red]Critical[/]", report.Summary.CriticalCount.ToString());

        if (report.Summary.VulnerableCount > 0)
        {
            summaryTable.AddRow("[red bold]Vulnerable[/]", report.Summary.VulnerableCount.ToString());
        }

        AnsiConsole.Write(summaryTable);

        // Show warnings
        if (wasRateLimited)
        {
            AnsiConsole.MarkupLine("\n[yellow]⚠ GitHub API rate limited - some repo data may be incomplete[/]");
        }
        if (skippedGitHub)
        {
            AnsiConsole.MarkupLine("\n[dim]Note: GitHub data skipped (--skip-github). Scores based on NuGet data only.[/]");
        }

        // Recommendations for low-scoring packages
        var problemPackages = report.Packages.Where(p => p.Recommendations.Count > 0).ToList();
        if (problemPackages.Count > 0)
        {
            AnsiConsole.WriteLine();
            AnsiConsole.Write(new Rule("[bold]Recommendations[/]").LeftJustified());

            foreach (var pkg in problemPackages)
            {
                AnsiConsole.MarkupLine($"\n[bold]{pkg.PackageId}[/] (score: {pkg.Score})");
                foreach (var rec in pkg.Recommendations)
                {
                    AnsiConsole.MarkupLine($"  • {rec}");
                }
            }
        }
    }

    private static void OutputJson(ProjectReport report)
    {
        var json = JsonSerializer.Serialize(report, new JsonSerializerOptions
        {
            WriteIndented = true,
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase
        });
        Console.WriteLine(json);
    }

    private static void OutputMarkdown(ProjectReport report)
    {
        Console.WriteLine($"# Package Health Report");
        Console.WriteLine($"\n**Project:** {report.ProjectPath}");
        Console.WriteLine($"**Generated:** {report.GeneratedAt:yyyy-MM-dd HH:mm:ss} UTC");
        Console.WriteLine($"**Project Score:** {report.OverallScore}/100 ({report.OverallStatus})");

        Console.WriteLine("\n## Summary\n");
        Console.WriteLine($"- Total Packages: {report.Summary.TotalPackages}");
        Console.WriteLine($"- Healthy: {report.Summary.HealthyCount}");
        Console.WriteLine($"- Watch: {report.Summary.WatchCount}");
        Console.WriteLine($"- Warning: {report.Summary.WarningCount}");
        Console.WriteLine($"- Critical: {report.Summary.CriticalCount}");

        if (report.Summary.VulnerableCount > 0)
        {
            Console.WriteLine($"- **Vulnerable: {report.Summary.VulnerableCount}**");
        }

        Console.WriteLine("\n## Packages\n");
        Console.WriteLine("| Package | Version | Score | Status |");
        Console.WriteLine("|---------|---------|-------|--------|");

        foreach (var pkg in report.Packages)
        {
            var statusEmoji = pkg.Status switch
            {
                HealthStatus.Healthy => "✅",
                HealthStatus.Watch => "🔵",
                HealthStatus.Warning => "⚠️",
                HealthStatus.Critical => "❌",
                _ => "?"
            };
            Console.WriteLine($"| {pkg.PackageId} | {pkg.Version} | {pkg.Score} | {statusEmoji} {pkg.Status} |");
        }

        var problemPackages = report.Packages.Where(p => p.Recommendations.Count > 0).ToList();
        if (problemPackages.Count > 0)
        {
            Console.WriteLine("\n## Recommendations\n");
            foreach (var pkg in problemPackages)
            {
                Console.WriteLine($"### {pkg.PackageId} (score: {pkg.Score})\n");
                foreach (var rec in pkg.Recommendations)
                {
                    Console.WriteLine($"- {rec}");
                }
                Console.WriteLine();
            }
        }
    }
}

public enum OutputFormat
{
    Table,
    Json,
    Markdown
}
