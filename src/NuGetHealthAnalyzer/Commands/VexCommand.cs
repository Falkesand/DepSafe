using System.CommandLine;
using System.Text.Json;
using NuGetHealthAnalyzer.Compliance;
using NuGetHealthAnalyzer.DataSources;
using NuGetHealthAnalyzer.Models;
using NuGetHealthAnalyzer.Scoring;
using Spectre.Console;

namespace NuGetHealthAnalyzer.Commands;

public static class VexCommand
{
    public static Command Create()
    {
        var pathArg = new Argument<string?>(
            "path",
            () => ".",
            "Path to project, solution, or directory");

        var outputOption = new Option<string?>(
            ["--output", "-o"],
            "Output file path (default: stdout)");

        var command = new Command("vex", "Generate VEX (Vulnerability Exploitability eXchange) document")
        {
            pathArg,
            outputOption
        };

        command.SetHandler(ExecuteAsync, pathArg, outputOption);

        return command;
    }

    private static async Task<int> ExecuteAsync(string? path, string? outputPath)
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
        var githubClient = new GitHubApiClient();
        var calculator = new HealthScoreCalculator();

        // VEX requires GitHub API for vulnerability data
        if (!githubClient.HasToken)
        {
            AnsiConsole.MarkupLine("[yellow]No GITHUB_TOKEN found. VEX generation requires GitHub API for vulnerability data.[/]");
            AnsiConsole.MarkupLine("[dim]Set GITHUB_TOKEN environment variable and try again.[/]");
            AnsiConsole.MarkupLine("[dim]Without a token, vulnerability queries are rate-limited to 60/hour and may be incomplete.[/]");
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

        // Phase 2: Batch fetch GitHub repo info
        var repoInfoMap = new Dictionary<string, GitHubRepoInfo?>(StringComparer.OrdinalIgnoreCase);

        if (!githubClient.IsRateLimited)
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
        }

        // Phase 3: Batch fetch vulnerabilities (critical for VEX)
        var allVulnerabilities = new Dictionary<string, List<VulnerabilityInfo>>(StringComparer.OrdinalIgnoreCase);

        if (!githubClient.IsRateLimited)
        {
            await AnsiConsole.Status()
                .StartAsync("Checking vulnerabilities (batch)...", async ctx =>
                {
                    allVulnerabilities = await githubClient.GetVulnerabilitiesBatchAsync(allReferences.Keys);

                    if (githubClient.IsRateLimited)
                    {
                        ctx.Status("[yellow]GitHub rate limited - vulnerability data may be incomplete[/]");
                    }
                });
        }
        else
        {
            AnsiConsole.MarkupLine("[yellow]Skipping vulnerability check - GitHub API rate limited[/]");
        }

        // Phase 4: Build package health data
        var packages = new List<PackageHealth>();

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

        var generator = new VexGenerator();
        var vex = generator.Generate(packages, allVulnerabilities);

        var output = JsonSerializer.Serialize(vex, new JsonSerializerOptions
        {
            WriteIndented = true,
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase
        });

        if (!string.IsNullOrEmpty(outputPath))
        {
            await File.WriteAllTextAsync(outputPath, output);
            AnsiConsole.MarkupLine($"[green]VEX document written to {outputPath}[/]");
        }
        else
        {
            Console.WriteLine(output);
        }

        var totalVulns = allVulnerabilities.Values.Sum(v => v.Count);
        var affectedPackages = allVulnerabilities.Count(kv => kv.Value.Count > 0);

        if (totalVulns > 0)
        {
            AnsiConsole.MarkupLine($"\n[yellow]Found {totalVulns} vulnerabilities in {affectedPackages} packages[/]");
        }
        else
        {
            AnsiConsole.MarkupLine("\n[green]No known vulnerabilities found[/]");
        }

        return 0;
    }
}
