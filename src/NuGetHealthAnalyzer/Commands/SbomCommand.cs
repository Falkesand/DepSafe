using System.CommandLine;
using System.Text.Json;
using NuGetHealthAnalyzer.Compliance;
using NuGetHealthAnalyzer.DataSources;
using NuGetHealthAnalyzer.Scoring;
using Spectre.Console;

namespace NuGetHealthAnalyzer.Commands;

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

        command.SetHandler(ExecuteAsync, pathArg, formatOption, outputOption, skipGitHubOption);

        return command;
    }

    private static async Task<int> ExecuteAsync(string? path, SbomFormat format, string? outputPath, bool skipGitHub)
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
            AnsiConsole.MarkupLine("[dim]Skipping GitHub API (--skip-github). No vulnerability data in SBOM.[/]");
            AnsiConsole.WriteLine();
        }

        // Collect all package references
        var allReferences = new Dictionary<string, Models.PackageReference>(StringComparer.OrdinalIgnoreCase);

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
        var nugetInfoMap = new Dictionary<string, Models.NuGetPackageInfo>(StringComparer.OrdinalIgnoreCase);

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
        var repoInfoMap = new Dictionary<string, Models.GitHubRepoInfo?>(StringComparer.OrdinalIgnoreCase);
        var vulnMap = new Dictionary<string, List<Models.VulnerabilityInfo>>(StringComparer.OrdinalIgnoreCase);

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
                });

            // Phase 3: Batch fetch vulnerabilities
            if (!githubClient.IsRateLimited && githubClient.HasToken)
            {
                await AnsiConsole.Status()
                    .StartAsync("Checking vulnerabilities (batch)...", async ctx =>
                    {
                        vulnMap = await githubClient.GetVulnerabilitiesBatchAsync(allReferences.Keys);
                    });
            }
        }

        // Phase 4: Calculate health scores
        var packages = new List<Models.PackageHealth>();

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

        var projectName = Path.GetFileNameWithoutExtension(path);
        var generator = new SbomGenerator();

        string output;
        if (format == SbomFormat.CycloneDx)
        {
            var cycloneDx = generator.GenerateCycloneDx(projectName, packages);
            output = JsonSerializer.Serialize(cycloneDx, new JsonSerializerOptions
            {
                WriteIndented = true,
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase
            });
        }
        else
        {
            var spdx = generator.Generate(projectName, packages);
            output = JsonSerializer.Serialize(spdx, new JsonSerializerOptions
            {
                WriteIndented = true
            });
        }

        if (!string.IsNullOrEmpty(outputPath))
        {
            await File.WriteAllTextAsync(outputPath, output);
            AnsiConsole.MarkupLine($"[green]SBOM written to {outputPath}[/]");
        }
        else
        {
            Console.WriteLine(output);
        }

        return 0;
    }
}

public enum SbomFormat
{
    Spdx,
    CycloneDx
}
