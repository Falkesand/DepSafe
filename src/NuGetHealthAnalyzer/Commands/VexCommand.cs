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

        var packages = new List<PackageHealth>();
        var allVulnerabilities = new Dictionary<string, List<VulnerabilityInfo>>(StringComparer.OrdinalIgnoreCase);

        await AnsiConsole.Progress()
            .StartAsync(async ctx =>
            {
                var task = ctx.AddTask($"Analyzing {allReferences.Count} packages", maxValue: allReferences.Count);

                foreach (var (packageId, reference) in allReferences)
                {
                    task.Description = $"Analyzing {packageId}";

                    var nugetInfo = await nugetClient.GetPackageInfoAsync(packageId);
                    if (nugetInfo is null)
                    {
                        task.Increment(1);
                        continue;
                    }

                    var repoInfo = await githubClient.GetRepositoryInfoAsync(nugetInfo.RepositoryUrl ?? nugetInfo.ProjectUrl);
                    var vulnerabilities = await githubClient.GetVulnerabilitiesAsync(packageId, reference.Version);

                    if (vulnerabilities.Count > 0)
                    {
                        allVulnerabilities[packageId] = vulnerabilities;
                    }

                    var health = calculator.Calculate(
                        packageId,
                        reference.Version,
                        nugetInfo,
                        repoInfo,
                        vulnerabilities);

                    packages.Add(health);
                    task.Increment(1);
                }
            });

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

        if (allVulnerabilities.Count > 0)
        {
            AnsiConsole.MarkupLine($"\n[yellow]Found {allVulnerabilities.Values.Sum(v => v.Count)} vulnerabilities in {allVulnerabilities.Count} packages[/]");
        }
        else
        {
            AnsiConsole.MarkupLine("\n[green]No known vulnerabilities found[/]");
        }

        return 0;
    }
}
