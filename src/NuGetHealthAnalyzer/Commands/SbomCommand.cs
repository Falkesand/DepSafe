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

        var command = new Command("sbom", "Generate Software Bill of Materials (SBOM)")
        {
            pathArg,
            formatOption,
            outputOption
        };

        command.SetHandler(ExecuteAsync, pathArg, formatOption, outputOption);

        return command;
    }

    private static async Task<int> ExecuteAsync(string? path, SbomFormat format, string? outputPath)
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

        var packages = new List<Models.PackageHealth>();

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
