using System.CommandLine;
using System.Text.Json;
using DepSafe.Compliance;
using DepSafe.DataSources;
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

        command.SetHandler(ExecuteAsync, pathArg, formatOption, outputOption, skipGitHubOption);

        return command;
    }

    private static async Task<int> ExecuteAsync(string? path, SbomFormat format, string? outputPath, bool skipGitHub)
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

        using var pipeline = new AnalysisPipeline(skipGitHub);
        pipeline.ShowGitHubStatus("No vulnerability data in SBOM.");

        var allReferences = await pipeline.ScanProjectFilesAsync(path);
        if (allReferences.Count == 0)
        {
            AnsiConsole.MarkupLine("[yellow]No package references found.[/]");
            return 0;
        }

        await pipeline.RunAsync(allReferences);

        var packages = pipeline.Packages;
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
            await File.WriteAllTextAsync(outputPath, output);
            AnsiConsole.MarkupLine($"[green]SBOM written to {Markup.Escape(outputPath)}[/]");
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
