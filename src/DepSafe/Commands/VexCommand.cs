using System.CommandLine;
using System.Text.Json;
using DepSafe.Compliance;
using DepSafe.DataSources;
using DepSafe.Models;
using DepSafe.Scoring;
using Spectre.Console;

namespace DepSafe.Commands;

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

        // VEX always needs GitHub for vulnerability data
        using var pipeline = new AnalysisPipeline(skipGitHub: false);
        pipeline.ShowGitHubStatus("VEX generation requires GitHub API for vulnerability data.");

        var allReferences = await pipeline.ScanProjectFilesAsync(path);
        if (allReferences.Count == 0)
        {
            AnsiConsole.MarkupLine("[yellow]No package references found.[/]");
            return 0;
        }

        await pipeline.RunAsync(allReferences);

        var packages = pipeline.Packages;
        var allVulnerabilities = pipeline.VulnerabilityMap;

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
