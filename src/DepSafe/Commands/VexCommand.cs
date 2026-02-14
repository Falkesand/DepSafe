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

        var signOption = new Option<bool>(
            ["--sign"],
            "Sign the generated artifact with sigil");

        var signKeyOption = new Option<string?>(
            ["--sign-key"],
            "Path to the signing key for sigil (uses default if not specified)");

        var command = new Command("vex", "Generate VEX (Vulnerability Exploitability eXchange) document")
        {
            pathArg,
            outputOption,
            signOption,
            signKeyOption
        };

        command.SetHandler(async context =>
        {
            var path = context.ParseResult.GetValueForArgument(pathArg);
            var outputPath = context.ParseResult.GetValueForOption(outputOption);
            var sign = context.ParseResult.GetValueForOption(signOption);
            var signKey = context.ParseResult.GetValueForOption(signKeyOption);
            var ct = context.GetCancellationToken();
            context.ExitCode = await ExecuteAsync(path, outputPath, sign, signKey, ct);
        });

        return command;
    }

    private static async Task<int> ExecuteAsync(string? path, string? outputPath, bool sign, string? signKey, CancellationToken ct)
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

        // VEX always needs GitHub for vulnerability data
        using var pipeline = new AnalysisPipeline(skipGitHub: false);
        pipeline.ShowGitHubStatus("VEX generation requires GitHub API for vulnerability data.");

        var allReferences = await AnalysisPipeline.ScanProjectFilesAsync(path, ct);
        if (allReferences.Count == 0)
        {
            AnsiConsole.MarkupLine("[yellow]No package references found.[/]");
            return 0;
        }

        await pipeline.RunAsync(allReferences, ct);

        var packages = pipeline.Packages;
        var allVulnerabilities = pipeline.VulnerabilityMap;

        var generator = new VexGenerator();
        var vex = generator.Generate(packages, allVulnerabilities);

        var output = JsonSerializer.Serialize(vex, JsonDefaults.Indented);

        if (!string.IsNullOrEmpty(outputPath))
        {
            await File.WriteAllTextAsync(outputPath, output, ct);
            AnsiConsole.MarkupLine($"[green]VEX document written to {Markup.Escape(outputPath)}[/]");

            if (sign)
            {
                var sigilService = await SigningHelper.TryCreateAsync(ct);
                if (sigilService is not null)
                {
                    await SigningHelper.TrySignArtifactAsync(sigilService, outputPath, signKey, ct);
                }
            }
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
