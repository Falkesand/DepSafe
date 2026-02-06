using System.CommandLine;
using System.Text.Json;
using DepSafe.DataSources;
using DepSafe.Models;
using DepSafe.Typosquatting;
using Spectre.Console;

namespace DepSafe.Commands;

public static class TyposquatCommand
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

        var offlineOption = new Option<bool>(
            ["--offline"],
            "Skip online popular package refresh, use embedded data only");

        var command = new Command("typosquat", "Check dependencies for potential typosquatting attacks")
        {
            pathArg,
            formatOption,
            offlineOption
        };

        command.SetHandler(ExecuteAsync, pathArg, formatOption, offlineOption);

        return command;
    }

    internal static async Task<List<TyposquatResult>> RunAnalysisAsync(
        string path, bool offline, CancellationToken ct = default)
    {
        // Load popular package index
        using var provider = new PopularPackageProvider(offlineOnly: offline);
        var index = await AnsiConsole.Status()
            .StartAsync("Loading popular package database...", async _ =>
                await provider.LoadAsync(ct));

        var detector = new TyposquatDetector(index);
        var allResults = new List<TyposquatResult>();

        // Scan for .NET projects
        var projectFiles = NuGetApiClient.FindProjectFiles(path).ToList();
        if (projectFiles.Count > 0)
        {
            var nugetPackages = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var projectFile in projectFiles)
            {
                var refs = await NuGetApiClient.ParseProjectFileAsync(projectFile);
                foreach (var r in refs)
                    nugetPackages.Add(r.PackageId);
            }

            if (nugetPackages.Count > 0)
            {
                var nugetResults = detector.CheckAll(nugetPackages, PackageEcosystem.NuGet);
                allResults.AddRange(nugetResults);
            }
        }

        // Scan for npm projects
        var packageJsonFiles = NpmApiClient.FindPackageJsonFiles(path).ToList();
        if (packageJsonFiles.Count > 0)
        {
            foreach (var packageJsonPath in packageJsonFiles)
            {
                var packageJson = await NpmApiClient.ParsePackageJsonAsync(packageJsonPath);
                if (packageJson is null) continue;

                var npmPackages = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                foreach (var dep in packageJson.Dependencies)
                    npmPackages.Add(dep.Key);
                foreach (var dep in packageJson.DevDependencies)
                    npmPackages.Add(dep.Key);

                if (npmPackages.Count > 0)
                {
                    var npmResults = detector.CheckAll(npmPackages, PackageEcosystem.Npm);
                    allResults.AddRange(npmResults);
                }
            }
        }

        return allResults;
    }

    private static async Task<int> ExecuteAsync(string? path, OutputFormat format, bool offline)
    {
        path = string.IsNullOrEmpty(path) ? Directory.GetCurrentDirectory() : Path.GetFullPath(path);

        if (!File.Exists(path) && !Directory.Exists(path))
        {
            AnsiConsole.MarkupLine($"[red]Path not found: {path}[/]");
            return 1;
        }

        var results = await RunAnalysisAsync(path, offline);

        if (format == OutputFormat.Json)
        {
            var json = JsonSerializer.Serialize(results, JsonDefaults.Indented);
            Console.WriteLine(json);
            return results.Count > 0 ? 1 : 0;
        }

        // Table output
        AnsiConsole.WriteLine();
        AnsiConsole.Write(new Rule("[bold]Typosquatting Analysis[/]").LeftJustified());
        AnsiConsole.MarkupLine($"[dim]{path}[/]");
        AnsiConsole.WriteLine();

        if (results.Count == 0)
        {
            AnsiConsole.MarkupLine("[green]No potential typosquatting issues found.[/]");
            return 0;
        }

        var table = new Table()
            .Border(TableBorder.Rounded)
            .AddColumn("Risk")
            .AddColumn("Package")
            .AddColumn("Similar To")
            .AddColumn("Detail")
            .AddColumn(new TableColumn("Confidence").Centered());

        foreach (var result in results)
        {
            var riskMarkup = result.RiskLevel switch
            {
                TyposquatRiskLevel.Critical => "[red bold]CRITICAL[/]",
                TyposquatRiskLevel.High => "[orange3 bold]HIGH[/]",
                TyposquatRiskLevel.Medium => "[yellow]MEDIUM[/]",
                TyposquatRiskLevel.Low => "[dim]LOW[/]",
                _ => "[dim]NONE[/]"
            };

            var confColor = result.Confidence switch
            {
                >= 90 => "red",
                >= 70 => "orange3",
                >= 50 => "yellow",
                _ => "dim"
            };

            table.AddRow(
                riskMarkup,
                result.PackageName,
                result.SimilarTo,
                result.Detail,
                $"[{confColor}]{result.Confidence}%[/]");
        }

        AnsiConsole.Write(table);

        AnsiConsole.WriteLine();
        AnsiConsole.MarkupLine($"[yellow]{results.Count} potential typosquatting issue(s) found.[/]");

        return 1; // Non-zero exit for CI/CD pipelines
    }
}
