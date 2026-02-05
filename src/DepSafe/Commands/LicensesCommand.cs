using System.CommandLine;
using System.Text.Json;
using DepSafe.Compliance;
using DepSafe.DataSources;
using DepSafe.Models;
using Spectre.Console;

namespace DepSafe.Commands;

public static class LicensesCommand
{
    public static Command Create()
    {
        var pathArg = new Argument<string?>(
            "path",
            () => ".",
            "Path to project, solution, or directory");

        var projectLicenseOption = new Option<string>(
            ["--project-license", "-l"],
            () => "MIT",
            "Your project's license (for compatibility checking)");

        var formatOption = new Option<string>(
            ["--format", "-f"],
            () => "table",
            "Output format (table or json)");

        var includeTransitiveOption = new Option<bool>(
            ["--include-transitive", "-t"],
            "Include transitive dependencies in analysis");

        var command = new Command("licenses", "Analyze license compatibility of dependencies")
        {
            pathArg,
            projectLicenseOption,
            formatOption,
            includeTransitiveOption
        };

        command.SetHandler(ExecuteAsync, pathArg, projectLicenseOption, formatOption, includeTransitiveOption);

        return command;
    }

    private static async Task<int> ExecuteAsync(string? path, string projectLicense, string format, bool includeTransitive)
    {
        path = string.IsNullOrEmpty(path) ? Directory.GetCurrentDirectory() : Path.GetFullPath(path);

        if (!File.Exists(path) && !Directory.Exists(path))
        {
            AnsiConsole.MarkupLine($"[red]Path not found: {path}[/]");
            return 1;
        }

        // Get packages using dotnet list
        var (topLevel, transitive) = await NuGetApiClient.ParsePackagesWithDotnetAsync(path);

        if (topLevel.Count == 0)
        {
            // Fall back to XML parsing
            var projectFiles = NuGetApiClient.FindProjectFiles(path).ToList();
            foreach (var projectFile in projectFiles)
            {
                var refs = await NuGetApiClient.ParseProjectFileAsync(projectFile);
                topLevel.AddRange(refs);
            }
        }

        if (topLevel.Count == 0)
        {
            AnsiConsole.MarkupLine("[yellow]No package references found.[/]");
            return 0;
        }

        var allPackages = includeTransitive
            ? topLevel.Concat(transitive).DistinctBy(p => p.PackageId).ToList()
            : topLevel;

        AnsiConsole.MarkupLine($"[dim]Analyzing {allPackages.Count} packages...[/]");

        // Fetch NuGet info for license data
        using var nugetClient = new NuGetApiClient();
        var packageLicenses = new List<(string PackageId, string? License)>();

        await AnsiConsole.Progress()
            .StartAsync(async ctx =>
            {
                var task = ctx.AddTask("Fetching license information", maxValue: allPackages.Count);

                foreach (var pkg in allPackages)
                {
                    var info = await nugetClient.GetPackageInfoAsync(pkg.PackageId);
                    packageLicenses.Add((pkg.PackageId, info?.License));
                    task.Increment(1);
                }
            });

        // Analyze compatibility
        var report = LicenseCompatibility.AnalyzeLicenses(packageLicenses, projectLicense);

        if (format == "json")
        {
            var json = JsonSerializer.Serialize(report, new JsonSerializerOptions
            {
                WriteIndented = true,
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase
            });
            Console.WriteLine(json);
            return report.ErrorCount > 0 ? 1 : 0;
        }

        // Table output
        AnsiConsole.WriteLine();
        AnsiConsole.Write(new Rule("[bold]License Compatibility Report[/]").LeftJustified());

        // Summary panel
        var statusColor = report.OverallStatus switch
        {
            "Compatible" => "green",
            "Review Required" => "yellow",
            _ => "red"
        };

        var summaryTable = new Table().Border(TableBorder.Rounded);
        summaryTable.AddColumn("Metric");
        summaryTable.AddColumn("Value");
        summaryTable.AddRow("Project License", $"[bold]{projectLicense}[/]");
        summaryTable.AddRow("Total Packages", report.TotalPackages.ToString());
        summaryTable.AddRow("Overall Status", $"[{statusColor}]{report.OverallStatus}[/]");
        summaryTable.AddRow("Errors", report.ErrorCount > 0 ? $"[red]{report.ErrorCount}[/]" : "[green]0[/]");
        summaryTable.AddRow("Warnings", report.WarningCount > 0 ? $"[yellow]{report.WarningCount}[/]" : "[dim]0[/]");

        AnsiConsole.Write(summaryTable);
        AnsiConsole.WriteLine();

        // License distribution
        AnsiConsole.Write(new Rule("[bold]License Distribution[/]").LeftJustified());

        var distTable = new Table().Border(TableBorder.Rounded);
        distTable.AddColumn("License");
        distTable.AddColumn("Count");
        distTable.AddColumn("Category");

        foreach (var (license, count) in report.LicenseDistribution.OrderByDescending(kv => kv.Value))
        {
            var info = LicenseCompatibility.GetLicenseInfo(license);
            var categoryColor = info?.Category switch
            {
                LicenseCompatibility.LicenseCategory.Permissive => "green",
                LicenseCompatibility.LicenseCategory.PublicDomain => "green",
                LicenseCompatibility.LicenseCategory.WeakCopyleft => "yellow",
                LicenseCompatibility.LicenseCategory.StrongCopyleft => "red",
                _ => "dim"
            };
            distTable.AddRow(license, count.ToString(), $"[{categoryColor}]{info?.Category.ToString() ?? "Unknown"}[/]");
        }

        if (report.UnknownLicenses.Count > 0)
        {
            distTable.AddRow("[dim]Unknown[/]", report.UnknownLicenses.Count.ToString(), "[dim]Unknown[/]");
        }

        AnsiConsole.Write(distTable);
        AnsiConsole.WriteLine();

        // Issues (errors and warnings)
        var issues = report.CompatibilityResults.Where(r => r.Severity != "Info").ToList();

        if (issues.Count > 0)
        {
            AnsiConsole.Write(new Rule("[bold]License Issues[/]").LeftJustified());

            var issuesTable = new Table().Border(TableBorder.Rounded);
            issuesTable.AddColumn("Severity");
            issuesTable.AddColumn("Package / Issue");
            issuesTable.AddColumn("Recommendation");

            foreach (var issue in issues.OrderByDescending(i => i.Severity == "Error"))
            {
                var severityColor = issue.Severity == "Error" ? "red" : "yellow";
                issuesTable.AddRow(
                    $"[{severityColor}]{issue.Severity}[/]",
                    issue.Message,
                    issue.Recommendation ?? "-");
            }

            AnsiConsole.Write(issuesTable);
        }
        else
        {
            AnsiConsole.MarkupLine("[green]No license compatibility issues found.[/]");
        }

        // Unknown licenses warning
        if (report.UnknownLicenses.Count > 0)
        {
            AnsiConsole.WriteLine();
            AnsiConsole.Write(new Rule("[bold yellow]Packages with Unknown Licenses[/]").LeftJustified());
            foreach (var unknown in report.UnknownLicenses.Take(10))
            {
                AnsiConsole.MarkupLine($"  [dim]•[/] {unknown}");
            }
            if (report.UnknownLicenses.Count > 10)
            {
                AnsiConsole.MarkupLine($"  [dim]... and {report.UnknownLicenses.Count - 10} more[/]");
            }
        }

        return report.ErrorCount > 0 ? 1 : 0;
    }
}
