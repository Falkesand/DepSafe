using System.Collections.Concurrent;
using System.CommandLine;
using System.CommandLine.Invocation;
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

        command.SetHandler(async context =>
        {
            var path = context.ParseResult.GetValueForArgument(pathArg);
            var projectLicense = context.ParseResult.GetValueForOption(projectLicenseOption)!;
            var format = context.ParseResult.GetValueForOption(formatOption)!;
            var includeTransitive = context.ParseResult.GetValueForOption(includeTransitiveOption);
            var ct = context.GetCancellationToken();
            context.ExitCode = await ExecuteAsync(path, projectLicense, format, includeTransitive, ct);
        });

        return command;
    }

    private static async Task<int> ExecuteAsync(string? path, string projectLicense, string format, bool includeTransitive, CancellationToken ct)
    {
        path = string.IsNullOrEmpty(path) ? Directory.GetCurrentDirectory() : Path.GetFullPath(path);

        if (!File.Exists(path) && !Directory.Exists(path))
        {
            AnsiConsole.MarkupLine($"[red]Path not found: {Markup.Escape(path)}[/]");
            return 1;
        }

        // Get packages using dotnet list
        var dotnetResult = await NuGetApiClient.ParsePackagesWithDotnetAsync(path, ct);
        var (topLevel, transitive) = dotnetResult.ValueOr(([], []));

        if (topLevel.Count == 0)
        {
            // Fall back to XML parsing
            var projectFiles = NuGetApiClient.FindProjectFiles(path).ToList();
            foreach (var projectFile in projectFiles)
            {
                var refsResult = await NuGetApiClient.ParseProjectFileAsync(projectFile, ct);
                topLevel.AddRange(refsResult.ValueOr([]));
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

                using var semaphore = new SemaphoreSlim(10);
                var results = new ConcurrentBag<(string PackageId, string? License)>();
                var tasks = allPackages.Select(async pkg =>
                {
                    await semaphore.WaitAsync(ct);
                    try
                    {
                        var result = await nugetClient.GetPackageInfoAsync(pkg.PackageId, ct);
                        results.Add((pkg.PackageId, result.IsSuccess ? result.Value.License : null));
                    }
                    finally
                    {
                        semaphore.Release();
                        task.Increment(1);
                    }
                });
                await Task.WhenAll(tasks);
                packageLicenses.AddRange(results);
            });

        // Analyze compatibility
        var report = LicenseCompatibility.AnalyzeLicenses(packageLicenses, projectLicense);

        if (format == "json")
        {
            var json = JsonSerializer.Serialize(report, JsonDefaults.Indented);
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
                LicenseCategory.Permissive => "green",
                LicenseCategory.PublicDomain => "green",
                LicenseCategory.WeakCopyleft => "yellow",
                LicenseCategory.StrongCopyleft => "red",
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
                    $"[{severityColor}]{Markup.Escape(issue.Severity)}[/]",
                    Markup.Escape(issue.Message),
                    Markup.Escape(issue.Recommendation ?? "-"));
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
                AnsiConsole.MarkupLine($"  [dim]\u2022[/] {Markup.Escape(unknown)}");
            }
            if (report.UnknownLicenses.Count > 10)
            {
                AnsiConsole.MarkupLine($"  [dim]... and {report.UnknownLicenses.Count - 10} more[/]");
            }
        }

        return report.ErrorCount > 0 ? 1 : 0;
    }
}
