using System.CommandLine;
using System.CommandLine.Invocation;
using System.Text.Json;
using DepSafe.DataSources;
using DepSafe.Models;
using DepSafe.Scoring;
using Spectre.Console;

namespace DepSafe.Commands;

public static class AnalyzeCommand
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

        var failBelowOption = new Option<int?>(
            ["--fail-below"],
            "Exit with error if project score falls below this threshold");

        var skipGitHubOption = new Option<bool>(
            ["--skip-github"],
            "Skip GitHub API calls (faster, but no repo activity or vulnerability data)");

        var checkTyposquatOption = new Option<bool>(
            ["--check-typosquat"],
            "Run typosquatting detection on all dependencies");

        var command = new Command("analyze", "Analyze package health for a project or solution")
        {
            pathArg,
            formatOption,
            failBelowOption,
            skipGitHubOption,
            checkTyposquatOption
        };

        command.SetHandler(async context =>
        {
            var path = context.ParseResult.GetValueForArgument(pathArg);
            var format = context.ParseResult.GetValueForOption(formatOption);
            var failBelow = context.ParseResult.GetValueForOption(failBelowOption);
            var skipGitHub = context.ParseResult.GetValueForOption(skipGitHubOption);
            var checkTyposquat = context.ParseResult.GetValueForOption(checkTyposquatOption);
            var ct = context.GetCancellationToken();
            context.ExitCode = await ExecuteAsync(path, format, failBelow, skipGitHub, checkTyposquat, ct);
        });

        return command;
    }

    private static async Task<int> ExecuteAsync(string? path, OutputFormat format, int? failBelow, bool skipGitHub, bool checkTyposquat, CancellationToken ct)
    {
        path = string.IsNullOrEmpty(path) ? Directory.GetCurrentDirectory() : Path.GetFullPath(path);

        if (!File.Exists(path) && !Directory.Exists(path))
        {
            AnsiConsole.MarkupLine($"[red]Path not found: {Markup.Escape(path)}[/]");
            return 1;
        }

        using var pipeline = new AnalysisPipeline(skipGitHub);
        pipeline.ShowGitHubStatus("No repo activity or vulnerability data.");

        var allReferences = await AnalysisPipeline.ScanProjectFilesAsync(path, ct);
        if (allReferences.Count == 0)
        {
            AnsiConsole.MarkupLine("[yellow]No package references found.[/]");
            return 0;
        }

        await pipeline.RunAsync(allReferences, ct);
        await pipeline.EnrichWithEpssAsync(ct);

        var packages = pipeline.Packages;

        // Calculate project score
        var projectScore = HealthScoreCalculator.CalculateProjectScore(packages);
        var projectStatus = projectScore switch
        {
            >= 80 => HealthStatus.Healthy,
            >= 60 => HealthStatus.Watch,
            >= 40 => HealthStatus.Warning,
            _ => HealthStatus.Critical
        };

        int healthyCount = 0, watchCount = 0, warningCount = 0, criticalCount = 0, vulnerableCount = 0;
        foreach (var p in packages)
        {
            switch (p.Status)
            {
                case HealthStatus.Healthy: healthyCount++; break;
                case HealthStatus.Watch: watchCount++; break;
                case HealthStatus.Warning: warningCount++; break;
                case HealthStatus.Critical: criticalCount++; break;
            }
            if (p.Vulnerabilities.Count > 0) vulnerableCount++;
        }

        var report = new ProjectReport
        {
            ProjectPath = path,
            GeneratedAt = DateTime.UtcNow,
            OverallScore = projectScore,
            OverallStatus = projectStatus,
            Packages = packages.OrderBy(p => p.Score).ToList(),
            Summary = new ProjectSummary
            {
                TotalPackages = packages.Count,
                HealthyCount = healthyCount,
                WatchCount = watchCount,
                WarningCount = warningCount,
                CriticalCount = criticalCount,
                VulnerableCount = vulnerableCount
            }
        };

        // Output based on format
        switch (format)
        {
            case OutputFormat.Json:
                OutputJson(report);
                break;
            case OutputFormat.Markdown:
                OutputMarkdown(report);
                break;
            default:
                OutputTable(report, false, skipGitHub);
                break;
        }

        // Typosquatting check (optional)
        if (checkTyposquat)
        {
            var typosquatResults = await TyposquatCommand.RunAnalysisAsync(path, offline: false, ct);
            if (typosquatResults.Count > 0)
            {
                AnsiConsole.WriteLine();
                AnsiConsole.Write(new Rule("[yellow bold]Typosquatting Warnings[/]").LeftJustified());

                foreach (var result in typosquatResults)
                {
                    var riskColor = result.RiskLevel switch
                    {
                        TyposquatRiskLevel.Critical => "red",
                        TyposquatRiskLevel.High => "orange3",
                        TyposquatRiskLevel.Medium => "yellow",
                        _ => "dim"
                    };
                    AnsiConsole.MarkupLine($"  [{riskColor}]{result.RiskLevel}[/]  {Markup.Escape(result.PackageName)} -> {Markup.Escape(result.SimilarTo)} ({Markup.Escape(result.Detail)}, confidence: {result.Confidence}%)");
                }
            }
        }

        // Return exit code based on threshold
        if (failBelow.HasValue && projectScore < failBelow.Value)
        {
            AnsiConsole.MarkupLine($"\n[red]Project score {projectScore} is below threshold {failBelow.Value}[/]");
            return 1;
        }

        return 0;
    }

    private static void OutputTable(ProjectReport report, bool wasRateLimited = false, bool skippedGitHub = false)
    {
        AnsiConsole.WriteLine();
        AnsiConsole.Write(new Rule($"[bold]Package Health Report[/]").LeftJustified());
        AnsiConsole.MarkupLine($"[dim]{Markup.Escape(report.ProjectPath)}[/]");
        AnsiConsole.WriteLine();

        var hasEpss = report.Packages.Any(p => p.MaxEpssProbability.HasValue);

        var table = new Table()
            .Border(TableBorder.Rounded)
            .AddColumn("Package")
            .AddColumn("Version")
            .AddColumn(new TableColumn("Score").Centered())
            .AddColumn("Status");

        if (hasEpss)
            table.AddColumn(new TableColumn("EPSS Risk").Centered());

        foreach (var pkg in report.Packages)
        {
            var statusMarkup = pkg.Status switch
            {
                HealthStatus.Healthy => "[green]✓ Healthy[/]",
                HealthStatus.Watch => "[yellow]◉ Watch[/]",
                HealthStatus.Warning => "[orange3]⚠ Warning[/]",
                HealthStatus.Critical => "[red]✗ Critical[/]",
                _ => pkg.Status.ToString()
            };

            var scoreColor = pkg.Score switch
            {
                >= 80 => "green",
                >= 60 => "yellow",
                >= 40 => "orange3",
                _ => "red"
            };

            if (hasEpss)
            {
                var epssDisplay = FormatEpss(pkg.MaxEpssProbability, pkg.MaxEpssPercentile);
                table.AddRow(
                    Markup.Escape(pkg.PackageId),
                    Markup.Escape(pkg.Version),
                    $"[{scoreColor}]{pkg.Score}[/]",
                    statusMarkup,
                    epssDisplay);
            }
            else
            {
                table.AddRow(
                    Markup.Escape(pkg.PackageId),
                    Markup.Escape(pkg.Version),
                    $"[{scoreColor}]{pkg.Score}[/]",
                    statusMarkup);
            }
        }

        AnsiConsole.Write(table);

        // Summary
        var statusColor = report.OverallStatus switch
        {
            HealthStatus.Healthy => "green",
            HealthStatus.Watch => "yellow",
            HealthStatus.Warning => "orange3",
            _ => "red"
        };

        AnsiConsole.WriteLine();
        AnsiConsole.MarkupLine($"[bold]Project Score: [{statusColor}]{report.OverallScore}/100[/] ({report.OverallStatus})[/]");

        var summaryTable = new Table()
            .Border(TableBorder.None)
            .HideHeaders()
            .AddColumn("")
            .AddColumn("");

        summaryTable.AddRow("[green]Healthy[/]", report.Summary.HealthyCount.ToString());
        summaryTable.AddRow("[yellow]Watch[/]", report.Summary.WatchCount.ToString());
        summaryTable.AddRow("[orange3]Warning[/]", report.Summary.WarningCount.ToString());
        summaryTable.AddRow("[red]Critical[/]", report.Summary.CriticalCount.ToString());

        if (report.Summary.VulnerableCount > 0)
        {
            summaryTable.AddRow("[red bold]Vulnerable[/]", report.Summary.VulnerableCount.ToString());
        }

        AnsiConsole.Write(summaryTable);

        // Show warnings
        if (wasRateLimited)
        {
            AnsiConsole.MarkupLine("\n[yellow]⚠ GitHub API rate limited - some repo data may be incomplete[/]");
        }
        if (skippedGitHub)
        {
            AnsiConsole.MarkupLine("\n[dim]Note: GitHub data skipped (--skip-github). Scores based on NuGet data only.[/]");
        }

        // Recommendations for low-scoring packages
        var problemPackages = report.Packages.Where(p => p.Recommendations.Count > 0).ToList();
        if (problemPackages.Count > 0)
        {
            AnsiConsole.WriteLine();
            AnsiConsole.Write(new Rule("[bold]Recommendations[/]").LeftJustified());

            foreach (var pkg in problemPackages)
            {
                AnsiConsole.MarkupLine($"\n[bold]{Markup.Escape(pkg.PackageId)}[/] (score: {pkg.Score})");
                foreach (var rec in pkg.Recommendations)
                {
                    AnsiConsole.MarkupLine($"  \u2022 {Markup.Escape(rec)}");
                }
            }
        }
    }

    private static string FormatEpss(double? probability, double? percentile)
    {
        if (!probability.HasValue)
            return "[dim]-[/]";

        var pct = probability.Value * 100;
        var pRank = percentile.HasValue ? $"p{(int)(percentile.Value * 100)}" : "";
        var color = probability.Value switch
        {
            >= 0.5 => "red",
            >= 0.1 => "orange3",
            >= 0.01 => "yellow",
            _ => "dim"
        };

        return $"[{color}]{pct:F1}% ({pRank})[/]";
    }

    private static void OutputJson(ProjectReport report)
    {
        var json = JsonSerializer.Serialize(report, JsonDefaults.Indented);
        Console.WriteLine(json);
    }

    private static void OutputMarkdown(ProjectReport report)
    {
        Console.WriteLine($"# Package Health Report");
        Console.WriteLine($"\n**Project:** {report.ProjectPath}");
        Console.WriteLine($"**Generated:** {report.GeneratedAt:yyyy-MM-dd HH:mm:ss} UTC");
        Console.WriteLine($"**Project Score:** {report.OverallScore}/100 ({report.OverallStatus})");

        Console.WriteLine("\n## Summary\n");
        Console.WriteLine($"- Total Packages: {report.Summary.TotalPackages}");
        Console.WriteLine($"- Healthy: {report.Summary.HealthyCount}");
        Console.WriteLine($"- Watch: {report.Summary.WatchCount}");
        Console.WriteLine($"- Warning: {report.Summary.WarningCount}");
        Console.WriteLine($"- Critical: {report.Summary.CriticalCount}");

        if (report.Summary.VulnerableCount > 0)
        {
            Console.WriteLine($"- **Vulnerable: {report.Summary.VulnerableCount}**");
        }

        Console.WriteLine("\n## Packages\n");
        Console.WriteLine("| Package | Version | Score | Status |");
        Console.WriteLine("|---------|---------|-------|--------|");

        foreach (var pkg in report.Packages)
        {
            var statusEmoji = pkg.Status switch
            {
                HealthStatus.Healthy => "✅",
                HealthStatus.Watch => "🔵",
                HealthStatus.Warning => "⚠️",
                HealthStatus.Critical => "❌",
                _ => "?"
            };
            Console.WriteLine($"| {pkg.PackageId} | {pkg.Version} | {pkg.Score} | {statusEmoji} {pkg.Status} |");
        }

        var problemPackages = report.Packages.Where(p => p.Recommendations.Count > 0).ToList();
        if (problemPackages.Count > 0)
        {
            Console.WriteLine("\n## Recommendations\n");
            foreach (var pkg in problemPackages)
            {
                Console.WriteLine($"### {pkg.PackageId} (score: {pkg.Score})\n");
                foreach (var rec in pkg.Recommendations)
                {
                    Console.WriteLine($"- {rec}");
                }
                Console.WriteLine();
            }
        }
    }
}
