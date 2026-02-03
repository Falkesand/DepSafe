using System.CommandLine;
using System.Text.Json;
using NuGetHealthAnalyzer.DataSources;
using NuGetHealthAnalyzer.Scoring;
using Spectre.Console;

namespace NuGetHealthAnalyzer.Commands;

public static class CheckCommand
{
    public static Command Create()
    {
        var packageArg = new Argument<string>(
            "package",
            "Package ID to check");

        var versionOption = new Option<string?>(
            ["--version", "-v"],
            "Specific version to check (defaults to latest)");

        var formatOption = new Option<OutputFormat>(
            ["--format", "-f"],
            () => OutputFormat.Table,
            "Output format");

        var skipGitHubOption = new Option<bool>(
            ["--skip-github"],
            "Skip GitHub API calls (faster, but no repo activity or vulnerability data)");

        var command = new Command("check", "Check health of a single package")
        {
            packageArg,
            versionOption,
            formatOption,
            skipGitHubOption
        };

        command.SetHandler(ExecuteAsync, packageArg, versionOption, formatOption, skipGitHubOption);

        return command;
    }

    private static async Task<int> ExecuteAsync(string packageId, string? version, OutputFormat format, bool skipGitHub)
    {
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
            AnsiConsole.MarkupLine("[dim]Skipping GitHub API (--skip-github). No repo activity or vulnerability data.[/]");
            AnsiConsole.WriteLine();
        }

        var nugetInfo = await AnsiConsole.Status()
            .StartAsync($"Fetching package info for {packageId}...", async _ =>
                await nugetClient.GetPackageInfoAsync(packageId));

        if (nugetInfo is null)
        {
            AnsiConsole.MarkupLine($"[red]Package not found: {packageId}[/]");
            return 1;
        }

        version ??= nugetInfo.LatestVersion;

        Models.GitHubRepoInfo? repoInfo = null;
        List<Models.VulnerabilityInfo> vulnerabilities = [];

        if (githubClient is not null && !githubClient.IsRateLimited)
        {
            repoInfo = await AnsiConsole.Status()
                .StartAsync("Fetching repository info...", async _ =>
                    await githubClient.GetRepositoryInfoAsync(nugetInfo.RepositoryUrl ?? nugetInfo.ProjectUrl));

            if (!githubClient.IsRateLimited && githubClient.HasToken)
            {
                vulnerabilities = await AnsiConsole.Status()
                    .StartAsync("Checking vulnerabilities...", async _ =>
                        await githubClient.GetVulnerabilitiesAsync(packageId, version));
            }
        }

        var health = calculator.Calculate(packageId, version, nugetInfo, repoInfo, vulnerabilities);

        if (format == OutputFormat.Json)
        {
            var json = JsonSerializer.Serialize(health, new JsonSerializerOptions
            {
                WriteIndented = true,
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase
            });
            Console.WriteLine(json);
            return 0;
        }

        // Table output
        AnsiConsole.WriteLine();

        var statusColor = health.Status switch
        {
            Models.HealthStatus.Healthy => "green",
            Models.HealthStatus.Watch => "yellow",
            Models.HealthStatus.Warning => "orange3",
            _ => "red"
        };

        var panel = new Panel(new Markup($"[bold {statusColor}]{health.Score}/100[/] - {health.Status}"))
        {
            Header = new PanelHeader($" {packageId} {version} "),
            Border = BoxBorder.Rounded,
            Padding = new Padding(2, 1)
        };
        AnsiConsole.Write(panel);

        // Details table
        var table = new Table()
            .Border(TableBorder.Rounded)
            .AddColumn("Metric")
            .AddColumn("Value");

        table.AddRow("Package ID", packageId);
        table.AddRow("Version", version);
        table.AddRow("Latest Version", nugetInfo.LatestVersion);
        table.AddRow("Total Downloads", FormatNumber(nugetInfo.TotalDownloads));
        table.AddRow("Days Since Release", health.Metrics.DaysSinceLastRelease.ToString());
        table.AddRow("Releases/Year", health.Metrics.ReleasesPerYear.ToString("F1"));
        table.AddRow("Download Trend", FormatTrend(health.Metrics.DownloadTrend));

        if (health.Metrics.DaysSinceLastCommit.HasValue)
        {
            table.AddRow("Days Since Commit", health.Metrics.DaysSinceLastCommit.Value.ToString());
        }

        if (health.Metrics.Stars.HasValue)
        {
            table.AddRow("GitHub Stars", FormatNumber(health.Metrics.Stars.Value));
        }

        if (health.Metrics.OpenIssues.HasValue)
        {
            table.AddRow("Open Issues", health.Metrics.OpenIssues.Value.ToString());
        }

        if (!string.IsNullOrEmpty(health.License))
        {
            table.AddRow("License", health.License);
        }

        if (!string.IsNullOrEmpty(health.RepositoryUrl))
        {
            table.AddRow("Repository", health.RepositoryUrl);
        }

        if (health.Metrics.VulnerabilityCount > 0)
        {
            table.AddRow("[red]Vulnerabilities[/]", $"[red]{health.Metrics.VulnerabilityCount}[/]");
        }

        AnsiConsole.Write(table);

        // Vulnerabilities
        if (vulnerabilities.Count > 0)
        {
            AnsiConsole.WriteLine();
            AnsiConsole.Write(new Rule("[red bold]Vulnerabilities[/]").LeftJustified());

            var vulnTable = new Table()
                .Border(TableBorder.Rounded)
                .AddColumn("ID")
                .AddColumn("Severity")
                .AddColumn("Summary")
                .AddColumn("Patched In");

            foreach (var vuln in vulnerabilities)
            {
                var severityColor = vuln.Severity.ToUpperInvariant() switch
                {
                    "CRITICAL" => "red",
                    "HIGH" => "orange3",
                    "MODERATE" or "MEDIUM" => "yellow",
                    _ => "dim"
                };

                vulnTable.AddRow(
                    vuln.Id,
                    $"[{severityColor}]{vuln.Severity}[/]",
                    vuln.Summary.Length > 50 ? vuln.Summary[..47] + "..." : vuln.Summary,
                    vuln.PatchedVersion ?? "N/A");
            }

            AnsiConsole.Write(vulnTable);
        }

        // Recommendations
        if (health.Recommendations.Count > 0)
        {
            AnsiConsole.WriteLine();
            AnsiConsole.Write(new Rule("[bold]Recommendations[/]").LeftJustified());

            foreach (var rec in health.Recommendations)
            {
                AnsiConsole.MarkupLine($"  • {rec}");
            }
        }

        return 0;
    }

    private static string FormatNumber(long number)
    {
        return number switch
        {
            >= 1_000_000_000 => $"{number / 1_000_000_000.0:F1}B",
            >= 1_000_000 => $"{number / 1_000_000.0:F1}M",
            >= 1_000 => $"{number / 1_000.0:F1}K",
            _ => number.ToString()
        };
    }

    private static string FormatTrend(double trend)
    {
        return trend switch
        {
            > 0.2 => $"[green]↑ Growing (+{trend:P0})[/]",
            < -0.2 => $"[red]↓ Declining ({trend:P0})[/]",
            _ => "[dim]→ Stable[/]"
        };
    }
}
