using System.CommandLine;
using System.CommandLine.Invocation;
using System.Text.Json;
using DepSafe.DataSources;
using DepSafe.Scoring;
using Spectre.Console;

namespace DepSafe.Commands;

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

        command.SetHandler(async context =>
        {
            var packageId = context.ParseResult.GetValueForArgument(packageArg);
            var version = context.ParseResult.GetValueForOption(versionOption);
            var format = context.ParseResult.GetValueForOption(formatOption);
            var skipGitHub = context.ParseResult.GetValueForOption(skipGitHubOption);
            var ct = context.GetCancellationToken();
            context.ExitCode = await ExecuteAsync(packageId, version, format, skipGitHub, ct);
        });

        return command;
    }

    private static async Task<int> ExecuteAsync(string packageId, string? version, OutputFormat format, bool skipGitHub, CancellationToken ct)
    {
        using var nugetClient = new NuGetApiClient();
        using var githubClient = skipGitHub ? null : new GitHubApiClient();
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

        var nugetResult = await AnsiConsole.Status()
            .StartAsync($"Fetching package info for {packageId}...", async _ =>
                await nugetClient.GetPackageInfoAsync(packageId, ct));

        if (nugetResult.IsFailure)
        {
            AnsiConsole.MarkupLine($"[red]{Markup.Escape(nugetResult.Error)}[/]");
            return 1;
        }

        var nugetInfo = nugetResult.Value;

        version ??= nugetInfo.LatestVersion;

        Models.GitHubRepoInfo? repoInfo = null;
        List<Models.VulnerabilityInfo> vulnerabilities = [];

        if (githubClient is not null && !githubClient.IsRateLimited)
        {
            var repoResult = await AnsiConsole.Status()
                .StartAsync("Fetching repository info...", async _ =>
                    await githubClient.GetRepositoryInfoAsync(nugetInfo.RepositoryUrl ?? nugetInfo.ProjectUrl, ct));
            if (repoResult.IsSuccess) repoInfo = repoResult.Value;

            if (!githubClient.IsRateLimited && githubClient.HasToken)
            {
                vulnerabilities = await AnsiConsole.Status()
                    .StartAsync("Checking vulnerabilities...", async _ =>
                        await githubClient.GetVulnerabilitiesAsync(packageId, version, ct));
            }
        }

        var health = calculator.Calculate(packageId, version, nugetInfo, repoInfo, vulnerabilities);

        // EPSS enrichment - fetch exploit probability scores for all CVEs
        if (vulnerabilities.Count > 0)
        {
            var allCves = vulnerabilities.SelectMany(v => v.Cves).Where(c => !string.IsNullOrEmpty(c)).ToList();
            if (allCves.Count > 0)
            {
                using var epssService = new EpssService();
                var epssScores = await AnsiConsole.Status()
                    .StartAsync("Fetching EPSS exploit probability scores...", async _ =>
                        await epssService.GetScoresAsync(allCves, ct));

                foreach (var vuln in vulnerabilities)
                {
                    var maxEpss = vuln.Cves
                        .Select(c => epssScores.TryGetValue(c, out var score) ? score : null)
                        .Where(s => s is not null)
                        .MaxBy(s => s!.Probability);

                    if (maxEpss is not null)
                    {
                        vuln.EpssProbability = maxEpss.Probability;
                        vuln.EpssPercentile = maxEpss.Percentile;
                    }
                }

                // Enrich PackageHealth with max EPSS
                var maxPkgEpss = vulnerabilities
                    .Where(v => v.EpssProbability.HasValue)
                    .MaxBy(v => v.EpssProbability);

                if (maxPkgEpss is not null)
                {
                    health.MaxEpssProbability = maxPkgEpss.EpssProbability;
                    health.MaxEpssPercentile = maxPkgEpss.EpssPercentile;
                }
            }
        }

        if (format == OutputFormat.Json)
        {
            var json = JsonSerializer.Serialize(health, JsonDefaults.Indented);
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

        table.AddRow("Package ID", Markup.Escape(packageId));
        table.AddRow("Version", Markup.Escape(version));
        table.AddRow("Latest Version", Markup.Escape(nugetInfo.LatestVersion));
        table.AddRow("Total Downloads", FormatNumber(nugetInfo.TotalDownloads));
        table.AddRow("Days Since Release", health.Metrics.DaysSinceLastRelease?.ToString() ?? "[dim]Unknown[/]");
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
            table.AddRow("License", Markup.Escape(health.License));
        }

        if (!string.IsNullOrEmpty(health.RepositoryUrl))
        {
            table.AddRow("Repository", Markup.Escape(health.RepositoryUrl));
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
                .AddColumn("EPSS")
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

                var epssDisplay = FormatEpss(vuln.EpssProbability, vuln.EpssPercentile);

                var summaryText = vuln.Summary.Length > 50 ? vuln.Summary[..47] + "..." : vuln.Summary;
                vulnTable.AddRow(
                    Markup.Escape(vuln.Id),
                    $"[{severityColor}]{Markup.Escape(vuln.Severity)}[/]",
                    epssDisplay,
                    Markup.Escape(summaryText),
                    Markup.Escape(vuln.PatchedVersion ?? "N/A"));
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
                AnsiConsole.MarkupLine($"  \u2022 {Markup.Escape(rec)}");
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

    private static string FormatEpss(double? probability, double? percentile)
    {
        if (!probability.HasValue)
            return "[dim]N/A[/]";

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
}
