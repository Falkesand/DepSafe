using System.CommandLine;
using System.CommandLine.Invocation;
using System.Text;
using System.Text.Json;
using System.Web;
using DepSafe.DataSources;
using DepSafe.Models;
using DepSafe.Scoring;
using Spectre.Console;

namespace DepSafe.Commands;

public static class BadgeCommand
{
    public static Command Create()
    {
        var pathArg = new Argument<string?>(
            "path",
            () => ".",
            "Path to project, solution, or directory");

        var formatOption = new Option<BadgeFormat>(
            ["--format", "-f"],
            () => BadgeFormat.Markdown,
            "Output format (markdown, html, json, or url)");

        var outputOption = new Option<string?>(
            ["--output", "-o"],
            "Output file path (default: stdout)");

        var styleOption = new Option<string>(
            ["--style", "-s"],
            () => "flat",
            "Badge style (flat, flat-square, plastic, for-the-badge)");

        var skipGitHubOption = new Option<bool>(
            ["--skip-github"],
            "Skip GitHub API calls (faster, but less accurate)");

        var command = new Command("badge", "Generate shields.io badges for README")
        {
            pathArg,
            formatOption,
            outputOption,
            styleOption,
            skipGitHubOption
        };

        command.SetHandler(async context =>
        {
            var path = context.ParseResult.GetValueForArgument(pathArg);
            var format = context.ParseResult.GetValueForOption(formatOption);
            var outputPath = context.ParseResult.GetValueForOption(outputOption);
            var style = context.ParseResult.GetValueForOption(styleOption)!;
            var skipGitHub = context.ParseResult.GetValueForOption(skipGitHubOption);
            var ct = context.GetCancellationToken();
            context.ExitCode = await ExecuteAsync(path, format, outputPath, style, skipGitHub, ct);
        });

        return command;
    }

    private static async Task<int> ExecuteAsync(string? path, BadgeFormat format, string? outputPath, string style, bool skipGitHub, CancellationToken ct)
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

        // Get transitive count from dotnet list (for badge display)
        var dotnetResult = await NuGetApiClient.ParsePackagesWithDotnetAsync(path, ct);
        var (topLevel, transitive) = dotnetResult.ValueOr(([], []));

        using var pipeline = new AnalysisPipeline(skipGitHub);
        var allReferences = await pipeline.ScanProjectFilesAsync(path, ct);

        // Merge in any packages from dotnet list that weren't found via project file parsing
        foreach (var pkg in topLevel)
        {
            allReferences.TryAdd(pkg.PackageId, pkg);
        }

        if (allReferences.Count == 0)
        {
            AnsiConsole.MarkupLine("[yellow]No package references found.[/]");
            return 0;
        }

        await pipeline.RunAsync(allReferences, ct);

        var packages = pipeline.Packages;
        var vulnCount = pipeline.VulnerabilityMap.Values.Sum(v => v.Count);

        // Calculate project score
        var projectScore = HealthScoreCalculator.CalculateProjectScore(packages);
        var projectStatus = projectScore switch
        {
            >= 80 => HealthStatus.Healthy,
            >= 60 => HealthStatus.Watch,
            >= 40 => HealthStatus.Warning,
            _ => HealthStatus.Critical
        };

        // Generate badges
        var badges = GenerateBadges(projectScore, projectStatus, packages.Count, vulnCount, transitive.Count, style);

        string output = format switch
        {
            BadgeFormat.Markdown => GenerateMarkdown(badges),
            BadgeFormat.Html => GenerateHtml(badges),
            BadgeFormat.Json => GenerateJson(badges, projectScore, projectStatus, packages.Count, vulnCount),
            BadgeFormat.Url => GenerateUrls(badges),
            _ => GenerateMarkdown(badges)
        };

        if (!string.IsNullOrEmpty(outputPath))
        {
            await File.WriteAllTextAsync(outputPath, output, ct);
            AnsiConsole.MarkupLine($"[green]Badges written to {Markup.Escape(outputPath)}[/]");
        }
        else
        {
            Console.WriteLine(output);
        }

        return 0;
    }

    private static Dictionary<string, string> GenerateBadges(int score, HealthStatus status, int packageCount, int vulnCount, int transitiveCount, string style)
    {
        var badges = new Dictionary<string, string>();

        // Health Score Badge
        var scoreColor = status switch
        {
            HealthStatus.Healthy => "brightgreen",
            HealthStatus.Watch => "blue",
            HealthStatus.Warning => "orange",
            _ => "red"
        };
        badges["health"] = $"https://img.shields.io/badge/health_score-{score}%2F100-{scoreColor}?style={style}";

        // Status Badge
        var statusText = HttpUtility.UrlEncode(status.ToString());
        badges["status"] = $"https://img.shields.io/badge/status-{statusText}-{scoreColor}?style={style}";

        // Package Count Badge
        badges["packages"] = $"https://img.shields.io/badge/packages-{packageCount}-informational?style={style}";

        // Transitive Count Badge
        badges["transitive"] = $"https://img.shields.io/badge/transitive-{transitiveCount}-lightgrey?style={style}";

        // Vulnerabilities Badge
        var vulnColor = vulnCount == 0 ? "brightgreen" : vulnCount <= 2 ? "orange" : "red";
        var vulnText = vulnCount == 0 ? "none" : vulnCount.ToString();
        badges["vulnerabilities"] = $"https://img.shields.io/badge/vulnerabilities-{vulnText}-{vulnColor}?style={style}";

        // CRA Compliance Badge (simplified)
        var craStatus = vulnCount == 0 && score >= 60 ? "compliant" : "review_required";
        var craColor = craStatus == "compliant" ? "brightgreen" : "orange";
        badges["cra"] = $"https://img.shields.io/badge/CRA-{craStatus}-{craColor}?style={style}";

        return badges;
    }

    private static string GenerateMarkdown(Dictionary<string, string> badges)
    {
        var sb = new StringBuilder();
        sb.AppendLine("<!-- NuGet Health Badges -->");
        sb.AppendLine();
        sb.AppendLine("## Dependency Health");
        sb.AppendLine();
        sb.AppendLine($"![Health Score]({badges["health"]})");
        sb.AppendLine($"![Status]({badges["status"]})");
        sb.AppendLine($"![Packages]({badges["packages"]})");
        sb.AppendLine($"![Vulnerabilities]({badges["vulnerabilities"]})");
        sb.AppendLine($"![CRA Compliance]({badges["cra"]})");
        sb.AppendLine();
        sb.AppendLine("<!-- Generated by DepSafe -->");

        return sb.ToString();
    }

    private static string GenerateHtml(Dictionary<string, string> badges)
    {
        var sb = new StringBuilder();
        sb.AppendLine("<!-- NuGet Health Badges -->");
        sb.AppendLine("<p>");
        sb.AppendLine($"  <img src=\"{badges["health"]}\" alt=\"Health Score\" />");
        sb.AppendLine($"  <img src=\"{badges["status"]}\" alt=\"Status\" />");
        sb.AppendLine($"  <img src=\"{badges["packages"]}\" alt=\"Packages\" />");
        sb.AppendLine($"  <img src=\"{badges["vulnerabilities"]}\" alt=\"Vulnerabilities\" />");
        sb.AppendLine($"  <img src=\"{badges["cra"]}\" alt=\"CRA Compliance\" />");
        sb.AppendLine("</p>");
        sb.AppendLine("<!-- Generated by DepSafe -->");

        return sb.ToString();
    }

    private static string GenerateUrls(Dictionary<string, string> badges)
    {
        var sb = new StringBuilder();
        foreach (var (name, url) in badges)
        {
            sb.AppendLine($"{name}: {url}");
        }
        return sb.ToString();
    }

    private static string GenerateJson(Dictionary<string, string> badges, int score, HealthStatus status, int packageCount, int vulnCount)
    {
        var data = new
        {
            score,
            status = status.ToString(),
            packageCount,
            vulnerabilityCount = vulnCount,
            badges
        };

        return JsonSerializer.Serialize(data, JsonDefaults.Indented);
    }
}
