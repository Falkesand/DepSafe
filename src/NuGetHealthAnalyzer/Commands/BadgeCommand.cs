using System.CommandLine;
using System.Text;
using System.Text.Json;
using System.Web;
using NuGetHealthAnalyzer.DataSources;
using NuGetHealthAnalyzer.Models;
using NuGetHealthAnalyzer.Scoring;
using Spectre.Console;

namespace NuGetHealthAnalyzer.Commands;

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

        command.SetHandler(ExecuteAsync, pathArg, formatOption, outputOption, styleOption, skipGitHubOption);

        return command;
    }

    private static async Task<int> ExecuteAsync(string? path, BadgeFormat format, string? outputPath, string style, bool skipGitHub)
    {
        path = string.IsNullOrEmpty(path) ? Directory.GetCurrentDirectory() : Path.GetFullPath(path);

        if (!File.Exists(path) && !Directory.Exists(path))
        {
            AnsiConsole.MarkupLine($"[red]Path not found: {path}[/]");
            return 1;
        }

        // Get packages
        var (topLevel, transitive) = await NuGetApiClient.ParsePackagesWithDotnetAsync(path);

        if (topLevel.Count == 0)
        {
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

        // Analyze health
        using var nugetClient = new NuGetApiClient();
        var githubClient = skipGitHub ? null : new GitHubApiClient();
        var calculator = new HealthScoreCalculator();
        var packages = new List<PackageHealth>();
        var vulnCount = 0;

        await AnsiConsole.Status()
            .StartAsync("Analyzing packages...", async ctx =>
            {
                var allPackageIds = topLevel.Select(p => p.PackageId).ToList();
                var allVulnerabilities = new Dictionary<string, List<VulnerabilityInfo>>(StringComparer.OrdinalIgnoreCase);

                // Fetch vulnerabilities if GitHub available
                if (githubClient?.HasToken == true)
                {
                    allVulnerabilities = await githubClient.GetVulnerabilitiesBatchAsync(allPackageIds);
                    vulnCount = allVulnerabilities.Values.Sum(v => v.Count);
                }

                foreach (var pkg in topLevel)
                {
                    var nugetInfo = await nugetClient.GetPackageInfoAsync(pkg.PackageId);
                    if (nugetInfo == null) continue;

                    var vulnerabilities = allVulnerabilities.GetValueOrDefault(pkg.PackageId, []);

                    var health = calculator.Calculate(
                        pkg.PackageId,
                        pkg.Version,
                        nugetInfo,
                        null,
                        vulnerabilities);

                    packages.Add(health);
                }
            });

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
            await File.WriteAllTextAsync(outputPath, output);
            AnsiConsole.MarkupLine($"[green]Badges written to {outputPath}[/]");
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
        sb.AppendLine("<!-- Generated by NuGet Health Analyzer -->");

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
        sb.AppendLine("<!-- Generated by NuGet Health Analyzer -->");

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

        return JsonSerializer.Serialize(data, new JsonSerializerOptions
        {
            WriteIndented = true,
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase
        });
    }
}

public enum BadgeFormat
{
    Markdown,
    Html,
    Json,
    Url
}
