using System.CommandLine;
using NuGetHealthAnalyzer.Compliance;
using NuGetHealthAnalyzer.DataSources;
using NuGetHealthAnalyzer.Models;
using NuGetHealthAnalyzer.Scoring;
using Spectre.Console;

namespace NuGetHealthAnalyzer.Commands;

public static class CraReportCommand
{
    public static Command Create()
    {
        var pathArg = new Argument<string?>(
            "path",
            () => ".",
            "Path to project, solution, or directory");

        var formatOption = new Option<CraOutputFormat>(
            ["--format", "-f"],
            () => CraOutputFormat.Html,
            "Output format (html or json)");

        var outputOption = new Option<string?>(
            ["--output", "-o"],
            "Output file path (default: cra-report.html or cra-report.json)");

        var command = new Command("cra-report", "Generate comprehensive CRA compliance report")
        {
            pathArg,
            formatOption,
            outputOption
        };

        command.SetHandler(ExecuteAsync, pathArg, formatOption, outputOption);

        return command;
    }

    private static async Task<int> ExecuteAsync(string? path, CraOutputFormat format, string? outputPath)
    {
        path = string.IsNullOrEmpty(path) ? Directory.GetCurrentDirectory() : Path.GetFullPath(path);

        if (!File.Exists(path) && !Directory.Exists(path))
        {
            AnsiConsole.MarkupLine($"[red]Path not found: {path}[/]");
            return 1;
        }

        var projectFiles = NuGetApiClient.FindProjectFiles(path).ToList();
        if (projectFiles.Count == 0)
        {
            AnsiConsole.MarkupLine("[yellow]No project files found.[/]");
            return 0;
        }

        using var nugetClient = new NuGetApiClient();
        var githubClient = new GitHubApiClient();
        var calculator = new HealthScoreCalculator();

        // Collect all package references
        var allReferences = new Dictionary<string, PackageReference>(StringComparer.OrdinalIgnoreCase);

        await AnsiConsole.Status()
            .StartAsync("Scanning project files...", async ctx =>
            {
                foreach (var projectFile in projectFiles)
                {
                    var refs = await NuGetApiClient.ParseProjectFileAsync(projectFile);
                    foreach (var r in refs)
                    {
                        if (!allReferences.ContainsKey(r.PackageId))
                        {
                            allReferences[r.PackageId] = r;
                        }
                    }
                }
            });

        if (allReferences.Count == 0)
        {
            AnsiConsole.MarkupLine("[yellow]No package references found.[/]");
            return 0;
        }

        var packages = new List<PackageHealth>();
        var allVulnerabilities = new Dictionary<string, List<VulnerabilityInfo>>(StringComparer.OrdinalIgnoreCase);

        await AnsiConsole.Progress()
            .StartAsync(async ctx =>
            {
                var task = ctx.AddTask($"Analyzing {allReferences.Count} packages", maxValue: allReferences.Count);

                foreach (var (packageId, reference) in allReferences)
                {
                    task.Description = $"Analyzing {packageId}";

                    var nugetInfo = await nugetClient.GetPackageInfoAsync(packageId);
                    if (nugetInfo is null)
                    {
                        task.Increment(1);
                        continue;
                    }

                    var repoInfo = await githubClient.GetRepositoryInfoAsync(nugetInfo.RepositoryUrl ?? nugetInfo.ProjectUrl);
                    var vulnerabilities = await githubClient.GetVulnerabilitiesAsync(packageId, reference.Version);

                    if (vulnerabilities.Count > 0)
                    {
                        allVulnerabilities[packageId] = vulnerabilities;
                    }

                    var health = calculator.Calculate(
                        packageId,
                        reference.Version,
                        nugetInfo,
                        repoInfo,
                        vulnerabilities);

                    packages.Add(health);
                    task.Increment(1);
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

        var healthReport = new ProjectReport
        {
            ProjectPath = path,
            GeneratedAt = DateTime.UtcNow,
            OverallScore = projectScore,
            OverallStatus = projectStatus,
            Packages = packages.OrderBy(p => p.Score).ToList(),
            Summary = new ProjectSummary
            {
                TotalPackages = packages.Count,
                HealthyCount = packages.Count(p => p.Status == HealthStatus.Healthy),
                WatchCount = packages.Count(p => p.Status == HealthStatus.Watch),
                WarningCount = packages.Count(p => p.Status == HealthStatus.Warning),
                CriticalCount = packages.Count(p => p.Status == HealthStatus.Critical),
                VulnerableCount = packages.Count(p => p.Vulnerabilities.Count > 0)
            }
        };

        var reportGenerator = new CraReportGenerator();
        var craReport = reportGenerator.Generate(healthReport, allVulnerabilities);

        // Determine output path
        if (string.IsNullOrEmpty(outputPath))
        {
            var projectName = Path.GetFileNameWithoutExtension(path);
            outputPath = format == CraOutputFormat.Json
                ? $"{projectName}-cra-report.json"
                : $"{projectName}-cra-report.html";
        }

        string output;
        if (format == CraOutputFormat.Json)
        {
            output = reportGenerator.GenerateJson(craReport);
        }
        else
        {
            output = reportGenerator.GenerateHtml(craReport);
        }

        await File.WriteAllTextAsync(outputPath, output);

        // Display summary
        AnsiConsole.WriteLine();
        AnsiConsole.Write(new Rule("[bold]CRA Compliance Report Generated[/]").LeftJustified());

        var statusColor = craReport.OverallComplianceStatus switch
        {
            CraComplianceStatus.Compliant => "green",
            CraComplianceStatus.ActionRequired => "yellow",
            _ => "red"
        };

        AnsiConsole.MarkupLine($"[bold]Overall Status:[/] [{statusColor}]{craReport.OverallComplianceStatus}[/]");
        AnsiConsole.MarkupLine($"[bold]Health Score:[/] {craReport.HealthScore}/100");
        AnsiConsole.MarkupLine($"[bold]Packages Analyzed:[/] {craReport.PackageCount}");
        AnsiConsole.MarkupLine($"[bold]Vulnerabilities Found:[/] {craReport.VulnerabilityCount}");

        AnsiConsole.WriteLine();

        var complianceTable = new Table()
            .Border(TableBorder.Rounded)
            .AddColumn("Requirement")
            .AddColumn("Status");

        foreach (var item in craReport.ComplianceItems)
        {
            var itemStatusColor = item.Status switch
            {
                CraComplianceStatus.Compliant => "green",
                CraComplianceStatus.ActionRequired => "yellow",
                _ => "red"
            };
            complianceTable.AddRow(item.Requirement, $"[{itemStatusColor}]{item.Status}[/]");
        }

        AnsiConsole.Write(complianceTable);

        AnsiConsole.MarkupLine($"\n[green]Report written to {outputPath}[/]");

        return craReport.OverallComplianceStatus == CraComplianceStatus.NonCompliant ? 1 : 0;
    }
}

public enum CraOutputFormat
{
    Html,
    Json
}
