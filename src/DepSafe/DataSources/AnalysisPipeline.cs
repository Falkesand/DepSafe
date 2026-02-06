using DepSafe.Models;
using DepSafe.Scoring;
using Spectre.Console;

namespace DepSafe.DataSources;

/// <summary>
/// Shared analysis pipeline for .NET package health assessment.
/// Eliminates duplication across Analyze, Sbom, Vex, and Badge commands.
/// </summary>
public sealed class AnalysisPipeline : IDisposable
{
    private readonly NuGetApiClient _nugetClient;
    private readonly GitHubApiClient? _githubClient;
    private readonly HealthScoreCalculator _calculator = new();
    private bool _disposed;

    public Dictionary<string, NuGetPackageInfo> NuGetInfoMap { get; } = new(StringComparer.OrdinalIgnoreCase);
    public Dictionary<string, GitHubRepoInfo?> RepoInfoMap { get; } = new(StringComparer.OrdinalIgnoreCase);
    public Dictionary<string, List<VulnerabilityInfo>> VulnerabilityMap { get; } = new(StringComparer.OrdinalIgnoreCase);
    public List<PackageHealth> Packages { get; } = [];

    public AnalysisPipeline(bool skipGitHub = false)
    {
        _nugetClient = new NuGetApiClient();
        _githubClient = skipGitHub ? null : new GitHubApiClient();
    }

    /// <summary>
    /// Show GitHub API status messages to the user.
    /// </summary>
    public void ShowGitHubStatus(string skipMessage = "No repo activity or vulnerability data.")
    {
        if (_githubClient is not null)
        {
            if (!_githubClient.HasToken)
            {
                AnsiConsole.MarkupLine("[yellow]No GITHUB_TOKEN found. GitHub API rate limited to 60 requests/hour.[/]");
                AnsiConsole.MarkupLine("[dim]Set GITHUB_TOKEN environment variable for 5000 requests/hour.[/]");
                AnsiConsole.WriteLine();
            }
        }
        else
        {
            AnsiConsole.MarkupLine($"[dim]Skipping GitHub API (--skip-github). {Markup.Escape(skipMessage)}[/]");
            AnsiConsole.WriteLine();
        }
    }

    /// <summary>
    /// Scan project files and collect package references with deduplication.
    /// </summary>
    public async Task<Dictionary<string, PackageReference>> ScanProjectFilesAsync(string path)
    {
        var projectFiles = NuGetApiClient.FindProjectFiles(path).ToList();
        if (projectFiles.Count == 0)
            return new Dictionary<string, PackageReference>(StringComparer.OrdinalIgnoreCase);

        var allReferences = new Dictionary<string, PackageReference>(StringComparer.OrdinalIgnoreCase);

        await AnsiConsole.Status()
            .StartAsync("Scanning project files...", async _ =>
            {
                foreach (var projectFile in projectFiles)
                {
                    var refs = await NuGetApiClient.ParseProjectFileAsync(projectFile);
                    foreach (var r in refs)
                    {
                        allReferences.TryAdd(r.PackageId, r);
                    }
                }
            });

        return allReferences;
    }

    /// <summary>
    /// Run the full analysis pipeline: NuGet info, GitHub repo info, vulnerabilities, and health scores.
    /// </summary>
    public async Task RunAsync(Dictionary<string, PackageReference> allReferences)
    {
        // Phase 1: Fetch NuGet info
        await AnsiConsole.Progress()
            .StartAsync(async ctx =>
            {
                var task = ctx.AddTask($"Fetching NuGet info for {allReferences.Count} packages", maxValue: allReferences.Count);

                foreach (var (packageId, _) in allReferences)
                {
                    task.Description = $"NuGet: {packageId}";
                    var info = await _nugetClient.GetPackageInfoAsync(packageId);
                    if (info is not null)
                    {
                        NuGetInfoMap[packageId] = info;
                    }
                    task.Increment(1);
                }
            });

        // Phase 2: GitHub repo info (if not skipped)
        if (_githubClient is not null && !_githubClient.IsRateLimited)
        {
            await AnsiConsole.Status()
                .StartAsync("Fetching GitHub repository info (batch)...", async ctx =>
                {
                    var repoUrls = NuGetInfoMap.Values
                        .Select(n => n.RepositoryUrl ?? n.ProjectUrl)
                        .Where(u => u?.Contains("github.com", StringComparison.OrdinalIgnoreCase) == true)
                        .ToList();

                    if (repoUrls.Count > 0)
                    {
                        var results = await _githubClient.GetRepositoriesBatchAsync(repoUrls);

                        foreach (var (packageId, info) in NuGetInfoMap)
                        {
                            var url = info.RepositoryUrl ?? info.ProjectUrl;
                            if (url is not null && results.TryGetValue(url, out var repoInfo))
                            {
                                RepoInfoMap[packageId] = repoInfo;
                            }
                        }
                    }

                    if (_githubClient.IsRateLimited)
                    {
                        ctx.Status("[yellow]GitHub rate limited - continuing with available data[/]");
                    }
                });

            // Phase 3: Vulnerabilities
            if (!_githubClient.IsRateLimited && _githubClient.HasToken)
            {
                await AnsiConsole.Status()
                    .StartAsync("Checking vulnerabilities (batch)...", async ctx =>
                    {
                        var vulns = await _githubClient.GetVulnerabilitiesBatchAsync(allReferences.Keys);
                        foreach (var kvp in vulns)
                        {
                            VulnerabilityMap[kvp.Key] = kvp.Value;
                        }

                        if (_githubClient.IsRateLimited)
                        {
                            ctx.Status("[yellow]GitHub rate limited - continuing with available data[/]");
                        }
                    });
            }
        }

        // Phase 4: Calculate health scores
        foreach (var (packageId, reference) in allReferences)
        {
            if (!NuGetInfoMap.TryGetValue(packageId, out var nugetInfo))
                continue;

            RepoInfoMap.TryGetValue(packageId, out var repoInfo);
            VulnerabilityMap.TryGetValue(packageId, out var vulnerabilities);
            vulnerabilities ??= [];

            var health = _calculator.Calculate(
                packageId,
                reference.Version,
                nugetInfo,
                repoInfo,
                vulnerabilities);

            Packages.Add(health);
        }
    }

    /// <summary>
    /// Enrich vulnerabilities with EPSS exploit probability scores.
    /// </summary>
    public async Task EnrichWithEpssAsync()
    {
        var allCveSet = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var vulnList in VulnerabilityMap.Values)
            foreach (var vi in vulnList)
                foreach (var c in vi.Cves)
                    if (!string.IsNullOrEmpty(c))
                        allCveSet.Add(c);
        var allCves = allCveSet.ToList();

        if (allCves.Count == 0) return;

        using var epssService = new EpssService();
        var epssScores = await AnsiConsole.Status()
            .StartAsync("Fetching EPSS exploit probability scores...", async _ =>
                await epssService.GetScoresAsync(allCves));

        // Build O(1) lookup for Packages by PackageId
        var packageLookup = new Dictionary<string, PackageHealth>(Packages.Count, StringComparer.OrdinalIgnoreCase);
        foreach (var p in Packages)
            packageLookup.TryAdd(p.PackageId, p);

        foreach (var (packageId, vulns) in VulnerabilityMap)
        {
            foreach (var vuln in vulns)
            {
                EpssScore? maxEpss = null;
                foreach (var c in vuln.Cves)
                {
                    if (epssScores.TryGetValue(c, out var score) &&
                        (maxEpss is null || score.Probability > maxEpss.Probability))
                        maxEpss = score;
                }

                if (maxEpss is not null)
                {
                    vuln.EpssProbability = maxEpss.Probability;
                    vuln.EpssPercentile = maxEpss.Percentile;
                }
            }

            if (packageLookup.TryGetValue(packageId, out var pkg))
            {
                var maxPkgEpss = vulns
                    .Where(v => v.EpssProbability.HasValue)
                    .OrderByDescending(v => v.EpssProbability)
                    .FirstOrDefault();

                if (maxPkgEpss is not null)
                {
                    pkg.MaxEpssProbability = maxPkgEpss.EpssProbability;
                    pkg.MaxEpssPercentile = maxPkgEpss.EpssPercentile;
                }
            }
        }
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _nugetClient.Dispose();
        _githubClient?.Dispose();
    }
}
