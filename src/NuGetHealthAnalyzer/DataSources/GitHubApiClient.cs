using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using NuGetHealthAnalyzer.Models;
using Octokit;

namespace NuGetHealthAnalyzer.DataSources;

/// <summary>
/// Client for GitHub API using Octokit.
/// </summary>
public sealed partial class GitHubApiClient
{
    private readonly GitHubClient _client;
    private readonly HttpClient _httpClient;
    private readonly ResponseCache _cache;
    private readonly SemaphoreSlim _rateLimiter = new(1);
    private DateTime _rateLimitReset = DateTime.MinValue;
    private readonly string? _token;

    public GitHubApiClient(string? token = null, ResponseCache? cache = null)
    {
        _client = new GitHubClient(new ProductHeaderValue("NuGetHealthAnalyzer"));
        _httpClient = new HttpClient();
        _httpClient.DefaultRequestHeaders.Add("User-Agent", "NuGetHealthAnalyzer");

        _token = token ?? Environment.GetEnvironmentVariable("GITHUB_TOKEN");

        if (!string.IsNullOrEmpty(_token))
        {
            _client.Credentials = new Credentials(_token);
            _httpClient.DefaultRequestHeaders.Add("Authorization", $"Bearer {_token}");
        }

        _cache = cache ?? new ResponseCache();
    }

    /// <summary>
    /// Get repository information from a URL.
    /// </summary>
    public async Task<GitHubRepoInfo?> GetRepositoryInfoAsync(string? repoUrl, CancellationToken ct = default)
    {
        if (string.IsNullOrEmpty(repoUrl)) return null;

        var (owner, repo) = ParseGitHubUrl(repoUrl);
        if (owner is null || repo is null) return null;

        var cacheKey = $"github:{owner}/{repo}";
        var cached = await _cache.GetAsync<GitHubRepoInfo>(cacheKey, ct);
        if (cached is not null) return cached;

        await WaitForRateLimitAsync(ct);

        try
        {
            var repository = await _client.Repository.Get(owner, repo);

            // Get last commit date
            var commits = await _client.Repository.Commit.GetAll(owner, repo, new CommitRequest
            {
                Since = DateTimeOffset.UtcNow.AddYears(-1)
            }, new ApiOptions { PageCount = 1, PageSize = 1 });

            var lastCommitDate = commits.FirstOrDefault()?.Commit.Author?.Date.UtcDateTime
                ?? repository.PushedAt?.UtcDateTime
                ?? DateTime.MinValue;

            // Count commits in last year
            int commitsLastYear;
            try
            {
                var allCommits = await _client.Repository.Commit.GetAll(owner, repo, new CommitRequest
                {
                    Since = DateTimeOffset.UtcNow.AddYears(-1)
                }, new ApiOptions { PageCount = 10, PageSize = 100 });
                commitsLastYear = allCommits.Count;
            }
            catch
            {
                commitsLastYear = 0;
            }

            var result = new GitHubRepoInfo
            {
                Owner = owner,
                Name = repo,
                FullName = $"{owner}/{repo}",
                Stars = repository.StargazersCount,
                OpenIssues = repository.OpenIssuesCount,
                Forks = repository.ForksCount,
                LastCommitDate = lastCommitDate,
                LastPushDate = repository.PushedAt?.UtcDateTime ?? DateTime.MinValue,
                IsArchived = repository.Archived,
                IsFork = repository.Fork,
                License = repository.License?.SpdxId,
                CommitsLastYear = commitsLastYear
            };

            await _cache.SetAsync(cacheKey, result, TimeSpan.FromHours(6), ct);
            return result;
        }
        catch (RateLimitExceededException ex)
        {
            _rateLimitReset = ex.Reset.UtcDateTime;
            Console.Error.WriteLine($"GitHub rate limit exceeded. Resets at {_rateLimitReset:HH:mm:ss}");
            return null;
        }
        catch (NotFoundException)
        {
            return null;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Error fetching GitHub info for {owner}/{repo}: {ex.Message}");
            return null;
        }
    }

    /// <summary>
    /// Get vulnerabilities for a package from GitHub Advisory Database via GraphQL API.
    /// </summary>
    public async Task<List<VulnerabilityInfo>> GetVulnerabilitiesAsync(
        string packageId,
        string? version = null,
        CancellationToken ct = default)
    {
        var cacheKey = $"vuln:{packageId}:{version ?? "all"}";
        var cached = await _cache.GetAsync<List<VulnerabilityInfo>>(cacheKey, ct);
        if (cached is not null) return cached;

        // GraphQL requires authentication
        if (string.IsNullOrEmpty(_token))
        {
            return [];
        }

        await WaitForRateLimitAsync(ct);

        try
        {
            var query = @"
                query($ecosystem: SecurityAdvisoryEcosystem!, $package: String!) {
                    securityVulnerabilities(first: 20, ecosystem: $ecosystem, package: $package) {
                        nodes {
                            advisory {
                                ghsaId
                                summary
                                description
                                severity
                                publishedAt
                                permalink
                                identifiers {
                                    type
                                    value
                                }
                            }
                            vulnerableVersionRange
                            firstPatchedVersion {
                                identifier
                            }
                        }
                    }
                }";

            var requestBody = new
            {
                query,
                variables = new { ecosystem = "NUGET", package = packageId }
            };

            var response = await _httpClient.PostAsJsonAsync(
                "https://api.github.com/graphql",
                requestBody,
                ct);

            if (!response.IsSuccessStatusCode)
            {
                return [];
            }

            var jsonOptions = new JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true
            };

            var result = await response.Content.ReadFromJsonAsync<GraphQLResponse>(jsonOptions, ct);

            var vulnerabilities = new List<VulnerabilityInfo>();

            if (result?.Data?.SecurityVulnerabilities?.Nodes is { } nodes)
            {
                foreach (var node in nodes)
                {
                    var advisory = node.Advisory;
                    if (advisory is null) continue;

                    var cves = advisory.Identifiers?
                        .Where(i => i.Type == "CVE")
                        .Select(i => i.Value)
                        .ToList() ?? [];

                    vulnerabilities.Add(new VulnerabilityInfo
                    {
                        Id = advisory.GhsaId ?? "",
                        Severity = advisory.Severity ?? "UNKNOWN",
                        Summary = advisory.Summary ?? "",
                        Description = advisory.Description,
                        PackageId = packageId,
                        VulnerableVersionRange = node.VulnerableVersionRange ?? "",
                        PatchedVersion = node.FirstPatchedVersion?.Identifier,
                        Cves = cves,
                        Url = advisory.Permalink,
                        PublishedAt = advisory.PublishedAt
                    });
                }
            }

            await _cache.SetAsync(cacheKey, vulnerabilities, TimeSpan.FromHours(1), ct);
            return vulnerabilities;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Error fetching vulnerabilities for {packageId}: {ex.Message}");
            return [];
        }
    }

    private async Task WaitForRateLimitAsync(CancellationToken ct)
    {
        await _rateLimiter.WaitAsync(ct);
        try
        {
            if (DateTime.UtcNow < _rateLimitReset)
            {
                var delay = _rateLimitReset - DateTime.UtcNow;
                if (delay.TotalSeconds > 0)
                {
                    Console.Error.WriteLine($"Waiting {delay.TotalSeconds:F0}s for rate limit reset...");
                    await Task.Delay(delay, ct);
                }
            }
        }
        finally
        {
            _rateLimiter.Release();
        }
    }

    private static (string? owner, string? repo) ParseGitHubUrl(string url)
    {
        var match = GitHubUrlRegex().Match(url);
        if (match.Success)
        {
            var owner = match.Groups["owner"].Value;
            var repo = match.Groups["repo"].Value;
            // Remove .git suffix if present
            if (repo.EndsWith(".git", StringComparison.OrdinalIgnoreCase))
            {
                repo = repo[..^4];
            }
            return (owner, repo);
        }
        return (null, null);
    }

    [GeneratedRegex(@"github\.com[/:](?<owner>[^/]+)/(?<repo>[^/\s?#]+)", RegexOptions.IgnoreCase)]
    private static partial Regex GitHubUrlRegex();

    // GraphQL response types
    private sealed class GraphQLResponse
    {
        public GraphQLData? Data { get; set; }
    }

    private sealed class GraphQLData
    {
        public SecurityVulnerabilitiesResult? SecurityVulnerabilities { get; set; }
    }

    private sealed class SecurityVulnerabilitiesResult
    {
        public List<VulnerabilityNode>? Nodes { get; set; }
    }

    private sealed class VulnerabilityNode
    {
        public AdvisoryInfo? Advisory { get; set; }
        public string? VulnerableVersionRange { get; set; }
        public PatchedVersion? FirstPatchedVersion { get; set; }
    }

    private sealed class AdvisoryInfo
    {
        public string? GhsaId { get; set; }
        public string? Summary { get; set; }
        public string? Description { get; set; }
        public string? Severity { get; set; }
        public DateTime? PublishedAt { get; set; }
        public string? Permalink { get; set; }
        public List<IdentifierInfo>? Identifiers { get; set; }
    }

    private sealed class IdentifierInfo
    {
        public string Type { get; set; } = "";
        public string Value { get; set; } = "";
    }

    private sealed class PatchedVersion
    {
        public string? Identifier { get; set; }
    }
}
