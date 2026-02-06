using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using DepSafe.Models;
using Octokit;

namespace DepSafe.DataSources;

/// <summary>
/// Client for GitHub API using Octokit with rate limit handling,
/// batch queries, and graceful degradation.
/// </summary>
public sealed partial class GitHubApiClient : IDisposable
{
    private readonly GitHubClient _client;
    private readonly HttpClient _httpClient;
    private readonly ResponseCache _cache;
    private readonly SemaphoreSlim _requestLimiter;
    private readonly string? _token;

    private bool _isRateLimited;
    private DateTime _rateLimitReset = DateTime.MinValue;
    private int _remainingRequests = int.MaxValue;

    /// <summary>
    /// Maximum concurrent GitHub API requests.
    /// </summary>
    public int MaxConcurrentRequests { get; }

    /// <summary>
    /// Whether the client is currently rate limited.
    /// </summary>
    public bool IsRateLimited => _isRateLimited && DateTime.UtcNow < _rateLimitReset;

    /// <summary>
    /// Whether a GitHub token is configured.
    /// </summary>
    public bool HasToken => !string.IsNullOrEmpty(_token);

    /// <summary>
    /// Remaining API requests before rate limit.
    /// </summary>
    public int RemainingRequests => _remainingRequests;

    public GitHubApiClient(string? token = null, ResponseCache? cache = null, int maxConcurrentRequests = 5)
    {
        MaxConcurrentRequests = maxConcurrentRequests;
        _requestLimiter = new SemaphoreSlim(maxConcurrentRequests);

        _client = new GitHubClient(new ProductHeaderValue("DepSafe"));
        _httpClient = new HttpClient(new HttpClientHandler
        {
            AutomaticDecompression = System.Net.DecompressionMethods.GZip | System.Net.DecompressionMethods.Deflate
        })
        { Timeout = TimeSpan.FromSeconds(30) };
        _httpClient.DefaultRequestHeaders.Add("User-Agent", "DepSafe");

        _token = token ?? Environment.GetEnvironmentVariable("GITHUB_TOKEN");

        if (!string.IsNullOrEmpty(_token))
        {
            _client.Credentials = new Credentials(_token);
            _httpClient.DefaultRequestHeaders.Add("Authorization", $"Bearer {_token}");
        }

        _cache = cache ?? new ResponseCache();
    }

    /// <summary>
    /// Get repository information for multiple URLs in a single batch query.
    /// </summary>
    public async Task<Dictionary<string, GitHubRepoInfo?>> GetRepositoriesBatchAsync(
        IEnumerable<string?> repoUrls,
        CancellationToken ct = default)
    {
        var results = new Dictionary<string, GitHubRepoInfo?>(StringComparer.OrdinalIgnoreCase);
        var urlsToFetch = new List<(string url, string owner, string repo)>();

        // Parse URLs and check cache
        foreach (var url in repoUrls.Where(u => !string.IsNullOrEmpty(u)).Distinct(StringComparer.OrdinalIgnoreCase))
        {
            var (owner, repo) = ParseGitHubUrl(url!);
            if (owner is null || repo is null)
            {
                results[url!] = null;
                continue;
            }

            var cacheKey = $"github:{owner}/{repo}";
            var cached = await _cache.GetAsync<GitHubRepoInfo>(cacheKey, ct);
            if (cached is not null)
            {
                results[url!] = cached;
            }
            else
            {
                urlsToFetch.Add((url!, owner, repo));
            }
        }

        if (urlsToFetch.Count == 0 || IsRateLimited)
        {
            // Fill remaining with nulls
            foreach (var (url, _, _) in urlsToFetch)
            {
                results.TryAdd(url, null);
            }
            return results;
        }

        // Batch fetch using GraphQL (up to 20 repos per query due to GraphQL complexity limits)
        const int batchSize = 20;
        foreach (var batch in urlsToFetch.Chunk(batchSize))
        {
            if (IsRateLimited) break;

            var batchResults = await FetchRepositoriesBatchGraphQLAsync(batch, ct);
            foreach (var (url, info) in batchResults)
            {
                results[url] = info;
                if (info is not null)
                {
                    var (owner, repo) = ParseGitHubUrl(url);
                    await _cache.SetAsync($"github:{owner}/{repo}", info, TimeSpan.FromHours(24), ct);
                }
            }
        }

        // Fill any missing with nulls
        foreach (var (url, _, _) in urlsToFetch)
        {
            results.TryAdd(url, null);
        }

        return results;
    }

    private async Task<Dictionary<string, GitHubRepoInfo?>> FetchRepositoriesBatchGraphQLAsync(
        IEnumerable<(string url, string owner, string repo)> repos,
        CancellationToken ct)
    {
        var results = new Dictionary<string, GitHubRepoInfo?>(StringComparer.OrdinalIgnoreCase);
        var repoList = repos.ToList();

        if (!HasToken || repoList.Count == 0)
        {
            foreach (var (url, _, _) in repoList)
                results[url] = null;
            return results;
        }

        await _requestLimiter.WaitAsync(ct);
        try
        {
            // Build GraphQL query for multiple repositories using StringBuilder
            var queryBuilder = new StringBuilder("query { ");
            for (int i = 0; i < repoList.Count; i++)
            {
                var (_, owner, repo) = repoList[i];
                queryBuilder.Append($@"
                    repo{i}: repository(owner: ""{SanitizeGraphQLString(owner)}"", name: ""{SanitizeGraphQLString(repo)}"") {{
                        nameWithOwner
                        stargazerCount
                        forkCount
                        isArchived
                        isFork
                        pushedAt
                        licenseInfo {{ spdxId }}
                        issues(states: OPEN) {{ totalCount }}
                        defaultBranchRef {{
                            target {{
                                ... on Commit {{
                                    history(first: 1) {{
                                        nodes {{ committedDate }}
                                    }}
                                }}
                            }}
                        }}
                        securityPolicy: object(expression: ""HEAD:SECURITY.md"") {{ id }}
                    }}");
            }
            queryBuilder.Append(" }");
            var query = queryBuilder.ToString();

            using var response = await _httpClient.PostAsJsonAsync(
                "https://api.github.com/graphql",
                new { query },
                ct);

            UpdateRateLimitFromResponse(response);

            if (!response.IsSuccessStatusCode)
            {
                if ((int)response.StatusCode == 403)
                {
                    _isRateLimited = true;
                }
                foreach (var (url, _, _) in repoList)
                    results[url] = null;
                return results;
            }

            var json = await response.Content.ReadFromJsonAsync<JsonElement>(JsonDefaults.CaseInsensitive, ct);

            if (json.TryGetProperty("data", out var data))
            {
                for (int i = 0; i < repoList.Count; i++)
                {
                    var (url, owner, repo) = repoList[i];

                    if (data.TryGetProperty($"repo{i}", out var repoData) &&
                        repoData.ValueKind != JsonValueKind.Null)
                    {
                        var info = ParseRepoFromGraphQL(repoData, owner, repo);
                        results[url] = info;
                    }
                    else
                    {
                        results[url] = null;
                    }
                }
            }
            else
            {
                foreach (var (url, _, _) in repoList)
                    results[url] = null;
            }
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Error in batch repository fetch: {ex.Message}");
            foreach (var (url, _, _) in repoList)
                results.TryAdd(url, null);
        }
        finally
        {
            _requestLimiter.Release();
        }

        return results;
    }

    private static GitHubRepoInfo ParseRepoFromGraphQL(JsonElement repoData, string owner, string repo)
    {
        var stars = repoData.TryGetProperty("stargazerCount", out var s) ? s.GetInt32() : 0;
        var forks = repoData.TryGetProperty("forkCount", out var f) ? f.GetInt32() : 0;
        var isArchived = repoData.TryGetProperty("isArchived", out var a) && a.GetBoolean();
        var isFork = repoData.TryGetProperty("isFork", out var fk) && fk.GetBoolean();
        var openIssues = 0;
        if (repoData.TryGetProperty("issues", out var issues) &&
            issues.TryGetProperty("totalCount", out var ic))
        {
            openIssues = ic.GetInt32();
        }

        var pushedAt = DateTime.MinValue;
        if (repoData.TryGetProperty("pushedAt", out var pa) && pa.ValueKind == JsonValueKind.String)
        {
            DateTime.TryParse(pa.GetString(), out pushedAt);
        }

        var lastCommitDate = pushedAt;
        if (repoData.TryGetProperty("defaultBranchRef", out var dbr) &&
            dbr.ValueKind != JsonValueKind.Null &&
            dbr.TryGetProperty("target", out var target) &&
            target.TryGetProperty("history", out var history) &&
            history.TryGetProperty("nodes", out var nodes) &&
            nodes.GetArrayLength() > 0)
        {
            var firstNode = nodes[0];
            if (firstNode.TryGetProperty("committedDate", out var cd) &&
                cd.ValueKind == JsonValueKind.String)
            {
                DateTime.TryParse(cd.GetString(), out lastCommitDate);
            }
        }

        string? license = null;
        if (repoData.TryGetProperty("licenseInfo", out var li) &&
            li.ValueKind != JsonValueKind.Null &&
            li.TryGetProperty("spdxId", out var spdx))
        {
            license = spdx.GetString();
        }

        // Check for SECURITY.md file (CRA Art. 11(5) - coordinated vulnerability disclosure)
        var hasSecurityPolicy = repoData.TryGetProperty("securityPolicy", out var sp) &&
                                sp.ValueKind != JsonValueKind.Null;

        return new GitHubRepoInfo
        {
            Owner = owner,
            Name = repo,
            FullName = $"{owner}/{repo}",
            Stars = stars,
            OpenIssues = openIssues,
            Forks = forks,
            LastCommitDate = lastCommitDate,
            LastPushDate = pushedAt,
            IsArchived = isArchived,
            IsFork = isFork,
            License = license,
            CommitsLastYear = 0, // Not fetched in batch for simplicity
            HasSecurityPolicy = hasSecurityPolicy
        };
    }

    /// <summary>
    /// Get repository information from a URL (single request, uses cache).
    /// </summary>
    public async Task<GitHubRepoInfo?> GetRepositoryInfoAsync(string? repoUrl, CancellationToken ct = default)
    {
        if (string.IsNullOrEmpty(repoUrl)) return null;
        if (IsRateLimited) return null;

        var (owner, repo) = ParseGitHubUrl(repoUrl);
        if (owner is null || repo is null) return null;

        var cacheKey = $"github:{owner}/{repo}";
        var cached = await _cache.GetAsync<GitHubRepoInfo>(cacheKey, ct);
        if (cached is not null) return cached;

        await _requestLimiter.WaitAsync(ct);
        try
        {
            var repository = await _client.Repository.Get(owner, repo);
            await UpdateRateLimitFromOctokitAsync();

            var lastCommitDate = repository.PushedAt?.UtcDateTime ?? DateTime.MinValue;

            // Check for SECURITY.md (CRA Art. 11(5))
            var hasSecurityPolicy = false;
            try
            {
                await _client.Repository.Content.GetAllContents(owner, repo, "SECURITY.md");
                hasSecurityPolicy = true;
            }
            catch (NotFoundException) { /* No SECURITY.md */ }

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
                CommitsLastYear = 0,
                HasSecurityPolicy = hasSecurityPolicy
            };

            await _cache.SetAsync(cacheKey, result, TimeSpan.FromHours(24), ct);
            return result;
        }
        catch (RateLimitExceededException ex)
        {
            _isRateLimited = true;
            _rateLimitReset = ex.Reset.UtcDateTime;
            _remainingRequests = 0;
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
        finally
        {
            _requestLimiter.Release();
        }
    }

    /// <summary>
    /// Get vulnerabilities for multiple packages in batch.
    /// </summary>
    public async Task<Dictionary<string, List<VulnerabilityInfo>>> GetVulnerabilitiesBatchAsync(
        IEnumerable<string> packageIds,
        CancellationToken ct = default)
    {
        var results = new Dictionary<string, List<VulnerabilityInfo>>(StringComparer.OrdinalIgnoreCase);
        var packagesToFetch = new List<string>();

        foreach (var packageId in packageIds.Distinct(StringComparer.OrdinalIgnoreCase))
        {
            var cacheKey = $"vuln:{packageId}:all";
            var cached = await _cache.GetAsync<List<VulnerabilityInfo>>(cacheKey, ct);
            if (cached is not null)
            {
                results[packageId] = cached;
            }
            else
            {
                packagesToFetch.Add(packageId);
            }
        }

        if (packagesToFetch.Count == 0 || !HasToken || IsRateLimited)
        {
            foreach (var pkg in packagesToFetch)
                results.TryAdd(pkg, []);
            return results;
        }

        // Batch vulnerabilities query (up to 10 packages per query)
        const int batchSize = 10;
        foreach (var batch in packagesToFetch.Chunk(batchSize))
        {
            if (IsRateLimited) break;

            var batchResults = await FetchVulnerabilitiesBatchAsync(batch, ct);
            foreach (var (packageId, vulns) in batchResults)
            {
                results[packageId] = vulns;
                await _cache.SetAsync($"vuln:{packageId}:all", vulns, TimeSpan.FromHours(1), ct);
            }
        }

        foreach (var pkg in packagesToFetch)
            results.TryAdd(pkg, []);

        return results;
    }

    private async Task<Dictionary<string, List<VulnerabilityInfo>>> FetchVulnerabilitiesBatchAsync(
        IEnumerable<string> packageIds,
        CancellationToken ct)
    {
        var results = new Dictionary<string, List<VulnerabilityInfo>>(StringComparer.OrdinalIgnoreCase);
        var packages = packageIds.ToList();

        await _requestLimiter.WaitAsync(ct);
        try
        {
            // Build query for multiple packages using StringBuilder
            var queryBuilder = new StringBuilder("query { ");
            for (int i = 0; i < packages.Count; i++)
            {
                queryBuilder.Append($@"
                    pkg{i}: securityVulnerabilities(first: 20, ecosystem: NUGET, package: ""{SanitizeGraphQLString(packages[i])}"") {{
                        nodes {{
                            advisory {{
                                ghsaId
                                summary
                                description
                                severity
                                publishedAt
                                permalink
                                identifiers {{ type value }}
                            }}
                            vulnerableVersionRange
                            firstPatchedVersion {{ identifier }}
                        }}
                    }}");
            }
            queryBuilder.Append(" }");
            var query = queryBuilder.ToString();

            using var response = await _httpClient.PostAsJsonAsync(
                "https://api.github.com/graphql",
                new { query },
                ct);

            UpdateRateLimitFromResponse(response);

            if (!response.IsSuccessStatusCode)
            {
                if ((int)response.StatusCode == 403)
                    _isRateLimited = true;

                foreach (var pkg in packages)
                    results[pkg] = [];
                return results;
            }

            var json = await response.Content.ReadFromJsonAsync<JsonElement>(JsonDefaults.CaseInsensitive, ct);

            if (json.TryGetProperty("data", out var data))
            {
                for (int i = 0; i < packages.Count; i++)
                {
                    var packageId = packages[i];
                    var vulns = new List<VulnerabilityInfo>();

                    if (data.TryGetProperty($"pkg{i}", out var pkgData) &&
                        pkgData.TryGetProperty("nodes", out var nodes))
                    {
                        foreach (var node in nodes.EnumerateArray())
                        {
                            var vuln = ParseVulnerabilityFromGraphQL(node, packageId);
                            if (vuln is not null)
                                vulns.Add(vuln);
                        }
                    }

                    results[packageId] = vulns;
                }
            }
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Error fetching vulnerabilities batch: {ex.Message}");
            foreach (var pkg in packages)
                results.TryAdd(pkg, []);
        }
        finally
        {
            _requestLimiter.Release();
        }

        return results;
    }

    private static VulnerabilityInfo? ParseVulnerabilityFromGraphQL(JsonElement node, string packageId)
    {
        if (!node.TryGetProperty("advisory", out var advisory) || advisory.ValueKind == JsonValueKind.Null)
            return null;

        var cves = new List<string>();
        if (advisory.TryGetProperty("identifiers", out var identifiers))
        {
            foreach (var id in identifiers.EnumerateArray())
            {
                if (id.TryGetProperty("type", out var type) &&
                    type.GetString() == "CVE" &&
                    id.TryGetProperty("value", out var value))
                {
                    cves.Add(value.GetString() ?? "");
                }
            }
        }

        string? patchedVersion = null;
        if (node.TryGetProperty("firstPatchedVersion", out var fpv) &&
            fpv.ValueKind != JsonValueKind.Null &&
            fpv.TryGetProperty("identifier", out var pv))
        {
            patchedVersion = pv.GetString();
        }

        return new VulnerabilityInfo
        {
            Id = advisory.TryGetProperty("ghsaId", out var ghsa) ? ghsa.GetString() ?? "" : "",
            Severity = advisory.TryGetProperty("severity", out var sev) ? sev.GetString() ?? "UNKNOWN" : "UNKNOWN",
            Summary = advisory.TryGetProperty("summary", out var sum) ? sum.GetString() ?? "" : "",
            Description = advisory.TryGetProperty("description", out var desc) ? desc.GetString() : null,
            PackageId = packageId,
            VulnerableVersionRange = node.TryGetProperty("vulnerableVersionRange", out var vvr) ? vvr.GetString() ?? "" : "",
            PatchedVersion = patchedVersion,
            Cves = cves,
            Url = advisory.TryGetProperty("permalink", out var pl) ? pl.GetString() : null,
            PublishedAt = advisory.TryGetProperty("publishedAt", out var pa) && pa.ValueKind == JsonValueKind.String
                ? DateTime.TryParse(pa.GetString(), out var dt) ? dt : null
                : null
        };
    }

    /// <summary>
    /// Get vulnerabilities for a single package (uses cache).
    /// </summary>
    public async Task<List<VulnerabilityInfo>> GetVulnerabilitiesAsync(
        string packageId,
        string? version = null,
        CancellationToken ct = default)
    {
        var results = await GetVulnerabilitiesBatchAsync([packageId], ct);
        return results.TryGetValue(packageId, out var vulns) ? vulns : [];
    }

    private void UpdateRateLimitFromResponse(HttpResponseMessage response)
    {
        if (response.Headers.TryGetValues("X-RateLimit-Remaining", out var remaining))
        {
            if (int.TryParse(remaining.FirstOrDefault(), out var rem))
                _remainingRequests = rem;
        }

        if (response.Headers.TryGetValues("X-RateLimit-Reset", out var reset))
        {
            if (long.TryParse(reset.FirstOrDefault(), out var unix))
                _rateLimitReset = DateTimeOffset.FromUnixTimeSeconds(unix).UtcDateTime;
        }

        if (_remainingRequests <= 0)
            _isRateLimited = true;
    }

    private async Task UpdateRateLimitFromOctokitAsync()
    {
        try
        {
            var rateLimit = await _client.RateLimit.GetRateLimits();
            _remainingRequests = rateLimit.Resources.Core.Remaining;
            _rateLimitReset = rateLimit.Resources.Core.Reset.UtcDateTime;
            _isRateLimited = _remainingRequests <= 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[WARN] Failed to check GitHub rate limit: {ex.Message}");
        }
    }

    private static (string? owner, string? repo) ParseGitHubUrl(string url)
    {
        var match = GitHubUrlRegex().Match(url);
        if (match.Success)
        {
            var owner = match.Groups["owner"].Value;
            var repo = match.Groups["repo"].Value;
            if (repo.EndsWith(".git", StringComparison.OrdinalIgnoreCase))
                repo = repo[..^4];
            return (owner, repo);
        }
        return (null, null);
    }

    /// <summary>
    /// Sanitize a string for safe use in GraphQL string literals.
    /// Escapes backslashes and double quotes to prevent injection.
    /// </summary>
    private static string SanitizeGraphQLString(string input)
    {
        return input.Replace("\\", "\\\\").Replace("\"", "\\\"");
    }

    public void Dispose()
    {
        _httpClient.Dispose();
        _requestLimiter.Dispose();
    }

    [GeneratedRegex(@"github\.com[/:](?<owner>[^/]+)/(?<repo>[^/\s?#]+)", RegexOptions.IgnoreCase)]
    private static partial Regex GitHubUrlRegex();
}
