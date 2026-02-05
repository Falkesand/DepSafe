using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;
using DepSafe.Models;

namespace DepSafe.DataSources;

/// <summary>
/// Client for OSV (Open Source Vulnerabilities) API.
/// Free, no authentication required.
/// https://osv.dev/
/// </summary>
public sealed class OsvApiClient : IDisposable
{
    private readonly HttpClient _httpClient;
    private readonly ResponseCache _cache;
    private const string OsvApiUrl = "https://api.osv.dev/v1";
    private const int BatchSize = 1000; // OSV supports up to 1000 queries per batch

    public OsvApiClient(ResponseCache? cache = null)
    {
        _httpClient = new HttpClient
        {
            Timeout = TimeSpan.FromSeconds(30)
        };
        _httpClient.DefaultRequestHeaders.Add("Accept", "application/json");
        _httpClient.DefaultRequestHeaders.Add("User-Agent", "DepSafe");
        _cache = cache ?? new ResponseCache();
    }

    /// <summary>
    /// Query vulnerabilities for a single package.
    /// </summary>
    public async Task<List<VulnerabilityInfo>> QueryAsync(
        string packageName,
        string? version,
        PackageEcosystem ecosystem,
        CancellationToken ct = default)
    {
        var results = await QueryBatchAsync(
            [(packageName, version, ecosystem)],
            ct);

        return results.GetValueOrDefault(packageName, []);
    }

    /// <summary>
    /// Query vulnerabilities for multiple packages in batch.
    /// </summary>
    public async Task<Dictionary<string, List<VulnerabilityInfo>>> QueryBatchAsync(
        IEnumerable<(string Name, string? Version, PackageEcosystem Ecosystem)> packages,
        CancellationToken ct = default)
    {
        var results = new Dictionary<string, List<VulnerabilityInfo>>(StringComparer.OrdinalIgnoreCase);
        var packageList = packages.ToList();

        if (packageList.Count == 0)
            return results;

        // Check cache first, collect packages that need fetching
        var packagesToFetch = new List<(string Name, string? Version, PackageEcosystem Ecosystem)>();
        foreach (var pkg in packageList)
        {
            var cacheKey = $"osv:{pkg.Ecosystem}:{pkg.Name}:{pkg.Version ?? "any"}";
            var cached = await _cache.GetAsync<List<VulnerabilityInfo>>(cacheKey, ct);
            if (cached is not null)
            {
                results[pkg.Name] = cached;
            }
            else
            {
                packagesToFetch.Add(pkg);
            }
        }

        if (packagesToFetch.Count == 0)
            return results;

        // Process uncached packages in batches
        for (int i = 0; i < packagesToFetch.Count; i += BatchSize)
        {
            int take = Math.Min(BatchSize, packagesToFetch.Count - i);
            var batch = packagesToFetch.GetRange(i, take);
            var batchResults = await QueryBatchInternalAsync(batch, ct);

            foreach (var (name, vulns) in batchResults)
            {
                if (!results.ContainsKey(name))
                    results[name] = [];
                results[name].AddRange(vulns);

                // Cache individual results
                var pkg = batch.FirstOrDefault(p => p.Name.Equals(name, StringComparison.OrdinalIgnoreCase));
                if (pkg != default)
                {
                    var cacheKey = $"osv:{pkg.Ecosystem}:{pkg.Name}:{pkg.Version ?? "any"}";
                    await _cache.SetAsync(cacheKey, vulns, TimeSpan.FromHours(6), ct);
                }
            }

            // Also cache empty results for packages with no vulnerabilities
            foreach (var pkg in batch)
            {
                if (!results.ContainsKey(pkg.Name))
                {
                    results[pkg.Name] = [];
                    var cacheKey = $"osv:{pkg.Ecosystem}:{pkg.Name}:{pkg.Version ?? "any"}";
                    await _cache.SetAsync(cacheKey, new List<VulnerabilityInfo>(), TimeSpan.FromHours(6), ct);
                }
            }
        }

        return results;
    }

    /// <summary>
    /// Query vulnerabilities for npm packages.
    /// </summary>
    public async Task<Dictionary<string, List<VulnerabilityInfo>>> QueryNpmPackagesAsync(
        IEnumerable<string> packageNames,
        CancellationToken ct = default)
    {
        var packages = packageNames.Select(name => (name, (string?)null, PackageEcosystem.Npm));
        return await QueryBatchAsync(packages, ct);
    }

    /// <summary>
    /// Query vulnerabilities for NuGet packages.
    /// </summary>
    public async Task<Dictionary<string, List<VulnerabilityInfo>>> QueryNuGetPackagesAsync(
        IEnumerable<string> packageNames,
        CancellationToken ct = default)
    {
        var packages = packageNames.Select(name => (name, (string?)null, PackageEcosystem.NuGet));
        return await QueryBatchAsync(packages, ct);
    }

    private async Task<Dictionary<string, List<VulnerabilityInfo>>> QueryBatchInternalAsync(
        List<(string Name, string? Version, PackageEcosystem Ecosystem)> packages,
        CancellationToken ct)
    {
        var results = new Dictionary<string, List<VulnerabilityInfo>>(StringComparer.OrdinalIgnoreCase);

        try
        {
            // Step 1: Batch query to get vulnerability IDs per package
            var queries = packages.Select(p => new OsvQuery
            {
                Package = new OsvPackage
                {
                    Name = p.Name,
                    Ecosystem = MapEcosystem(p.Ecosystem)
                },
                Version = p.Version
            }).ToList();

            var request = new OsvBatchRequest { Queries = queries };

            var response = await _httpClient.PostAsJsonAsync(
                $"{OsvApiUrl}/querybatch",
                request,
                ct);

            if (!response.IsSuccessStatusCode)
            {
                return results;
            }

            var batchResponse = await response.Content.ReadFromJsonAsync<OsvBatchResponse>(ct);

            if (batchResponse?.Results is null)
                return results;

            // Step 2: Collect all unique vulnerability IDs and map to packages
            var vulnIdToPackages = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);

            for (int i = 0; i < packages.Count && i < batchResponse.Results.Count; i++)
            {
                var packageName = packages[i].Name;
                var vulnIds = batchResponse.Results[i].Vulns?.Select(v => v.Id).Where(id => id is not null) ?? [];

                foreach (var vulnId in vulnIds)
                {
                    if (!vulnIdToPackages.ContainsKey(vulnId!))
                        vulnIdToPackages[vulnId!] = [];
                    vulnIdToPackages[vulnId!].Add(packageName);
                }
            }

            if (vulnIdToPackages.Count == 0)
                return results;

            // Step 3: Fetch full details for each unique vulnerability
            var vulnDetails = await FetchVulnerabilityDetailsAsync(vulnIdToPackages.Keys.ToList(), ct);

            // Step 4: Map vulnerabilities back to packages
            foreach (var (vulnId, affectedPackages) in vulnIdToPackages)
            {
                if (!vulnDetails.TryGetValue(vulnId, out var vuln))
                    continue;

                foreach (var packageName in affectedPackages)
                {
                    if (!results.ContainsKey(packageName))
                        results[packageName] = [];

                    results[packageName].Add(MapToVulnerabilityInfo(vuln, packageName));
                }
            }
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"OSV API error: {ex.Message}");
        }

        return results;
    }

    /// <summary>
    /// Fetch full vulnerability details for a list of vulnerability IDs.
    /// </summary>
    private async Task<Dictionary<string, OsvVulnerability>> FetchVulnerabilityDetailsAsync(
        List<string> vulnIds,
        CancellationToken ct)
    {
        var results = new Dictionary<string, OsvVulnerability>(StringComparer.OrdinalIgnoreCase);

        // Fetch vulnerabilities in parallel (with some concurrency limit)
        var semaphore = new SemaphoreSlim(10); // Max 10 concurrent requests
        var tasks = vulnIds.Select(async vulnId =>
        {
            await semaphore.WaitAsync(ct);
            try
            {
                var response = await _httpClient.GetAsync($"{OsvApiUrl}/vulns/{Uri.EscapeDataString(vulnId)}", ct);
                if (response.IsSuccessStatusCode)
                {
                    var vuln = await response.Content.ReadFromJsonAsync<OsvVulnerability>(ct);
                    if (vuln is not null)
                    {
                        lock (results)
                        {
                            results[vulnId] = vuln;
                        }
                    }
                }
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                // Log but continue - individual vulnerability fetch failures shouldn't stop the batch
                Console.Error.WriteLine($"[WARN] Failed to fetch vulnerability details for {vulnId}: {ex.Message}");
            }
            finally
            {
                semaphore.Release();
            }
        });

        await Task.WhenAll(tasks);
        return results;
    }

    private static string MapEcosystem(PackageEcosystem ecosystem) => ecosystem switch
    {
        PackageEcosystem.Npm => "npm",
        PackageEcosystem.NuGet => "NuGet",
        _ => "npm"
    };

    private static VulnerabilityInfo MapToVulnerabilityInfo(OsvVulnerability vuln, string packageName = "")
    {
        // Determine severity from CVSS or database-specific severity
        var severity = DetermineSeverity(vuln);
        var affectedVersions = ExtractAffectedVersions(vuln);
        var fixedVersions = ExtractFixedVersions(vuln);

        // Build a meaningful description - prefer Summary, fall back to truncated Details
        var summary = vuln.Summary;
        if (string.IsNullOrWhiteSpace(summary) && !string.IsNullOrWhiteSpace(vuln.Details))
        {
            // Use first paragraph of details, truncated if needed
            var details = vuln.Details;
            var firstPara = details.Split('\n')[0];
            summary = firstPara.Length > 300 ? firstPara[..297] + "..." : firstPara;
        }

        // Generate OSV URL for the vulnerability
        var osvUrl = vuln.Id is not null ? $"https://osv.dev/vulnerability/{vuln.Id}" : null;

        return new VulnerabilityInfo
        {
            Id = vuln.Id ?? "UNKNOWN",
            Summary = summary ?? "See vulnerability link for details",
            Description = vuln.Details,
            Severity = severity,
            PackageId = packageName,
            VulnerableVersionRange = affectedVersions.Count > 0 ? string.Join(", ", affectedVersions) : "Unknown",
            PatchedVersion = fixedVersions.Count > 0 ? fixedVersions[0] : null,
            Cves = ExtractCves(vuln),
            Url = osvUrl,  // Link to OSV for consistent vulnerability details
            PublishedAt = ParseDate(vuln.Published)
        };
    }

    private static List<string> ExtractCves(OsvVulnerability vuln)
    {
        var cves = new List<string>();

        // OSV IDs that start with CVE are CVEs
        if (vuln.Id?.StartsWith("CVE-", StringComparison.OrdinalIgnoreCase) == true)
        {
            cves.Add(vuln.Id);
        }

        // Also check aliases if available
        if (vuln.References is not null)
        {
            foreach (var reference in vuln.References)
            {
                if (reference.Url?.Contains("cve.org") == true || reference.Url?.Contains("nvd.nist.gov") == true)
                {
                    // Extract CVE from URL if possible
                    var match = System.Text.RegularExpressions.Regex.Match(
                        reference.Url, @"CVE-\d{4}-\d+", System.Text.RegularExpressions.RegexOptions.IgnoreCase);
                    if (match.Success && !cves.Contains(match.Value, StringComparer.OrdinalIgnoreCase))
                    {
                        cves.Add(match.Value.ToUpperInvariant());
                    }
                }
            }
        }

        return cves;
    }

    private static string DetermineSeverity(OsvVulnerability vuln)
    {
        // Try CVSS first
        if (vuln.Severity is { Count: > 0 })
        {
            var cvss = vuln.Severity.FirstOrDefault();
            if (cvss?.Score is not null)
            {
                // Parse CVSS vector to get base score
                var score = ParseCvssScore(cvss.Score);
                return score switch
                {
                    >= 9.0 => "CRITICAL",
                    >= 7.0 => "HIGH",
                    >= 4.0 => "MEDIUM",
                    >= 0.1 => "LOW",
                    _ => "UNKNOWN"
                };
            }
        }

        // Try database-specific severity
        if (vuln.DatabaseSpecific?.Severity is not null)
        {
            return vuln.DatabaseSpecific.Severity.ToUpperInvariant();
        }

        return "UNKNOWN";
    }

    private static double ParseCvssScore(string cvssVector)
    {
        // CVSS vectors look like: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        // We need to calculate the score from the vector components
        // For simplicity, extract score if provided directly or estimate from severity metrics

        // Some OSV entries have the score directly
        if (double.TryParse(cvssVector, out var directScore))
            return directScore;

        // Simplified CVSS 3.x parsing - look for high impact indicators
        if (cvssVector.Contains("/C:H") || cvssVector.Contains("/I:H") || cvssVector.Contains("/A:H"))
        {
            if (cvssVector.Contains("/S:C")) // Scope changed
                return 9.0;
            return 7.5;
        }

        if (cvssVector.Contains("/C:L") || cvssVector.Contains("/I:L") || cvssVector.Contains("/A:L"))
            return 4.0;

        return 5.0; // Default medium
    }

    private static DateTime? ParseDate(string? dateStr)
    {
        if (string.IsNullOrEmpty(dateStr))
            return null;

        if (DateTime.TryParse(dateStr, out var date))
            return date;

        return null;
    }

    private static List<string> ExtractAffectedVersions(OsvVulnerability vuln)
    {
        var versions = new List<string>();

        if (vuln.Affected is null)
            return versions;

        foreach (var affected in vuln.Affected)
        {
            if (affected.Ranges is null) continue;

            foreach (var range in affected.Ranges)
            {
                if (range.Events is null) continue;

                string? introduced = null;
                string? fixed_ = null;

                foreach (var evt in range.Events)
                {
                    if (evt.Introduced is not null)
                        introduced = evt.Introduced;
                    if (evt.Fixed is not null)
                        fixed_ = evt.Fixed;
                }

                if (introduced is not null)
                {
                    var versionRange = fixed_ is not null
                        ? $">={introduced}, <{fixed_}"
                        : $">={introduced}";
                    versions.Add(versionRange);
                }
            }

            // Also add specific versions if listed
            if (affected.Versions is not null)
            {
                versions.AddRange(affected.Versions.Take(5)); // Limit to avoid huge lists
            }
        }

        return versions.Distinct().ToList();
    }

    private static List<string> ExtractFixedVersions(OsvVulnerability vuln)
    {
        var versions = new List<string>();

        if (vuln.Affected is null)
            return versions;

        foreach (var affected in vuln.Affected)
        {
            if (affected.Ranges is null) continue;

            foreach (var range in affected.Ranges)
            {
                if (range.Events is null) continue;

                foreach (var evt in range.Events)
                {
                    if (evt.Fixed is not null)
                        versions.Add(evt.Fixed);
                }
            }
        }

        return versions.Distinct().ToList();
    }

    public void Dispose()
    {
        _httpClient.Dispose();
    }

    // OSV API request/response models
    private sealed class OsvBatchRequest
    {
        [JsonPropertyName("queries")]
        public required List<OsvQuery> Queries { get; init; }
    }

    private sealed class OsvQuery
    {
        [JsonPropertyName("package")]
        public required OsvPackage Package { get; init; }

        [JsonPropertyName("version")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string? Version { get; init; }
    }

    private sealed class OsvPackage
    {
        [JsonPropertyName("name")]
        public required string Name { get; init; }

        [JsonPropertyName("ecosystem")]
        public required string Ecosystem { get; init; }
    }

    private sealed class OsvBatchResponse
    {
        [JsonPropertyName("results")]
        public List<OsvQueryResult>? Results { get; init; }
    }

    private sealed class OsvQueryResult
    {
        [JsonPropertyName("vulns")]
        public List<OsvVulnerability>? Vulns { get; init; }
    }

    private sealed class OsvVulnerability
    {
        [JsonPropertyName("id")]
        public string? Id { get; init; }

        [JsonPropertyName("summary")]
        public string? Summary { get; init; }

        [JsonPropertyName("details")]
        public string? Details { get; init; }

        [JsonPropertyName("published")]
        public string? Published { get; init; }

        [JsonPropertyName("modified")]
        public string? Modified { get; init; }

        [JsonPropertyName("severity")]
        public List<OsvSeverity>? Severity { get; init; }

        [JsonPropertyName("affected")]
        public List<OsvAffected>? Affected { get; init; }

        [JsonPropertyName("references")]
        public List<OsvReference>? References { get; init; }

        [JsonPropertyName("database_specific")]
        public OsvDatabaseSpecific? DatabaseSpecific { get; init; }
    }

    private sealed class OsvSeverity
    {
        [JsonPropertyName("type")]
        public string? Type { get; init; }

        [JsonPropertyName("score")]
        public string? Score { get; init; }
    }

    private sealed class OsvAffected
    {
        [JsonPropertyName("package")]
        public OsvPackage? Package { get; init; }

        [JsonPropertyName("ranges")]
        public List<OsvRange>? Ranges { get; init; }

        [JsonPropertyName("versions")]
        public List<string>? Versions { get; init; }
    }

    private sealed class OsvRange
    {
        [JsonPropertyName("type")]
        public string? Type { get; init; }

        [JsonPropertyName("events")]
        public List<OsvEvent>? Events { get; init; }
    }

    private sealed class OsvEvent
    {
        [JsonPropertyName("introduced")]
        public string? Introduced { get; init; }

        [JsonPropertyName("fixed")]
        public string? Fixed { get; init; }
    }

    private sealed class OsvReference
    {
        [JsonPropertyName("type")]
        public string? Type { get; init; }

        [JsonPropertyName("url")]
        public string? Url { get; init; }
    }

    private sealed class OsvDatabaseSpecific
    {
        [JsonPropertyName("severity")]
        public string? Severity { get; init; }

        [JsonPropertyName("cwe_ids")]
        public List<string>? CweIds { get; init; }
    }
}
