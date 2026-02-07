using System.Text.Json;
using DepSafe.Models;

namespace DepSafe.Compliance;

public sealed partial class CraReportGenerator
{
    private List<(string PackageId, string? License)> GetPackageLicenses()
    {
        if (_packageLicensesCache is not null)
            return _packageLicensesCache;

        _packageLicensesCache = new List<(string PackageId, string? License)>();
        if (_healthDataCache is not null)
        {
            foreach (var pkg in _healthDataCache)
                _packageLicensesCache.Add((pkg.PackageId, pkg.License));
        }
        if (_transitiveDataCache is not null)
        {
            foreach (var pkg in _transitiveDataCache)
                _packageLicensesCache.Add((pkg.PackageId, pkg.License));
        }
        return _packageLicensesCache;
    }

    private string GeneratePackageDataJson()
    {
        var packages = new Dictionary<string, object>(StringComparer.OrdinalIgnoreCase);

        // Add direct packages
        if (_healthDataCache is not null)
        {
            foreach (var pkg in _healthDataCache)
            {
                packages[pkg.PackageId] = CreatePackageDataObject(pkg, isDirect: true);
            }
        }

        // Add transitive and sub-dependency packages
        if (_transitiveDataCache is not null)
        {
            foreach (var pkg in _transitiveDataCache)
            {
                if (!packages.ContainsKey(pkg.PackageId))
                {
                    packages[pkg.PackageId] = CreatePackageDataObject(pkg, isDirect: false);
                }
            }
        }

        return JsonSerializer.Serialize(packages);
    }

    private string GenerateSbomMissingDataJson()
    {
        if (_sbomValidation is null)
            return "null";

        var data = new Dictionary<string, List<string>>
        {
            ["supplier"] = _sbomValidation.MissingSupplier,
            ["license"] = _sbomValidation.MissingLicense,
            ["purl"] = _sbomValidation.MissingPurl,
            ["checksum"] = _sbomValidation.MissingChecksum
        };

        return JsonSerializer.Serialize(data);
    }

    private object CreatePackageDataObject(PackageHealth pkg, bool isDirect)
    {
        var ecosystem = pkg.Ecosystem == PackageEcosystem.Npm ? "npm" : "nuget";
        var registryUrl = ecosystem == "npm"
            ? $"https://www.npmjs.com/package/{Uri.EscapeDataString(pkg.PackageId)}/v/{Uri.EscapeDataString(pkg.Version)}"
            : $"https://www.nuget.org/packages/{pkg.PackageId}/{pkg.Version}";

        var hasData = pkg.Metrics.TotalDownloads > 0 ||
                      pkg.Metrics.DaysSinceLastRelease.HasValue ||
                      pkg.Metrics.ReleasesPerYear > 0;

        _parentLookup.TryGetValue(pkg.PackageId, out var parents);

        return new
        {
            name = pkg.PackageId,
            version = pkg.Version,
            score = pkg.Score,
            status = StatusToLower(pkg.Status),
            ecosystem,
            isDirect,
            hasData,
            license = pkg.License,
            daysSinceLastRelease = pkg.Metrics.DaysSinceLastRelease,
            releasesPerYear = pkg.Metrics.ReleasesPerYear,
            downloads = pkg.Metrics.TotalDownloads,
            stars = pkg.Metrics.Stars,
            daysSinceLastCommit = pkg.Metrics.DaysSinceLastCommit,
            downloadTrend = pkg.Metrics.DownloadTrend,
            openIssues = pkg.Metrics.OpenIssues ?? 0,
            repoUrl = pkg.RepositoryUrl,
            registryUrl,
            recommendations = pkg.Recommendations,
            vulnCount = pkg.Vulnerabilities.Count,
            dependencies = pkg.Dependencies.Select(d => new { id = d.PackageId, range = d.VersionRange }).ToList(),
            parents = parents ?? [],
            latestVersion = pkg.LatestVersion,
            peerDependencies = pkg.PeerDependencies.Select(p => new { id = p.Key, range = p.Value }).ToList(),
            craScore = pkg.CraScore,
            craStatus = pkg.CraStatus.ToString(),
            hasKev = pkg.HasKevVulnerability,
            maxEpss = pkg.MaxEpssProbability,
            patchPendingCount = pkg.PatchAvailableNotAppliedCount,
            oldestUnpatchedDays = pkg.OldestUnpatchedVulnDays,
            hasIntegrity = !string.IsNullOrEmpty(pkg.ContentIntegrity),
            authorCount = pkg.Authors.Count
        };
    }
}
