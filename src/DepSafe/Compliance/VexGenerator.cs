using DepSafe.Models;
using DepSafe.Scoring;

namespace DepSafe.Compliance;

/// <summary>
/// Generates VEX (Vulnerability Exploitability eXchange) documents in OpenVEX format.
/// </summary>
public sealed class VexGenerator
{
    private readonly string _author;

    public VexGenerator(string? author = null)
    {
        _author = author ?? "DepSafe";
    }

    /// <summary>
    /// Generate OpenVEX document from vulnerabilities.
    /// </summary>
    public VexDocument Generate(
        IEnumerable<PackageHealth> packages,
        IReadOnlyDictionary<string, List<VulnerabilityInfo>> vulnerabilities)
    {
        var statements = new List<VexStatement>();

        foreach (var pkg in packages)
        {
            if (!vulnerabilities.TryGetValue(pkg.PackageId, out var vulns) || vulns.Count == 0)
                continue;

            foreach (var vuln in vulns)
            {
                var status = DetermineStatus(vuln, pkg.Version);
                // Generate appropriate URL based on vulnerability ID
                var vulnUrl = vuln.Url ?? GetVulnerabilityUrl(vuln.Id);
                var purl = $"pkg:{(pkg.Ecosystem == PackageEcosystem.Npm ? "npm" : "nuget")}/{pkg.PackageId}@{pkg.Version}";

                var statement = new VexStatement
                {
                    Vulnerability = new VexVulnerability
                    {
                        Id = vulnUrl,
                        Name = vuln.Id,
                        Description = !string.IsNullOrWhiteSpace(vuln.Summary) ? vuln.Summary : vuln.Description,
                        Aliases = vuln.Cves.Count > 0 ? vuln.Cves : null
                    },
                    Products =
                    [
                        new VexProduct
                        {
                            Id = purl,
                            Identifiers = new VexIdentifiers
                            {
                                Purl = purl
                            }
                        }
                    ],
                    Status = status,
                    Justification = status == VexStatus.NotAffected
                        ? DetermineJustification(vuln, pkg.Version)
                        : null,
                    ActionStatement = status == VexStatus.Affected
                        ? GenerateActionStatement(vuln)
                        : null,
                    ImpactStatement = status == VexStatus.Affected
                        ? $"Package version {pkg.Version} is within vulnerable range {vuln.VulnerableVersionRange}"
                        : null,
                    PatchedVersion = vuln.PatchedVersion
                };

                statements.Add(statement);
            }
        }

        return new VexDocument
        {
            Id = $"https://nuget-health.dev/vex/{Guid.NewGuid()}",
            Author = _author,
            Timestamp = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ"),
            Statements = statements
        };
    }

    private static string DetermineStatus(VulnerabilityInfo vuln, string packageVersion)
    {
        var inVulnerableRange = true; // Conservative default
        if (!string.IsNullOrEmpty(vuln.VulnerableVersionRange))
        {
            inVulnerableRange = IsVersionInRange(packageVersion, vuln.VulnerableVersionRange);
        }

        // Check if version is at or above the patched version
        if (!string.IsNullOrEmpty(vuln.PatchedVersion))
        {
            try
            {
                var current = NuGet.Versioning.NuGetVersion.Parse(packageVersion);
                var patched = NuGet.Versioning.NuGetVersion.Parse(vuln.PatchedVersion);

                if (current >= patched)
                {
                    return VexStatus.Fixed;
                }
            }
            catch
            {
                // Version parsing failed, fall through to range-based logic
            }
        }

        if (!inVulnerableRange)
        {
            return VexStatus.NotAffected;
        }

        return VexStatus.Affected;
    }

    private static bool IsVersionInRange(string version, string range) =>
        Scoring.HealthScoreCalculator.IsVersionInVulnerableRange(version, range);

    private static string? DetermineJustification(VulnerabilityInfo vuln, string packageVersion)
    {
        if (!string.IsNullOrEmpty(vuln.PatchedVersion))
        {
            return VexJustification.VulnerableCodeNotPresent;
        }

        return null;
    }

    private static string GenerateActionStatement(VulnerabilityInfo vuln)
    {
        if (!string.IsNullOrEmpty(vuln.PatchedVersion))
        {
            return $"Upgrade to version {vuln.PatchedVersion} or later to remediate this vulnerability.";
        }

        return "Review the vulnerability and consider alternative packages or mitigation strategies.";
    }

    private static string GetVulnerabilityUrl(string vulnId)
    {
        // Generate URL based on vulnerability ID format
        if (vulnId.StartsWith("GHSA-", StringComparison.OrdinalIgnoreCase))
        {
            // GitHub Security Advisory - use OSV which aggregates these
            return $"https://osv.dev/vulnerability/{vulnId}";
        }
        if (vulnId.StartsWith("CVE-", StringComparison.OrdinalIgnoreCase))
        {
            // CVE - link to NVD
            return $"https://nvd.nist.gov/vuln/detail/{vulnId}";
        }
        if (vulnId.StartsWith("PYSEC-", StringComparison.OrdinalIgnoreCase) ||
            vulnId.StartsWith("GO-", StringComparison.OrdinalIgnoreCase) ||
            vulnId.StartsWith("RUSTSEC-", StringComparison.OrdinalIgnoreCase))
        {
            // Other OSV ecosystems
            return $"https://osv.dev/vulnerability/{vulnId}";
        }

        // Default to OSV for unknown formats
        return $"https://osv.dev/vulnerability/{vulnId}";
    }
}
