using NuGetHealthAnalyzer.Models;

namespace NuGetHealthAnalyzer.Compliance;

/// <summary>
/// Generates VEX (Vulnerability Exploitability eXchange) documents in OpenVEX format.
/// </summary>
public sealed class VexGenerator
{
    private readonly string _author;

    public VexGenerator(string? author = null)
    {
        _author = author ?? "NuGetHealthAnalyzer";
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
                var statement = new VexStatement
                {
                    Vulnerability = new VexVulnerability
                    {
                        Id = vuln.Url ?? $"https://github.com/advisories/{vuln.Id}",
                        Name = vuln.Id,
                        Description = vuln.Summary,
                        Aliases = vuln.Cves.Count > 0 ? vuln.Cves : null
                    },
                    Products =
                    [
                        new VexProduct
                        {
                            Id = $"pkg:nuget/{pkg.PackageId}@{pkg.Version}",
                            Identifiers = new VexIdentifiers
                            {
                                Purl = $"pkg:nuget/{pkg.PackageId}@{pkg.Version}"
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
                        : null
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
        // Check if package version is patched
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
                // Version parsing failed, assume affected
            }
        }

        // Check vulnerable version range
        if (!string.IsNullOrEmpty(vuln.VulnerableVersionRange))
        {
            if (IsVersionInRange(packageVersion, vuln.VulnerableVersionRange))
            {
                return VexStatus.Affected;
            }
            return VexStatus.NotAffected;
        }

        return VexStatus.UnderInvestigation;
    }

    private static bool IsVersionInRange(string version, string range)
    {
        // Parse common vulnerability range formats like "< 4.5.0", ">= 2.0, < 3.0"
        try
        {
            var current = NuGet.Versioning.NuGetVersion.Parse(version);

            // Split on comma for compound ranges
            var parts = range.Split(',').Select(p => p.Trim()).ToArray();

            foreach (var part in parts)
            {
                if (part.StartsWith(">="))
                {
                    var v = NuGet.Versioning.NuGetVersion.Parse(part[2..].Trim());
                    if (current < v) return false;
                }
                else if (part.StartsWith('>'))
                {
                    var v = NuGet.Versioning.NuGetVersion.Parse(part[1..].Trim());
                    if (current <= v) return false;
                }
                else if (part.StartsWith("<="))
                {
                    var v = NuGet.Versioning.NuGetVersion.Parse(part[2..].Trim());
                    if (current > v) return false;
                }
                else if (part.StartsWith('<'))
                {
                    var v = NuGet.Versioning.NuGetVersion.Parse(part[1..].Trim());
                    if (current >= v) return false;
                }
                else if (part.StartsWith('='))
                {
                    var v = NuGet.Versioning.NuGetVersion.Parse(part[1..].Trim());
                    if (current != v) return false;
                }
            }

            return true;
        }
        catch
        {
            // If we can't parse, assume affected for safety
            return true;
        }
    }

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
}
