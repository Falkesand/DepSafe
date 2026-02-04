using DepSafe.Models;

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
        // FIRST check vulnerable version range
        if (!string.IsNullOrEmpty(vuln.VulnerableVersionRange))
        {
            if (!IsVersionInRange(packageVersion, vuln.VulnerableVersionRange))
            {
                return VexStatus.NotAffected; // Not in vulnerable range
            }
        }
        // If no range specified, conservatively assume in range

        // THEN check if version is patched (only matters if we're in the vulnerable range)
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
                // Version parsing failed, assume still affected
            }
        }

        // Version is in vulnerable range and not patched
        return VexStatus.Affected;
    }

    private static bool IsVersionInRange(string version, string range)
    {
        // Parse common vulnerability range formats like "< 4.5.0", ">= 2.0, < 3.0"
        try
        {
            var current = NuGet.Versioning.NuGetVersion.Parse(version);

            // Split on comma for compound ranges
            var parts = range.Split(',').Select(p => p.Trim()).ToArray();

            // Track whether we have any range constraints vs just exact versions
            bool hasRangeConstraint = false;
            bool hasExactMatch = false;

            foreach (var part in parts)
            {
                if (part.StartsWith(">="))
                {
                    hasRangeConstraint = true;
                    var v = NuGet.Versioning.NuGetVersion.Parse(part[2..].Trim());
                    if (current < v) return false;
                }
                else if (part.StartsWith('>'))
                {
                    hasRangeConstraint = true;
                    var v = NuGet.Versioning.NuGetVersion.Parse(part[1..].Trim());
                    if (current <= v) return false;
                }
                else if (part.StartsWith("<="))
                {
                    hasRangeConstraint = true;
                    var v = NuGet.Versioning.NuGetVersion.Parse(part[2..].Trim());
                    if (current > v) return false;
                }
                else if (part.StartsWith('<'))
                {
                    hasRangeConstraint = true;
                    var v = NuGet.Versioning.NuGetVersion.Parse(part[1..].Trim());
                    if (current >= v) return false;
                }
                else if (part.StartsWith('='))
                {
                    hasRangeConstraint = true;
                    var v = NuGet.Versioning.NuGetVersion.Parse(part[1..].Trim());
                    if (current != v) return false;
                }
                else if (!string.IsNullOrWhiteSpace(part))
                {
                    // Exact version match (e.g., "4.4.2" from OSV's versions list)
                    try
                    {
                        var v = NuGet.Versioning.NuGetVersion.Parse(part);
                        if (current == v)
                        {
                            hasExactMatch = true;
                        }
                    }
                    catch
                    {
                        // Not a parseable version, ignore
                    }
                }
            }

            // If we only have exact version matches, return true only if current matches
            if (!hasRangeConstraint)
            {
                return hasExactMatch;
            }

            // Range constraints all passed
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
