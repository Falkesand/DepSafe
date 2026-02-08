using DepSafe.DataSources;
using DepSafe.Models;

namespace DepSafe.Tests;

public class OsvApiClientTests
{
    [Fact]
    public void MapEcosystem_NuGet_ReturnsNuGetString()
    {
        var result = OsvApiClient.MapEcosystem(PackageEcosystem.NuGet);

        Assert.Equal("NuGet", result);
    }

    [Fact]
    public void MapEcosystem_Npm_ReturnsNpmString()
    {
        var result = OsvApiClient.MapEcosystem(PackageEcosystem.Npm);

        Assert.Equal("npm", result);
    }

    [Fact]
    public void MapEcosystem_UnknownValue_ReturnsDefault()
    {
        var result = OsvApiClient.MapEcosystem((PackageEcosystem)999);

        Assert.Equal("npm", result);
    }

    [Fact]
    public void ParseCvssScore_NumericString_ReturnsParsedValue()
    {
        // Use whole number to avoid locale-dependent decimal separator issues
        var result = OsvApiClient.ParseCvssScore("8");

        Assert.Equal(8.0, result);
    }

    [Fact]
    public void ParseCvssScore_VectorWithScopeChange_Returns9()
    {
        var result = OsvApiClient.ParseCvssScore("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");

        Assert.Equal(9.0, result);
    }

    [Fact]
    public void ParseCvssScore_VectorHighImpactNoScope_Returns7_5()
    {
        var result = OsvApiClient.ParseCvssScore("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

        Assert.Equal(7.5, result);
    }

    [Fact]
    public void ParseCvssScore_VectorLowImpact_Returns4()
    {
        var result = OsvApiClient.ParseCvssScore("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");

        Assert.Equal(4.0, result);
    }

    [Fact]
    public void ParseCvssScore_DefaultVector_Returns5()
    {
        var result = OsvApiClient.ParseCvssScore("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N");

        Assert.Equal(5.0, result);
    }

    [Fact]
    public void DetermineSeverity_CriticalScore_ReturnsCritical()
    {
        var vuln = new OsvApiClient.OsvVulnerability
        {
            Severity =
            [
                new OsvApiClient.OsvSeverity { Score = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H" }
            ]
        };

        var result = OsvApiClient.DetermineSeverity(vuln);

        Assert.Equal("CRITICAL", result);
    }

    [Fact]
    public void DetermineSeverity_HighScore_ReturnsHigh()
    {
        var vuln = new OsvApiClient.OsvVulnerability
        {
            Severity =
            [
                new OsvApiClient.OsvSeverity { Score = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" }
            ]
        };

        var result = OsvApiClient.DetermineSeverity(vuln);

        Assert.Equal("HIGH", result);
    }

    [Fact]
    public void DetermineSeverity_MediumScore_ReturnsMedium()
    {
        var vuln = new OsvApiClient.OsvVulnerability
        {
            Severity =
            [
                new OsvApiClient.OsvSeverity { Score = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" }
            ]
        };

        var result = OsvApiClient.DetermineSeverity(vuln);

        Assert.Equal("MEDIUM", result);
    }

    [Fact]
    public void DetermineSeverity_LowScore_ReturnsLow()
    {
        // Use whole number to avoid locale-dependent decimal separator issues
        var vuln = new OsvApiClient.OsvVulnerability
        {
            Severity =
            [
                new OsvApiClient.OsvSeverity { Score = "3" }
            ]
        };

        var result = OsvApiClient.DetermineSeverity(vuln);

        Assert.Equal("LOW", result);
    }

    [Fact]
    public void DetermineSeverity_DatabaseSpecificFallback_ReturnsValue()
    {
        var vuln = new OsvApiClient.OsvVulnerability
        {
            DatabaseSpecific = new OsvApiClient.OsvDatabaseSpecific { Severity = "high" }
        };

        var result = OsvApiClient.DetermineSeverity(vuln);

        Assert.Equal("HIGH", result);
    }

    [Fact]
    public void DetermineSeverity_NoSeverity_ReturnsUnknown()
    {
        var vuln = new OsvApiClient.OsvVulnerability();

        var result = OsvApiClient.DetermineSeverity(vuln);

        Assert.Equal("UNKNOWN", result);
    }

    [Fact]
    public void ParseDate_ValidIsoDate_ReturnsDateTime()
    {
        var result = OsvApiClient.ParseDate("2024-03-15T10:30:00Z");

        Assert.NotNull(result);
        Assert.Equal(2024, result.Value.Year);
        Assert.Equal(3, result.Value.Month);
        Assert.Equal(15, result.Value.Day);
    }

    [Fact]
    public void ParseDate_InvalidString_ReturnsNull()
    {
        var result = OsvApiClient.ParseDate("not-a-date");

        Assert.Null(result);
    }

    [Fact]
    public void ParseDate_Null_ReturnsNull()
    {
        var result = OsvApiClient.ParseDate(null);

        Assert.Null(result);
    }

    [Fact]
    public void ExtractCves_CveInId_IncludesIt()
    {
        var vuln = new OsvApiClient.OsvVulnerability
        {
            Id = "CVE-2024-1234"
        };

        var result = OsvApiClient.ExtractCves(vuln);

        Assert.Single(result);
        Assert.Contains("CVE-2024-1234", result);
    }

    [Fact]
    public void ExtractCves_CveInReference_ExtractsIt()
    {
        var vuln = new OsvApiClient.OsvVulnerability
        {
            Id = "GHSA-xxxx-yyyy-zzzz",
            References =
            [
                new OsvApiClient.OsvReference
                {
                    Url = "https://nvd.nist.gov/vuln/detail/CVE-2024-5678"
                }
            ]
        };

        var result = OsvApiClient.ExtractCves(vuln);

        Assert.Single(result);
        Assert.Contains("CVE-2024-5678", result);
    }

    [Fact]
    public void ExtractCves_NoCves_ReturnsEmpty()
    {
        var vuln = new OsvApiClient.OsvVulnerability
        {
            Id = "GHSA-xxxx-yyyy-zzzz"
        };

        var result = OsvApiClient.ExtractCves(vuln);

        Assert.Empty(result);
    }

    [Fact]
    public void ExtractAffectedVersions_IntroducedAndFixed_ReturnsRange()
    {
        var vuln = new OsvApiClient.OsvVulnerability
        {
            Affected =
            [
                new OsvApiClient.OsvAffected
                {
                    Ranges =
                    [
                        new OsvApiClient.OsvRange
                        {
                            Events =
                            [
                                new OsvApiClient.OsvEvent { Introduced = "1.0.0" },
                                new OsvApiClient.OsvEvent { Fixed = "1.2.3" }
                            ]
                        }
                    ]
                }
            ]
        };

        var result = OsvApiClient.ExtractAffectedVersions(vuln);

        Assert.Single(result);
        Assert.Contains(">=1.0.0, <1.2.3", result);
    }

    [Fact]
    public void ExtractAffectedVersions_NullAffected_ReturnsEmpty()
    {
        var vuln = new OsvApiClient.OsvVulnerability
        {
            Affected = null
        };

        var result = OsvApiClient.ExtractAffectedVersions(vuln);

        Assert.Empty(result);
    }

    [Fact]
    public void ExtractFixedVersions_WithFixedEvent_ReturnsList()
    {
        var vuln = new OsvApiClient.OsvVulnerability
        {
            Affected =
            [
                new OsvApiClient.OsvAffected
                {
                    Ranges =
                    [
                        new OsvApiClient.OsvRange
                        {
                            Events =
                            [
                                new OsvApiClient.OsvEvent { Introduced = "0.5.0" },
                                new OsvApiClient.OsvEvent { Fixed = "2.0.1" }
                            ]
                        }
                    ]
                }
            ]
        };

        var result = OsvApiClient.ExtractFixedVersions(vuln);

        Assert.Single(result);
        Assert.Contains("2.0.1", result);
    }

    [Fact]
    public void ExtractFixedVersions_NoFixedEvents_ReturnsEmpty()
    {
        var vuln = new OsvApiClient.OsvVulnerability
        {
            Affected =
            [
                new OsvApiClient.OsvAffected
                {
                    Ranges =
                    [
                        new OsvApiClient.OsvRange
                        {
                            Events =
                            [
                                new OsvApiClient.OsvEvent { Introduced = "1.0.0" }
                            ]
                        }
                    ]
                }
            ]
        };

        var result = OsvApiClient.ExtractFixedVersions(vuln);

        Assert.Empty(result);
    }

    [Fact]
    public void MapToVulnerabilityInfo_CompleteVuln_MapsAllFields()
    {
        var vuln = new OsvApiClient.OsvVulnerability
        {
            Id = "GHSA-abcd-efgh-ijkl",
            Summary = "Remote code execution in example package",
            Details = "A detailed description of the vulnerability.",
            Published = "2024-06-01T12:00:00Z",
            Severity =
            [
                new OsvApiClient.OsvSeverity { Score = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H" }
            ],
            Affected =
            [
                new OsvApiClient.OsvAffected
                {
                    Ranges =
                    [
                        new OsvApiClient.OsvRange
                        {
                            Events =
                            [
                                new OsvApiClient.OsvEvent { Introduced = "1.0.0" },
                                new OsvApiClient.OsvEvent { Fixed = "1.5.0" }
                            ]
                        }
                    ]
                }
            ],
            References =
            [
                new OsvApiClient.OsvReference
                {
                    Url = "https://nvd.nist.gov/vuln/detail/CVE-2024-9999"
                }
            ]
        };

        var result = OsvApiClient.MapToVulnerabilityInfo(vuln, "ExamplePackage");

        Assert.Equal("GHSA-abcd-efgh-ijkl", result.Id);
        Assert.Equal("Remote code execution in example package", result.Summary);
        Assert.Equal("A detailed description of the vulnerability.", result.Description);
        Assert.Equal("CRITICAL", result.Severity);
        Assert.Equal("ExamplePackage", result.PackageId);
        Assert.Contains(">=1.0.0, <1.5.0", result.VulnerableVersionRange);
        Assert.Equal("1.5.0", result.PatchedVersion);
        Assert.Contains("CVE-2024-9999", result.Cves);
        Assert.Equal("https://osv.dev/vulnerability/GHSA-abcd-efgh-ijkl", result.Url);
        Assert.NotNull(result.PublishedAt);
        Assert.Equal(2024, result.PublishedAt.Value.Year);
        Assert.Equal(6, result.PublishedAt.Value.Month);
        Assert.Equal(1, result.PublishedAt.Value.Day);
    }
}
