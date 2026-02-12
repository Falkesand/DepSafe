using DepSafe.Compliance;
using DepSafe.Models;

namespace DepSafe.Tests;

public class PolicyEvaluatorTests
{
    private static CraReport CreateReport(
        int criticalVulnerabilityCount = 0,
        int? maxInactiveMonths = null,
        int vulnerabilityCount = 0,
        int craReadinessScore = 85,
        int reportableVulnerabilityCount = 0,
        int? maxUnpatchedVulnerabilityDays = null,
        bool hasUnmaintainedPackages = false,
        int? sbomCompletenessPercentage = 100,
        int? maxDependencyDepth = 3,
        int? minPackageHealthScore = 75,
        string? minHealthScorePackage = null,
        CraComplianceStatus overallComplianceStatus = CraComplianceStatus.Compliant,
        List<CraComplianceItem>? complianceItems = null,
        List<string>? deprecatedPackages = null) => new()
    {
        GeneratedAt = DateTime.UtcNow,
        ProjectPath = "/test/project",
        HealthScore = 80,
        HealthStatus = HealthStatus.Healthy,
        ComplianceItems = complianceItems ?? [],
        OverallComplianceStatus = overallComplianceStatus,
        Sbom = new SbomDocument
        {
            SpdxId = "SPDXRef-DOCUMENT",
            Name = "test",
            DocumentNamespace = "https://test",
            CreationInfo = new SbomCreationInfo { Created = "2024-01-01", Creators = ["Tool: test"] },
            Packages = [],
            Relationships = [],
        },
        Vex = new VexDocument { Id = "test", Author = "test", Timestamp = "2024-01-01T00:00:00Z", Statements = [] },
        PackageCount = 5,
        TransitivePackageCount = 10,
        VulnerabilityCount = vulnerabilityCount,
        CriticalPackageCount = 0,
        CraReadinessScore = craReadinessScore,
        CriticalVulnerabilityCount = criticalVulnerabilityCount,
        MaxInactiveMonths = maxInactiveMonths,
        MaxUnpatchedVulnerabilityDays = maxUnpatchedVulnerabilityDays,
        SbomCompletenessPercentage = sbomCompletenessPercentage,
        MaxDependencyDepth = maxDependencyDepth,
        HasUnmaintainedPackages = hasUnmaintainedPackages,
        ReportableVulnerabilityCount = reportableVulnerabilityCount,
        DeprecatedPackages = deprecatedPackages ?? [],
        MinPackageHealthScore = minPackageHealthScore,
        MinHealthScorePackage = minHealthScorePackage,
    };

    private static PackageHealth CreatePackage(
        string id = "TestPkg",
        int score = 75,
        int? contributorCount = null,
        string? license = "MIT") => new()
    {
        PackageId = id,
        Version = "1.0.0",
        Score = score,
        Status = score >= 80 ? HealthStatus.Healthy
            : score >= 60 ? HealthStatus.Watch
            : score >= 40 ? HealthStatus.Warning
            : HealthStatus.Critical,
        Metrics = new PackageMetrics { TotalDownloads = 1000 },
        License = license,
        MaintainerTrust = contributorCount.HasValue
            ? new MaintainerTrust(
                Score: 50,
                Tier: MaintainerTrustTier.Moderate,
                ContributorCount: contributorCount.Value,
                TotalCommits: 100,
                TotalReleases: 10,
                ReleaseAuthorCount: 1,
                TopReleaseAuthor: "author")
            : null,
    };

    [Fact]
    public void NoCriticalVulnerabilities_WithCritical_ReturnsViolation()
    {
        var config = new CraConfig { NoCriticalVulnerabilities = true };
        var report = CreateReport(criticalVulnerabilityCount: 2);

        var result = PolicyEvaluator.Evaluate(report, config);

        var violation = Assert.Single(result.Violations);
        Assert.Equal("NoCriticalVulnerabilities", violation.Rule);
        Assert.Equal("Art. 10(6)", violation.CraArticle);
        Assert.Equal(PolicySeverity.Block, violation.Severity);
        Assert.Equal(2, result.ExitCode);
    }

    [Fact]
    public void NoCriticalVulnerabilities_NoCritical_NoViolation()
    {
        var config = new CraConfig { NoCriticalVulnerabilities = true };
        var report = CreateReport(criticalVulnerabilityCount: 0);

        var result = PolicyEvaluator.Evaluate(report, config);

        Assert.Empty(result.Violations);
    }

    [Fact]
    public void MinPackageMaintainers_BelowThreshold_ReturnsViolation()
    {
        var config = new CraConfig { MinPackageMaintainers = 2 };
        var report = CreateReport();
        var packages = new List<PackageHealth>
        {
            CreatePackage(id: "SmallPkg", contributorCount: 1),
        };

        var result = PolicyEvaluator.Evaluate(report, config, packages);

        var violation = Assert.Single(result.Violations);
        Assert.Equal("MinPackageMaintainers", violation.Rule);
        Assert.Equal("Art. 13(5)", violation.CraArticle);
    }

    [Fact]
    public void MinPackageMaintainers_MeetsThreshold_NoViolation()
    {
        var config = new CraConfig { MinPackageMaintainers = 2 };
        var report = CreateReport();
        var packages = new List<PackageHealth>
        {
            CreatePackage(id: "BigPkg", contributorCount: 3),
            CreatePackage(id: "BigPkg2", contributorCount: 5),
        };

        var result = PolicyEvaluator.Evaluate(report, config, packages);

        Assert.DoesNotContain(result.Violations, v => v.Rule == "MinPackageMaintainers");
    }

    [Fact]
    public void BlockUnmaintainedMonths_ExceedsThreshold_ReturnsViolation()
    {
        var config = new CraConfig { BlockUnmaintainedMonths = 12 };
        var report = CreateReport(maxInactiveMonths: 18);

        var result = PolicyEvaluator.Evaluate(report, config);

        var violation = Assert.Single(result.Violations);
        Assert.Equal("BlockUnmaintainedMonths", violation.Rule);
    }

    [Fact]
    public void BlockUnmaintainedMonths_TakesPrecedenceOverBool()
    {
        var config = new CraConfig
        {
            BlockUnmaintainedMonths = 6,
            FailOnUnmaintainedPackages = true,
        };
        var report = CreateReport(maxInactiveMonths: 10, hasUnmaintainedPackages: false);

        var result = PolicyEvaluator.Evaluate(report, config);

        // BlockUnmaintainedMonths fires (10 > 6), but FailOnUnmaintainedPackages does not
        // because BlockUnmaintainedMonths takes precedence via else-if
        Assert.Single(result.Violations);
        Assert.Equal("BlockUnmaintainedMonths", result.Violations[0].Rule);
    }

    [Fact]
    public void ExistingFailOnRules_StillWork()
    {
        var config = new CraConfig
        {
            FailOnKev = true,
            FailOnVulnerabilityCount = 0,
            FailOnCraReadinessBelow = 80,
        };
        var kevItem = new CraComplianceItem
        {
            Requirement = "CRA Art. 10(6) - CISA KEV",
            Description = "Check for CISA KEV vulnerabilities",
            Status = CraComplianceStatus.NonCompliant,
            Evidence = "1 KEV vulnerability found",
        };
        var report = CreateReport(
            vulnerabilityCount: 3,
            craReadinessScore: 65,
            complianceItems: [kevItem]);

        var result = PolicyEvaluator.Evaluate(report, config);

        Assert.Equal(3, result.Violations.Count);
        Assert.Contains(result.Violations, v => v.Rule == "FailOnKev");
        Assert.Contains(result.Violations, v => v.Rule == "FailOnVulnerabilityCount");
        Assert.Contains(result.Violations, v => v.Rule == "FailOnCraReadinessBelow");
        Assert.Equal(2, result.ExitCode);
    }

    [Fact]
    public void ComplianceNotes_AttachedToViolation()
    {
        var config = new CraConfig
        {
            MinHealthScore = 60,
            ComplianceNotes = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["WeakPkg"] = "Accepted risk: internal use only",
            },
        };
        var report = CreateReport(minPackageHealthScore: 40, minHealthScorePackage: "WeakPkg");

        var result = PolicyEvaluator.Evaluate(report, config);

        var violation = Assert.Single(result.Violations);
        Assert.Equal("MinHealthScore", violation.Rule);
        Assert.Equal("Accepted risk: internal use only", violation.Justification);
    }

    [Fact]
    public void LicenseViolations_IncludedInResult()
    {
        var config = new CraConfig
        {
            AllowedLicenses = ["MIT", "Apache-2.0"],
        };
        var report = CreateReport();
        var packages = new List<PackageHealth>
        {
            CreatePackage(id: "GplPkg", license: "GPL-3.0"),
        };

        var result = PolicyEvaluator.Evaluate(report, config, packages);

        var violation = Assert.Single(result.Violations);
        Assert.Equal("LicensePolicy", violation.Rule);
        Assert.Equal("Art. 13(6)", violation.CraArticle);
    }

    [Fact]
    public void NoConfig_ReturnsEmpty()
    {
        var report = CreateReport();

        var result = PolicyEvaluator.Evaluate(report, null);

        Assert.Empty(result.Violations);
        Assert.Equal(0, result.ExitCode);
    }

    [Fact]
    public void MultipleViolations_AllCollected()
    {
        var config = new CraConfig
        {
            NoCriticalVulnerabilities = true,
            FailOnDeprecatedPackages = true,
        };
        var report = CreateReport(
            criticalVulnerabilityCount: 1,
            deprecatedPackages: ["OldPkg"]);

        var result = PolicyEvaluator.Evaluate(report, config);

        Assert.Equal(2, result.Violations.Count);
        Assert.Contains(result.Violations, v => v.Rule == "NoCriticalVulnerabilities");
        Assert.Contains(result.Violations, v => v.Rule == "FailOnDeprecatedPackages");
    }

    [Fact]
    public void Remediation_IncludesPackageDetails()
    {
        var config = new CraConfig { MinPackageMaintainers = 3 };
        var report = CreateReport();
        var packages = new List<PackageHealth>
        {
            CreatePackage(id: "TinyLib", contributorCount: 1),
        };

        var result = PolicyEvaluator.Evaluate(report, config, packages);

        var violation = Assert.Single(result.Violations);
        Assert.Contains("TinyLib", violation.Remediation);
    }

    [Fact]
    public void ExcludePackages_RemovedBeforeScoring()
    {
        var packages = new List<PackageHealth>
        {
            CreatePackage("KeepMe"),
            CreatePackage("DropMe"),
            CreatePackage("AlsoKeep")
        };
        var excludeList = new List<string> { "DropMe" };

        var filtered = PolicyEvaluator.FilterExcludedPackages(packages, excludeList);

        Assert.Equal(2, filtered.Count);
        Assert.DoesNotContain(filtered, p => p.PackageId == "DropMe");
    }

    [Fact]
    public void ExcludePackages_CaseInsensitive()
    {
        var packages = new List<PackageHealth>
        {
            CreatePackage("Newtonsoft.Json")
        };
        var excludeList = new List<string> { "newtonsoft.json" };

        var filtered = PolicyEvaluator.FilterExcludedPackages(packages, excludeList);

        Assert.Empty(filtered);
    }

    [Fact]
    public void ExcludePackages_EmptyList_NoEffect()
    {
        var packages = new List<PackageHealth>
        {
            CreatePackage("PkgA"),
            CreatePackage("PkgB")
        };

        var filtered = PolicyEvaluator.FilterExcludedPackages(packages, []);

        Assert.Equal(2, filtered.Count);
    }

    [Fact]
    public void PolicyEvaluation_EndToEnd()
    {
        var config = new CraConfig
        {
            NoCriticalVulnerabilities = true,
            MinPackageMaintainers = 2,
            FailOnDeprecatedPackages = true,
            MinHealthScore = 50,
            AllowedLicenses = ["MIT", "Apache-2.0"],
            ComplianceNotes = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["OldPkg"] = "Planned for removal in v2.0"
            }
        };
        var report = CreateReport(
            criticalVulnerabilityCount: 1,
            deprecatedPackages: ["OldPkg"],
            minPackageHealthScore: 40,
            minHealthScorePackage: "WeakPkg");
        var packages = new List<PackageHealth>
        {
            CreatePackage("GoodPkg", contributorCount: 5, license: "MIT"),
            CreatePackage("SoloPkg", contributorCount: 1, license: "MIT"),
            CreatePackage("GplPkg", contributorCount: 3, license: "GPL-3.0")
        };

        var result = PolicyEvaluator.Evaluate(report, config, packages);

        // Should have: NoCriticalVulnerabilities, MinPackageMaintainers (SoloPkg),
        // FailOnDeprecatedPackages (OldPkg), MinHealthScore (WeakPkg), LicensePolicy (GplPkg)
        Assert.Equal(5, result.Violations.Count);
        Assert.Equal(2, result.ExitCode);

        // All violations should have CRA article references
        Assert.All(result.Violations, v => Assert.NotNull(v.CraArticle));

        // OldPkg should have justification from ComplianceNotes
        var deprecatedViolation = result.Violations.First(v => v.Rule == "FailOnDeprecatedPackages");
        Assert.Equal("Planned for removal in v2.0", deprecatedViolation.Justification);
    }
}
