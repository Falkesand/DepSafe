using DepSafe.Compliance;
using DepSafe.Models;

namespace DepSafe.Tests;

public class AuditSimulatorTests
{
    private static PackageHealth CreatePackage(
        string id = "TestPkg",
        string version = "1.0.0",
        int score = 80,
        string? license = "MIT",
        bool hasKev = false,
        int patchNotApplied = 0) => new()
    {
        PackageId = id,
        Version = version,
        Score = score,
        Status = score >= 70 ? HealthStatus.Healthy : (score >= 40 ? HealthStatus.Warning : HealthStatus.Critical),
        Metrics = new PackageMetrics { TotalDownloads = 1000 },
        License = license,
        HasKevVulnerability = hasKev,
        PatchAvailableNotAppliedCount = patchNotApplied,
    };

    private static CraReport CreateMinimalCraReport() => new()
    {
        GeneratedAt = DateTime.UtcNow,
        ProjectPath = "/test/project",
        HealthScore = 80,
        HealthStatus = HealthStatus.Healthy,
        ComplianceItems = [],
        OverallComplianceStatus = CraComplianceStatus.Compliant,
        Sbom = new SbomDocument
        {
            SpdxId = "SPDXRef-DOCUMENT",
            Name = "test-sbom",
            DocumentNamespace = "https://test.example.com/sbom",
            CreationInfo = new SbomCreationInfo
            {
                Created = DateTime.UtcNow.ToString("o"),
                Creators = ["Tool: DepSafe"],
            },
            Packages = [],
            Relationships = [],
        },
        Vex = new VexDocument
        {
            Id = "https://test.example.com/vex",
            Author = "DepSafe",
            Timestamp = DateTime.UtcNow.ToString("o"),
            Statements = [],
        },
        PackageCount = 1,
        TransitivePackageCount = 0,
        VulnerabilityCount = 0,
        CriticalPackageCount = 0,
        CraReadinessScore = 80,
    };

    private static SbomValidationResult CreateCleanSbomValidation() => new()
    {
        TotalPackages = 1,
        WithSupplier = 1,
        WithLicense = 1,
        WithPurl = 1,
        WithChecksum = 1,
        HasTimestamp = true,
        HasCreator = true,
    };

    private static AttackSurfaceResult CreateCleanAttackSurface() => new()
    {
        DirectCount = 3,
        TransitiveCount = 5,
        MaxDepth = 2,
        HeavyPackages = [],
    };

    [Fact]
    public void NoVulnerabilities_NoKnownExploitableFinding()
    {
        var packages = new[] { CreatePackage() };
        var vulns = new Dictionary<string, List<VulnerabilityInfo>>();
        var report = CreateMinimalCraReport();

        var result = AuditSimulator.Analyze(
            packages,
            vulns,
            report,
            CreateCleanSbomValidation(),
            [new ProvenanceResult { PackageId = "TestPkg", Version = "1.0.0", HasRepositorySignature = true }],
            CreateCleanAttackSurface(),
            hasSecurityPolicy: true,
            packagesWithSecurityPolicy: 1,
            packagesWithRepo: 1,
            config: new CraConfig { SecurityContact = "security@test.com", SupportPeriodEnd = "2028-12" },
            hasReadme: true,
            hasChangelog: true);

        Assert.DoesNotContain(result.Findings, f => f.ArticleReference.Contains("Annex I \u00a71(2)(a)"));
    }

    [Fact]
    public void PackageWithCve_CriticalFinding()
    {
        var packages = new[] { CreatePackage("Foo", "1.0.0") };
        var vulns = new Dictionary<string, List<VulnerabilityInfo>>
        {
            ["Foo"] =
            [
                new VulnerabilityInfo
                {
                    Id = "GHSA-001",
                    Severity = "CRITICAL",
                    Summary = "Test vuln",
                    PackageId = "Foo",
                    VulnerableVersionRange = "< 2.0.0",
                    PatchedVersion = "2.0.0",
                    Cves = ["CVE-2024-001"],
                },
            ],
        };
        var report = CreateMinimalCraReport();

        var result = AuditSimulator.Analyze(
            packages,
            vulns,
            report,
            CreateCleanSbomValidation(),
            null,
            CreateCleanAttackSurface(),
            hasSecurityPolicy: true,
            packagesWithSecurityPolicy: 1,
            packagesWithRepo: 1,
            config: new CraConfig { SecurityContact = "security@test.com", SupportPeriodEnd = "2028-12" },
            hasReadme: true,
            hasChangelog: true);

        var finding = Assert.Single(result.Findings, f => f.ArticleReference.Contains("Annex I \u00a71(2)(a)"));
        Assert.Equal(AuditSeverity.Critical, finding.Severity);
        Assert.Contains("Foo", finding.AffectedPackages);
    }

    [Fact]
    public void KevVulnerability_CriticalArt14Finding()
    {
        var packages = new[] { CreatePackage(hasKev: true) };
        var vulns = new Dictionary<string, List<VulnerabilityInfo>>();
        var report = CreateMinimalCraReport();

        var result = AuditSimulator.Analyze(
            packages,
            vulns,
            report,
            CreateCleanSbomValidation(),
            null,
            CreateCleanAttackSurface(),
            hasSecurityPolicy: true,
            packagesWithSecurityPolicy: 1,
            packagesWithRepo: 1,
            config: new CraConfig { SecurityContact = "security@test.com", SupportPeriodEnd = "2028-12" },
            hasReadme: true,
            hasChangelog: true);

        var finding = Assert.Single(result.Findings, f => f.ArticleReference.Contains("Art. 14"));
        Assert.Equal(AuditSeverity.Critical, finding.Severity);
    }

    [Fact]
    public void PatchAvailableNotApplied_HighFinding()
    {
        var packages = new[] { CreatePackage(patchNotApplied: 2) };
        var vulns = new Dictionary<string, List<VulnerabilityInfo>>();
        var report = CreateMinimalCraReport();

        var result = AuditSimulator.Analyze(
            packages,
            vulns,
            report,
            CreateCleanSbomValidation(),
            null,
            CreateCleanAttackSurface(),
            hasSecurityPolicy: true,
            packagesWithSecurityPolicy: 1,
            packagesWithRepo: 1,
            config: new CraConfig { SecurityContact = "security@test.com", SupportPeriodEnd = "2028-12" },
            hasReadme: true,
            hasChangelog: true);

        var finding = Assert.Single(result.Findings, f => f.ArticleReference.Contains("Annex I \u00a72(2)"));
        Assert.Equal(AuditSeverity.High, finding.Severity);
    }

    [Fact]
    public void SbomMissingFields_HighFinding()
    {
        var packages = new[] { CreatePackage() };
        var vulns = new Dictionary<string, List<VulnerabilityInfo>>();
        var report = CreateMinimalCraReport();
        var sbomValidation = new SbomValidationResult
        {
            TotalPackages = 1,
            WithSupplier = 0,
            WithLicense = 1,
            WithPurl = 1,
            WithChecksum = 1,
            HasTimestamp = true,
            HasCreator = true,
            MissingSupplier = ["Foo"],
        };

        var result = AuditSimulator.Analyze(
            packages,
            vulns,
            report,
            sbomValidation,
            null,
            CreateCleanAttackSurface(),
            hasSecurityPolicy: true,
            packagesWithSecurityPolicy: 1,
            packagesWithRepo: 1,
            config: new CraConfig { SecurityContact = "security@test.com", SupportPeriodEnd = "2028-12" },
            hasReadme: true,
            hasChangelog: true);

        var finding = Assert.Single(result.Findings, f => f.ArticleReference.Contains("Annex I \u00a72(1)"));
        Assert.Equal(AuditSeverity.High, finding.Severity);
    }

    [Fact]
    public void LowHealthScore_HighFinding()
    {
        var packages = new[] { CreatePackage(score: 30) };
        var vulns = new Dictionary<string, List<VulnerabilityInfo>>();
        var report = CreateMinimalCraReport();

        var result = AuditSimulator.Analyze(
            packages,
            vulns,
            report,
            CreateCleanSbomValidation(),
            null,
            CreateCleanAttackSurface(),
            hasSecurityPolicy: true,
            packagesWithSecurityPolicy: 1,
            packagesWithRepo: 1,
            config: new CraConfig { SecurityContact = "security@test.com", SupportPeriodEnd = "2028-12" },
            hasReadme: true,
            hasChangelog: true);

        var finding = Assert.Single(result.Findings, f => f.ArticleReference.Contains("Art. 13(5)"));
        Assert.Equal(AuditSeverity.High, finding.Severity);
    }

    [Fact]
    public void NoUpstreamSecurityPolicy_MediumFinding()
    {
        var packages = new[] { CreatePackage() };
        var vulns = new Dictionary<string, List<VulnerabilityInfo>>();
        var report = CreateMinimalCraReport();

        var result = AuditSimulator.Analyze(
            packages,
            vulns,
            report,
            CreateCleanSbomValidation(),
            null,
            CreateCleanAttackSurface(),
            hasSecurityPolicy: true,
            packagesWithSecurityPolicy: 0,
            packagesWithRepo: 5,
            config: new CraConfig { SecurityContact = "security@test.com", SupportPeriodEnd = "2028-12" },
            hasReadme: true,
            hasChangelog: true);

        var finding = Assert.Single(result.Findings, f => f.ArticleReference.Contains("Annex I \u00a72(5)"));
        Assert.Equal(AuditSeverity.Medium, finding.Severity);
    }

    [Fact]
    public void NoSecurityContact_MediumFinding()
    {
        var packages = new[] { CreatePackage() };
        var vulns = new Dictionary<string, List<VulnerabilityInfo>>();
        var report = CreateMinimalCraReport();

        var result = AuditSimulator.Analyze(
            packages,
            vulns,
            report,
            CreateCleanSbomValidation(),
            null,
            CreateCleanAttackSurface(),
            hasSecurityPolicy: false,
            packagesWithSecurityPolicy: 1,
            packagesWithRepo: 1,
            config: new CraConfig { SecurityContact = null, SupportPeriodEnd = "2028-12" },
            hasReadme: true,
            hasChangelog: true);

        var finding = Assert.Single(result.Findings, f => f.ArticleReference.Contains("Annex I \u00a72(6)"));
        Assert.Equal(AuditSeverity.Medium, finding.Severity);
    }

    [Fact]
    public void DeepDependencyTree_MediumFinding()
    {
        var packages = new[] { CreatePackage() };
        var vulns = new Dictionary<string, List<VulnerabilityInfo>>();
        var report = CreateMinimalCraReport();
        var attackSurface = new AttackSurfaceResult
        {
            DirectCount = 5,
            TransitiveCount = 50,
            MaxDepth = 8,
            HeavyPackages = [],
        };

        var result = AuditSimulator.Analyze(
            packages,
            vulns,
            report,
            CreateCleanSbomValidation(),
            null,
            attackSurface,
            hasSecurityPolicy: true,
            packagesWithSecurityPolicy: 1,
            packagesWithRepo: 1,
            config: new CraConfig { SecurityContact = "security@test.com", SupportPeriodEnd = "2028-12" },
            hasReadme: true,
            hasChangelog: true);

        var finding = Assert.Single(result.Findings, f => f.ArticleReference.Contains("Annex I \u00a71(2)(j)"));
        Assert.Equal(AuditSeverity.Medium, finding.Severity);
    }

    [Fact]
    public void MissingLicense_MediumFinding()
    {
        var packages = new[] { CreatePackage(license: null) };
        var vulns = new Dictionary<string, List<VulnerabilityInfo>>();
        var report = CreateMinimalCraReport();

        var result = AuditSimulator.Analyze(
            packages,
            vulns,
            report,
            CreateCleanSbomValidation(),
            null,
            CreateCleanAttackSurface(),
            hasSecurityPolicy: true,
            packagesWithSecurityPolicy: 1,
            packagesWithRepo: 1,
            config: new CraConfig { SecurityContact = "security@test.com", SupportPeriodEnd = "2028-12" },
            hasReadme: true,
            hasChangelog: true);

        var finding = Assert.Single(result.Findings, f => f.ArticleReference.Contains("Annex II"));
        Assert.Equal(AuditSeverity.Medium, finding.Severity);
    }

    [Fact]
    public void NoSupportPeriod_LowFinding()
    {
        var packages = new[] { CreatePackage() };
        var vulns = new Dictionary<string, List<VulnerabilityInfo>>();
        var report = CreateMinimalCraReport();

        var result = AuditSimulator.Analyze(
            packages,
            vulns,
            report,
            CreateCleanSbomValidation(),
            null,
            CreateCleanAttackSurface(),
            hasSecurityPolicy: true,
            packagesWithSecurityPolicy: 1,
            packagesWithRepo: 1,
            config: new CraConfig { SecurityContact = "security@test.com", SupportPeriodEnd = null },
            hasReadme: true,
            hasChangelog: true);

        var finding = Assert.Single(result.Findings, f => f.ArticleReference.Contains("Art. 13(8)"));
        Assert.Equal(AuditSeverity.Low, finding.Severity);
    }

    [Fact]
    public void UnverifiedProvenance_HighFinding()
    {
        var packages = new[] { CreatePackage() };
        var vulns = new Dictionary<string, List<VulnerabilityInfo>>();
        var report = CreateMinimalCraReport();
        var provenanceResults = new List<ProvenanceResult>
        {
            new() { PackageId = "TestPkg", Version = "1.0.0" }  // No signatures = IsVerified is false
        };

        var result = AuditSimulator.Analyze(
            packages,
            vulns,
            report,
            CreateCleanSbomValidation(),
            provenanceResults,
            CreateCleanAttackSurface(),
            hasSecurityPolicy: true,
            packagesWithSecurityPolicy: 1,
            packagesWithRepo: 1,
            config: new CraConfig { SecurityContact = "security@test.com", SupportPeriodEnd = "2028-12" },
            hasReadme: true,
            hasChangelog: true);

        var finding = Assert.Single(result.Findings, f => f.ArticleReference.Contains("Annex I"));
        Assert.Equal(AuditSeverity.High, finding.Severity);
        Assert.Contains("TestPkg", finding.AffectedPackages);
    }

    [Fact]
    public void MissingDocumentation_LowFinding()
    {
        var packages = new[] { CreatePackage() };
        var vulns = new Dictionary<string, List<VulnerabilityInfo>>();
        var report = CreateMinimalCraReport();

        var result = AuditSimulator.Analyze(
            packages,
            vulns,
            report,
            CreateCleanSbomValidation(),
            [new ProvenanceResult { PackageId = "TestPkg", Version = "1.0.0", HasRepositorySignature = true }],
            CreateCleanAttackSurface(),
            hasSecurityPolicy: true,
            packagesWithSecurityPolicy: 1,
            packagesWithRepo: 1,
            config: new CraConfig { SecurityContact = "security@test.com", SupportPeriodEnd = "2028-12" },
            hasReadme: false,   // Missing!
            hasChangelog: true);

        var finding = Assert.Single(result.Findings, f => f.Severity == AuditSeverity.Low);
        Assert.Contains("README", finding.Finding);
    }

    [Fact]
    public void CleanProject_EmptyFindings()
    {
        var packages = new[] { CreatePackage() };
        var vulns = new Dictionary<string, List<VulnerabilityInfo>>();
        var report = CreateMinimalCraReport();

        var result = AuditSimulator.Analyze(
            packages,
            vulns,
            report,
            CreateCleanSbomValidation(),
            [new ProvenanceResult { PackageId = "TestPkg", Version = "1.0.0", HasRepositorySignature = true }],
            CreateCleanAttackSurface(),
            hasSecurityPolicy: true,
            packagesWithSecurityPolicy: 1,
            packagesWithRepo: 1,
            config: new CraConfig { SecurityContact = "security@test.com", SupportPeriodEnd = "2028-12" },
            hasReadme: true,
            hasChangelog: true);

        Assert.Empty(result.Findings);
        Assert.Equal(0, result.CriticalCount);
        Assert.Equal(0, result.HighCount);
        Assert.Equal(0, result.MediumCount);
        Assert.Equal(0, result.LowCount);
    }

    [Fact]
    public void FindingsSortedBySeverity()
    {
        // Trigger Critical (KEV), Medium (deep tree), and Low (no support period)
        var packages = new[] { CreatePackage(hasKev: true) };
        var vulns = new Dictionary<string, List<VulnerabilityInfo>>();
        var report = CreateMinimalCraReport();
        var attackSurface = new AttackSurfaceResult
        {
            DirectCount = 5,
            TransitiveCount = 50,
            MaxDepth = 8,
            HeavyPackages = [],
        };

        var result = AuditSimulator.Analyze(
            packages,
            vulns,
            report,
            CreateCleanSbomValidation(),
            [new ProvenanceResult { PackageId = "TestPkg", Version = "1.0.0", HasRepositorySignature = true }],
            attackSurface,
            hasSecurityPolicy: true,
            packagesWithSecurityPolicy: 1,
            packagesWithRepo: 1,
            config: new CraConfig { SecurityContact = "security@test.com", SupportPeriodEnd = null },
            hasReadme: true,
            hasChangelog: true);

        Assert.True(result.Findings.Count >= 3, $"Expected at least 3 findings, got {result.Findings.Count}");

        // Verify ordering: Critical < High < Medium < Low (sorted by severity descending)
        for (int i = 1; i < result.Findings.Count; i++)
        {
            Assert.True(
                result.Findings[i - 1].Severity <= result.Findings[i].Severity,
                $"Finding at index {i - 1} ({result.Findings[i - 1].Severity}) should come before or equal to finding at index {i} ({result.Findings[i].Severity})");
        }
    }
}
