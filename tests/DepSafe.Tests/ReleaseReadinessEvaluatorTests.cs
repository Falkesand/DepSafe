using DepSafe.Compliance;
using DepSafe.Models;

namespace DepSafe.Tests;

public class ReleaseReadinessEvaluatorTests
{
    private static CraReport CreateReport(
        CraComplianceStatus overallStatus = CraComplianceStatus.Compliant,
        List<CraComplianceItem>? items = null) => new()
    {
        GeneratedAt = DateTime.UtcNow,
        ProjectPath = "/test",
        HealthScore = 80,
        HealthStatus = HealthStatus.Healthy,
        ComplianceItems = items ?? [],
        OverallComplianceStatus = overallStatus,
        Sbom = new SbomDocument { SpdxId = "SPDXRef-DOCUMENT", Name = "test", DocumentNamespace = "https://test", CreationInfo = new SbomCreationInfo { Created = "2024-01-01", Creators = ["Tool: test"] }, Packages = [], Relationships = [] },
        Vex = new VexDocument { Id = "test", Author = "test", Timestamp = "2024-01-01T00:00:00Z", Statements = [] },
        PackageCount = 5,
        TransitivePackageCount = 0,
        VulnerabilityCount = 0,
        CriticalPackageCount = 0,
    };

    private static CraComplianceItem CreateItem(
        string requirement = "Test Requirement",
        CraComplianceStatus status = CraComplianceStatus.Compliant) => new()
    {
        Requirement = requirement,
        Description = "Test description",
        Status = status,
    };

    [Fact]
    public void Evaluate_AllCompliant_NoViolations_IsReady()
    {
        var report = CreateReport(items:
        [
            CreateItem("Req A", CraComplianceStatus.Compliant),
            CreateItem("Req B", CraComplianceStatus.Compliant),
        ]);

        var result = ReleaseReadinessEvaluator.Evaluate(report, []);

        Assert.True(result.IsReady);
        Assert.Empty(result.BlockingItems);
        Assert.Empty(result.AdvisoryItems);
    }

    [Fact]
    public void Evaluate_NonCompliantItem_IsBlocking()
    {
        var report = CreateReport(items:
        [
            CreateItem("CRA Art. 10(4) - Exploited Vulnerabilities (CISA KEV)", CraComplianceStatus.NonCompliant),
        ]);

        var result = ReleaseReadinessEvaluator.Evaluate(report, []);

        Assert.False(result.IsReady);
        Assert.Single(result.BlockingItems);
        Assert.Contains("CISA KEV", result.BlockingItems[0].Requirement);
    }

    [Fact]
    public void Evaluate_PolicyViolation_IsBlocking()
    {
        var report = CreateReport(items:
        [
            CreateItem("Req A", CraComplianceStatus.Compliant),
        ]);

        var result = ReleaseReadinessEvaluator.Evaluate(report, ["License policy: SomePkg — GPL blocked"]);

        Assert.False(result.IsReady);
        Assert.Single(result.BlockingItems);
        Assert.Contains("GPL blocked", result.BlockingItems[0].Reason);
    }

    [Fact]
    public void Evaluate_ActionRequiredItem_IsAdvisory()
    {
        var report = CreateReport(items:
        [
            CreateItem("CRA Art. 10(6) - Security Updates", CraComplianceStatus.ActionRequired),
        ]);

        var result = ReleaseReadinessEvaluator.Evaluate(report, []);

        Assert.True(result.IsReady);
        Assert.Empty(result.BlockingItems);
        Assert.Single(result.AdvisoryItems);
    }

    [Fact]
    public void Evaluate_ReviewItem_IsAdvisory()
    {
        var report = CreateReport(items:
        [
            CreateItem("CRA Art. 10(9) - License Information", CraComplianceStatus.Review),
        ]);

        var result = ReleaseReadinessEvaluator.Evaluate(report, []);

        Assert.True(result.IsReady);
        Assert.Empty(result.BlockingItems);
        Assert.Single(result.AdvisoryItems);
    }

    [Fact]
    public void Evaluate_Mixed_AllBlockersAndAdvisoriesListed()
    {
        var report = CreateReport(items:
        [
            CreateItem("Req A", CraComplianceStatus.NonCompliant),
            CreateItem("Req B", CraComplianceStatus.ActionRequired),
            CreateItem("Req C", CraComplianceStatus.Compliant),
            CreateItem("Req D", CraComplianceStatus.NonCompliant),
            CreateItem("Req E", CraComplianceStatus.Review),
        ]);

        var result = ReleaseReadinessEvaluator.Evaluate(report, ["Policy violation X"]);

        Assert.False(result.IsReady);
        Assert.Equal(3, result.BlockingItems.Count); // 2 NonCompliant + 1 policy violation
        Assert.Equal(2, result.AdvisoryItems.Count); // ActionRequired + Review
    }

    [Fact]
    public void Evaluate_EmptyReport_IsReady()
    {
        var report = CreateReport(items: []);

        var result = ReleaseReadinessEvaluator.Evaluate(report, []);

        Assert.True(result.IsReady);
    }

    [Fact]
    public void Evaluate_OnlyPolicyViolations_NoComplianceIssues_IsBlocked()
    {
        var report = CreateReport(items:
        [
            CreateItem("Req A", CraComplianceStatus.Compliant),
        ]);

        var result = ReleaseReadinessEvaluator.Evaluate(report, ["Deprecated package detected", "Min health score violated"]);

        Assert.False(result.IsReady);
        Assert.Equal(2, result.BlockingItems.Count);
    }
}
