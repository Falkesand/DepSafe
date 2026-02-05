using DepSafe.Compliance;
using DepSafe.Models;

namespace DepSafe.Tests;

public class CraComplianceTests
{
    [Fact]
    public void ReadinessScore_AllCompliant_Returns100()
    {
        var items = new List<CraComplianceItem>
        {
            MakeItem("CRA Art. 10(4) - Exploited Vulnerabilities (CISA KEV)", CraComplianceStatus.Compliant),
            MakeItem("CRA Art. 11 - Vulnerability Handling", CraComplianceStatus.Compliant),
            MakeItem("CRA Art. 10 - Software Bill of Materials", CraComplianceStatus.Compliant),
        };

        var score = CraReportGenerator.CalculateCraReadinessScore(items);
        Assert.Equal(100, score);
    }

    [Fact]
    public void ReadinessScore_AllNonCompliant_Returns0()
    {
        var items = new List<CraComplianceItem>
        {
            MakeItem("CRA Art. 10(4) - Exploited Vulnerabilities (CISA KEV)", CraComplianceStatus.NonCompliant),
            MakeItem("CRA Art. 11 - Vulnerability Handling", CraComplianceStatus.NonCompliant),
            MakeItem("CRA Art. 10 - Software Bill of Materials", CraComplianceStatus.NonCompliant),
        };

        var score = CraReportGenerator.CalculateCraReadinessScore(items);
        Assert.Equal(0, score);
    }

    [Fact]
    public void ReadinessScore_MixedStatus_CalculatesWeightedScore()
    {
        var items = new List<CraComplianceItem>
        {
            MakeItem("CRA Art. 10(4) - Exploited Vulnerabilities (CISA KEV)", CraComplianceStatus.Compliant),   // weight 15
            MakeItem("CRA Art. 11 - Vulnerability Handling", CraComplianceStatus.ActionRequired),                 // weight 15, 25%
            MakeItem("CRA Art. 10 - Software Bill of Materials", CraComplianceStatus.Review),                     // weight 10, 50%
        };

        var score = CraReportGenerator.CalculateCraReadinessScore(items);

        // (15*1.0 + 15*0.25 + 10*0.5) / (15+15+10) * 100 = (15+3.75+5)/40*100 = 59.375 -> 59
        Assert.Equal(59, score);
    }

    [Fact]
    public void ReadinessScore_ReviewItems_Get50Percent()
    {
        var items = new List<CraComplianceItem>
        {
            MakeItem("CRA Art. 10 - Software Bill of Materials", CraComplianceStatus.Review),
        };

        var score = CraReportGenerator.CalculateCraReadinessScore(items);
        Assert.Equal(50, score);
    }

    [Fact]
    public void ReadinessScore_EmptyList_Returns0()
    {
        var items = new List<CraComplianceItem>();
        var score = CraReportGenerator.CalculateCraReadinessScore(items);
        Assert.Equal(0, score);
    }

    [Fact]
    public void ReadinessScore_UnknownItem_GetsDefaultWeight()
    {
        var items = new List<CraComplianceItem>
        {
            MakeItem("Some Unknown Requirement", CraComplianceStatus.Compliant),
        };

        var score = CraReportGenerator.CalculateCraReadinessScore(items);
        Assert.Equal(100, score);
    }

    [Fact]
    public void SbomValidation_AllFieldsPresent_Returns100Completeness()
    {
        var result = new SbomValidationResult
        {
            TotalPackages = 10,
            WithSupplier = 10,
            WithLicense = 10,
            WithPurl = 10,
            WithChecksum = 10,
            HasTimestamp = true,
            HasCreator = true
        };

        Assert.Equal(100, result.CompletenessPercent);
    }

    [Fact]
    public void SbomValidation_NoFieldsPresent_Returns0Completeness()
    {
        var result = new SbomValidationResult
        {
            TotalPackages = 10,
            WithSupplier = 0,
            WithLicense = 0,
            WithPurl = 0,
            WithChecksum = 0,
            HasTimestamp = false,
            HasCreator = false
        };

        Assert.Equal(0, result.CompletenessPercent);
    }

    [Fact]
    public void SbomValidation_PartialFields_ReturnsPartialScore()
    {
        var result = new SbomValidationResult
        {
            TotalPackages = 10,
            WithSupplier = 10,
            WithLicense = 10,
            WithPurl = 0,
            WithChecksum = 0,
            HasTimestamp = true,
            HasCreator = true
        };

        // doc = 1.0, pkg = (10+10+0+0)/(40) = 0.5
        // (1.0*0.3 + 0.5*0.7) * 100 = 65
        Assert.Equal(65, result.CompletenessPercent);
    }

    [Fact]
    public void SbomValidation_ZeroPackages_BasedOnDocFields()
    {
        var result = new SbomValidationResult
        {
            TotalPackages = 0,
            WithSupplier = 0,
            WithLicense = 0,
            WithPurl = 0,
            WithChecksum = 0,
            HasTimestamp = true,
            HasCreator = true
        };

        Assert.Equal(100, result.CompletenessPercent);
    }

    [Fact]
    public void CraConfig_DefaultValues_NoFailures()
    {
        var config = new CraConfig();
        Assert.False(config.FailOnKev);
        Assert.Null(config.FailOnEpssThreshold);
        Assert.Null(config.FailOnVulnerabilityCount);
        Assert.Null(config.FailOnCraReadinessBelow);
        Assert.Null(config.SupportPeriodEnd);
        Assert.Null(config.SecurityContact);
    }

    [Fact]
    public void ProvenanceResult_WithRepoSignature_IsVerified()
    {
        var result = new ProvenanceResult
        {
            PackageId = "Test.Package",
            Version = "1.0.0",
            HasRepositorySignature = true,
            HasAuthorSignature = false
        };

        Assert.True(result.IsVerified);
    }

    [Fact]
    public void ProvenanceResult_WithNoSignature_IsNotVerified()
    {
        var result = new ProvenanceResult
        {
            PackageId = "Test.Package",
            Version = "1.0.0",
            HasRepositorySignature = false,
            HasAuthorSignature = false
        };

        Assert.False(result.IsVerified);
    }

    private static CraComplianceItem MakeItem(string requirement, CraComplianceStatus status) => new()
    {
        Requirement = requirement,
        Description = "Test",
        Status = status,
        Evidence = "Test evidence"
    };
}
