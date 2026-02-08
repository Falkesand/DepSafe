using DepSafe.Compliance;
using DepSafe.Models;

namespace DepSafe.Tests;

public class CraReportGeneratorTests
{
    // --- CalculateCraReadinessScore ---

    [Fact]
    public void CalculateCraReadinessScore_AllCompliant_Returns100()
    {
        var items = new List<CraComplianceItem>
        {
            MakeItem("CRA Art. 10(4) - Exploited Vulnerabilities (CISA KEV)", CraComplianceStatus.Compliant),
            MakeItem("CRA Art. 11 - Vulnerability Handling", CraComplianceStatus.Compliant),
            MakeItem("CRA Art. 10 - Software Bill of Materials", CraComplianceStatus.Compliant),
            MakeItem("CRA Annex I Part I(1) - Release Readiness", CraComplianceStatus.Compliant),
            MakeItem("CRA Art. 11(4) - Remediation Timeliness", CraComplianceStatus.Compliant),
            MakeItem("CRA Art. 10(4) - Exploit Probability (EPSS)", CraComplianceStatus.Compliant),
            MakeItem("CRA Art. 10(6) - Security Updates", CraComplianceStatus.Compliant),
            MakeItem("CRA Art. 13(8) - Support Period", CraComplianceStatus.Compliant),
            MakeItem("CRA Annex I Part I(10) - Attack Surface", CraComplianceStatus.Compliant),
            MakeItem("CRA Annex I Part II(1) - SBOM Completeness", CraComplianceStatus.Compliant),
            MakeItem("CRA Art. 13(5) - Package Provenance", CraComplianceStatus.Compliant),
            MakeItem("CRA Annex II - Documentation", CraComplianceStatus.Compliant),
            MakeItem("CRA Art. 10(9) - License Information", CraComplianceStatus.Compliant),
            MakeItem("CRA Art. 11(5) - Security Policy", CraComplianceStatus.Compliant),
            MakeItem("CRA Art. 10 - No Deprecated Components", CraComplianceStatus.Compliant),
            MakeItem("CRA Art. 10 - Cryptographic Compliance", CraComplianceStatus.Compliant),
            MakeItem("CRA Art. 10 - Supply Chain Integrity", CraComplianceStatus.Compliant),
            MakeItem("CRA Art. 14 - Incident Reporting", CraComplianceStatus.Compliant),
            MakeItem("CRA Art. 10 - Artifact Integrity", CraComplianceStatus.Compliant),
        };

        var score = CraReportGenerator.CalculateCraReadinessScore(items);

        Assert.Equal(100, score);
    }

    [Fact]
    public void CalculateCraReadinessScore_AllNonCompliant_Returns0()
    {
        var items = new List<CraComplianceItem>
        {
            MakeItem("CRA Art. 10(4) - Exploited Vulnerabilities (CISA KEV)", CraComplianceStatus.NonCompliant),
            MakeItem("CRA Art. 11 - Vulnerability Handling", CraComplianceStatus.NonCompliant),
            MakeItem("CRA Art. 10 - Software Bill of Materials", CraComplianceStatus.NonCompliant),
            MakeItem("CRA Annex I Part I(1) - Release Readiness", CraComplianceStatus.NonCompliant),
            MakeItem("CRA Art. 11(4) - Remediation Timeliness", CraComplianceStatus.NonCompliant),
            MakeItem("CRA Art. 10(4) - Exploit Probability (EPSS)", CraComplianceStatus.NonCompliant),
            MakeItem("CRA Art. 10(6) - Security Updates", CraComplianceStatus.NonCompliant),
            MakeItem("CRA Art. 13(8) - Support Period", CraComplianceStatus.NonCompliant),
            MakeItem("CRA Annex I Part I(10) - Attack Surface", CraComplianceStatus.NonCompliant),
            MakeItem("CRA Annex I Part II(1) - SBOM Completeness", CraComplianceStatus.NonCompliant),
            MakeItem("CRA Art. 13(5) - Package Provenance", CraComplianceStatus.NonCompliant),
            MakeItem("CRA Annex II - Documentation", CraComplianceStatus.NonCompliant),
            MakeItem("CRA Art. 10(9) - License Information", CraComplianceStatus.NonCompliant),
            MakeItem("CRA Art. 11(5) - Security Policy", CraComplianceStatus.NonCompliant),
            MakeItem("CRA Art. 10 - No Deprecated Components", CraComplianceStatus.NonCompliant),
            MakeItem("CRA Art. 10 - Cryptographic Compliance", CraComplianceStatus.NonCompliant),
            MakeItem("CRA Art. 10 - Supply Chain Integrity", CraComplianceStatus.NonCompliant),
            MakeItem("CRA Art. 14 - Incident Reporting", CraComplianceStatus.NonCompliant),
            MakeItem("CRA Art. 10 - Artifact Integrity", CraComplianceStatus.NonCompliant),
        };

        var score = CraReportGenerator.CalculateCraReadinessScore(items);

        Assert.Equal(0, score);
    }

    // --- Artifact Integrity Compliance Item ---

    [Fact]
    public void CalculateCraReadinessScore_ArtifactIntegrity_HasWeight2()
    {
        // Artifact Integrity with weight 2, Compliant: earned=2, total=2, score=100
        var items = new List<CraComplianceItem>
        {
            MakeItem("CRA Art. 10 - Artifact Integrity", CraComplianceStatus.Compliant),
        };

        var score = CraReportGenerator.CalculateCraReadinessScore(items);

        Assert.Equal(100, score);
    }

    [Fact]
    public void CalculateCraReadinessScore_MixedStatuses_CalculatesWeighted()
    {
        // KEV weight=15 Compliant=1.0, VulnHandling weight=15 ActionRequired=0.25, SBOM weight=10 Review=0.5
        // earned = 15*1.0 + 15*0.25 + 10*0.5 = 15 + 3.75 + 5 = 23.75
        // total  = 15 + 15 + 10 = 40
        // score  = Math.Round(100.0 * 23.75 / 40) = Math.Round(59.375) = 59
        var items = new List<CraComplianceItem>
        {
            MakeItem("CRA Art. 10(4) - Exploited Vulnerabilities (CISA KEV)", CraComplianceStatus.Compliant),
            MakeItem("CRA Art. 11 - Vulnerability Handling", CraComplianceStatus.ActionRequired),
            MakeItem("CRA Art. 10 - Software Bill of Materials", CraComplianceStatus.Review),
        };

        var score = CraReportGenerator.CalculateCraReadinessScore(items);

        Assert.Equal(59, score);
    }

    [Fact]
    public void CalculateCraReadinessScore_EmptyList_Returns0()
    {
        var items = new List<CraComplianceItem>();

        var score = CraReportGenerator.CalculateCraReadinessScore(items);

        Assert.Equal(0, score);
    }

    [Fact]
    public void CalculateCraReadinessScore_ReviewStatus_Gets50Percent()
    {
        // Single item with Review status: earned = weight * 0.5, total = weight
        // score = Math.Round(100.0 * 0.5) = 50
        var items = new List<CraComplianceItem>
        {
            MakeItem("CRA Art. 10 - Software Bill of Materials", CraComplianceStatus.Review),
        };

        var score = CraReportGenerator.CalculateCraReadinessScore(items);

        Assert.Equal(50, score);
    }

    [Fact]
    public void CalculateCraReadinessScore_UnknownRequirement_UsesDefaultWeight()
    {
        // Unknown requirement gets default weight of 2
        // Compliant multiplier = 1.0, so earned = 2*1.0 = 2, total = 2
        // score = Math.Round(100.0 * 2 / 2) = 100
        var items = new List<CraComplianceItem>
        {
            MakeItem("Some Unknown Requirement", CraComplianceStatus.Compliant),
        };

        var score = CraReportGenerator.CalculateCraReadinessScore(items);

        Assert.Equal(100, score);
    }

    // --- GetScoreClass ---

    [Theory]
    [InlineData(80, "healthy")]
    [InlineData(65, "watch")]
    [InlineData(45, "warning")]
    [InlineData(30, "critical")]
    public void GetScoreClass_Thresholds(int score, string expected)
    {
        var result = CraReportGenerator.GetScoreClass(score);

        Assert.Equal(expected, result);
    }

    // --- GetCraScoreClass ---

    [Theory]
    [InlineData(90, "healthy")]
    [InlineData(75, "watch")]
    [InlineData(55, "warning")]
    [InlineData(40, "critical")]
    public void GetCraScoreClass_Thresholds(int score, string expected)
    {
        var result = CraReportGenerator.GetCraScoreClass(score);

        Assert.Equal(expected, result);
    }

    // --- FormatNumber ---

    [Fact]
    public void FormatNumber_Zero_ReturnsZero()
    {
        Assert.Equal("0", CraReportGenerator.FormatNumber(0));
    }

    [Fact]
    public void FormatNumber_BelowThousand_ReturnsPlainNumber()
    {
        Assert.Equal("999", CraReportGenerator.FormatNumber(999));
    }

    [Fact]
    public void FormatNumber_Thousands_ReturnsSuffixK()
    {
        var result = CraReportGenerator.FormatNumber(1500);

        // Account for locale-specific decimal separator (e.g. "1.5K" or "1,5K")
        var expected = $"{1500 / 1_000.0:F1}K";
        Assert.Equal(expected, result);
    }

    [Fact]
    public void FormatNumber_Millions_ReturnsSuffixM()
    {
        var result = CraReportGenerator.FormatNumber(2_500_000);

        var expected = $"{2_500_000 / 1_000_000.0:F1}M";
        Assert.Equal(expected, result);
    }

    // --- FormatDuration ---

    [Fact]
    public void FormatDuration_SubSecond()
    {
        var duration = TimeSpan.FromMilliseconds(500);

        var result = CraReportGenerator.FormatDuration(duration);

        Assert.Contains("ms", result);
        Assert.Contains("500", result);
    }

    [Fact]
    public void FormatDuration_Seconds()
    {
        var duration = TimeSpan.FromSeconds(30);

        var result = CraReportGenerator.FormatDuration(duration);

        Assert.Contains("s", result);
        Assert.Contains("30", result);
    }

    [Fact]
    public void FormatDuration_Minutes()
    {
        var duration = TimeSpan.FromSeconds(135); // 2m 15s

        var result = CraReportGenerator.FormatDuration(duration);

        Assert.Contains("m", result);
        Assert.Contains("2", result);
    }

    [Fact]
    public void FormatDuration_Hours()
    {
        var duration = TimeSpan.FromMinutes(90); // 1h 30m

        var result = CraReportGenerator.FormatDuration(duration);

        Assert.Contains("h", result);
        Assert.Contains("1", result);
    }

    // --- FormatDownloads ---

    [Fact]
    public void FormatDownloads_Zero_ReturnsNA()
    {
        var result = CraReportGenerator.FormatDownloads(0);

        Assert.Equal("N/A", result);
    }

    [Fact]
    public void FormatDownloads_Positive_FormatsNumber()
    {
        var result = CraReportGenerator.FormatDownloads(1500);

        // Account for locale-specific decimal separator
        var expected = $"{1500 / 1_000.0:F1}K";
        Assert.Equal(expected, result);
    }

    // --- EscapeHtml ---

    [Theory]
    [InlineData("<", "&lt;")]
    [InlineData("&", "&amp;")]
    [InlineData("\"", "&quot;")]
    [InlineData("'", "&#39;")]
    [InlineData("clean", "clean")]
    public void EscapeHtml_SpecialChars(string input, string expected)
    {
        var result = CraReportGenerator.EscapeHtml(input);

        Assert.Equal(expected, result);
    }

    [Fact]
    public void EscapeHtml_EmptyString_ReturnsEmpty()
    {
        var result = CraReportGenerator.EscapeHtml(string.Empty);

        Assert.Equal(string.Empty, result);
    }

    // --- EscapeJs ---

    [Fact]
    public void EscapeJs_Quotes_Escaped()
    {
        var singleQuote = CraReportGenerator.EscapeJs("it's");
        var doubleQuote = CraReportGenerator.EscapeJs("say \"hello\"");

        Assert.Equal("it\\'s", singleQuote);
        Assert.Equal("say \\\"hello\\\"", doubleQuote);
    }

    // --- MinifyCss ---

    [Fact]
    public void MinifyCss_RemovesComments()
    {
        var css = "a { /* comment */ color: red; }";

        var result = CraReportGenerator.MinifyCss(css);

        Assert.DoesNotContain("comment", result);
        Assert.Contains("color", result);
        Assert.Contains("red", result);
    }

    [Fact]
    public void MinifyCss_CollapsesWhitespace()
    {
        var css = "a  {  color :  red  ;  }";

        var result = CraReportGenerator.MinifyCss(css);

        // Structural characters should have no adjacent whitespace
        Assert.DoesNotContain(" {", result);
        Assert.DoesNotContain("{ ", result);
        Assert.DoesNotContain(" :", result);
        Assert.DoesNotContain(": ", result);
        Assert.DoesNotContain(" ;", result);
        Assert.DoesNotContain("; ", result);
        Assert.DoesNotContain(" }", result);
    }

    // --- DetermineOverallStatus ---

    [Fact]
    public void DetermineOverallStatus_AllCompliant_ReturnsCompliant()
    {
        var items = new List<CraComplianceItem>
        {
            MakeItem("CRA Art. 10 - Software Bill of Materials", CraComplianceStatus.Compliant),
            MakeItem("CRA Art. 11 - Vulnerability Handling", CraComplianceStatus.Compliant),
        };

        var result = CraReportGenerator.DetermineOverallStatus(items);

        Assert.Equal(CraComplianceStatus.Compliant, result);
    }

    [Fact]
    public void DetermineOverallStatus_AnyNonCompliant_ReturnsNonCompliant()
    {
        var items = new List<CraComplianceItem>
        {
            MakeItem("CRA Art. 10 - Software Bill of Materials", CraComplianceStatus.Compliant),
            MakeItem("CRA Art. 11 - Vulnerability Handling", CraComplianceStatus.NonCompliant),
            MakeItem("CRA Art. 10(4) - Exploited Vulnerabilities (CISA KEV)", CraComplianceStatus.ActionRequired),
        };

        var result = CraReportGenerator.DetermineOverallStatus(items);

        Assert.Equal(CraComplianceStatus.NonCompliant, result);
    }

    // --- Helper ---

    private static CraComplianceItem MakeItem(string requirement, CraComplianceStatus status) => new()
    {
        Requirement = requirement,
        Description = "Test description",
        Status = status,
        Evidence = "Test evidence",
    };
}
