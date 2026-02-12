using DepSafe.Compliance;
using DepSafe.Models;
using DepSafe.Scoring;

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
        };

        var score = CraReportGenerator.CalculateCraReadinessScore(items);

        Assert.Equal(0, score);
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

    // --- Dashboard Sections: Release Readiness ---

    [Fact]
    public void GenerateHtml_ReleaseReadinessGo_RendersGreenCard()
    {
        var gen = CreateGenerator();
        var report = CreateMinimalReport();
        var readiness = new ReleaseReadinessResult
        {
            BlockingItems = [],
            AdvisoryItems = [],
        };
        gen.SetReleaseReadiness(readiness);

        var html = gen.GenerateHtml(report);

        Assert.Contains("release-gate-go", html);
        Assert.Contains("GO", html);
        Assert.Contains("All compliance checks passed", html);
    }

    [Fact]
    public void GenerateHtml_ReleaseReadinessNoGo_RendersBlockers()
    {
        var gen = CreateGenerator();
        var report = CreateMinimalReport();
        var readiness = new ReleaseReadinessResult
        {
            BlockingItems =
            [
                new ReleaseBlocker { Requirement = "KEV Vulnerabilities", Reason = "Known exploited vulnerability found" },
            ],
            AdvisoryItems = ["Review SBOM completeness"],
        };
        gen.SetReleaseReadiness(readiness);

        var html = gen.GenerateHtml(report);

        Assert.Contains("release-gate-nogo", html);
        Assert.Contains("NO-GO", html);
        Assert.Contains("KEV Vulnerabilities", html);
        Assert.Contains("Known exploited vulnerability found", html);
        Assert.Contains("advisory-list", html);
        Assert.Contains("Review SBOM completeness", html);
    }

    // --- Dashboard Sections: Security Budget ---

    [Fact]
    public void GenerateHtml_SecurityBudgetWithItems_RendersTieredTables()
    {
        var gen = CreateGenerator();
        var report = CreateMinimalReport();
        var budget = new SecurityBudgetResult
        {
            Items =
            [
                new TieredRemediationItem
                {
                    Item = new RemediationRoadmapItem
                    {
                        PackageId = "Foo.Bar",
                        CurrentVersion = "1.0.0",
                        RecommendedVersion = "1.0.1",
                        CveCount = 2,
                        CveIds = ["CVE-2024-001", "CVE-2024-002"],
                        ScoreLift = 5,
                        Effort = UpgradeEffort.Patch,
                        PriorityScore = 100,
                    },
                    Tier = RemediationTier.HighROI,
                    RoiScore = 50.0,
                    CumulativeRiskReductionPercent = 80.0,
                },
                new TieredRemediationItem
                {
                    Item = new RemediationRoadmapItem
                    {
                        PackageId = "Baz.Qux",
                        CurrentVersion = "2.0.0",
                        RecommendedVersion = "3.0.0",
                        CveCount = 1,
                        CveIds = ["CVE-2024-003"],
                        ScoreLift = 1,
                        Effort = UpgradeEffort.Major,
                        PriorityScore = 10,
                    },
                    Tier = RemediationTier.LowROI,
                    RoiScore = 5.0,
                    CumulativeRiskReductionPercent = 100.0,
                },
            ],
            TotalRiskScore = 110,
            HighROIRiskReduction = 100,
            HighROIPercentage = 80.0,
        };
        gen.SetSecurityBudget(budget);

        var html = gen.GenerateHtml(report);

        Assert.Contains("budget-summary", html);
        Assert.Contains("Fix 1 item", html);
        Assert.Contains("80%", html);
        Assert.Contains("tier-high", html);
        Assert.Contains("Foo.Bar", html);
        Assert.Contains("tier-low", html);
        Assert.Contains("Baz.Qux", html);
    }

    [Fact]
    public void GenerateHtml_SecurityBudgetEmpty_RendersEmptyState()
    {
        var gen = CreateGenerator();
        var report = CreateMinimalReport();
        var budget = new SecurityBudgetResult
        {
            Items = [],
            TotalRiskScore = 0,
            HighROIRiskReduction = 0,
            HighROIPercentage = 0,
        };
        gen.SetSecurityBudget(budget);

        var html = gen.GenerateHtml(report);

        Assert.Contains("id=\"security-budget\"", html);
        Assert.Contains("No remediation items to prioritize", html);
    }

    [Fact]
    public void GenerateHtml_SecurityBudgetWithMaintenanceItems_RendersActionText()
    {
        var gen = CreateGenerator();
        var report = CreateMinimalReport();
        gen.SetSecurityBudget(new SecurityBudgetResult
        {
            Items =
            [
                new TieredRemediationItem
                {
                    Item = new RemediationRoadmapItem
                    {
                        PackageId = "OldPkg",
                        CurrentVersion = "1.0.0",
                        Effort = UpgradeEffort.Major,
                        PriorityScore = 200,
                        Reason = RemediationReason.Deprecated,
                        ActionText = "Replace deprecated package",
                    },
                    Tier = RemediationTier.HighROI,
                    RoiScore = 67,
                    CumulativeRiskReductionPercent = 100,
                },
            ],
            TotalRiskScore = 200,
            HighROIRiskReduction = 200,
            HighROIPercentage = 100,
        });

        var html = gen.GenerateHtml(report);

        Assert.Contains("Replace deprecated package", html);
        Assert.Contains("\u2014", html); // Em-dash for 0 CVEs
    }

    // --- Dashboard Sections: Policy Violations ---

    [Fact]
    public void GenerateHtml_PolicyViolations_RendersViolationTable()
    {
        var gen = CreateGenerator();
        var report = CreateMinimalReport();
        var policyResult = new PolicyEvaluationResult(
        [
            new PolicyViolation("license-blocked", "Evil.Pkg uses GPL-3.0 which is blocked", "Art. 10(9)", "Replace with MIT-licensed alternative", null, PolicySeverity.Block),
        ], ExitCode: 2);
        gen.SetPolicyEvaluation(policyResult);

        var html = gen.GenerateHtml(report);

        Assert.Contains("id=\"policy-violations\"", html);
        Assert.Contains("license-blocked", html);
        Assert.Contains("Evil.Pkg uses GPL-3.0 which is blocked", html);
        Assert.Contains("BLOCK", html);
    }

    [Fact]
    public void GenerateHtml_NoPolicyConfigured_HidesPolicySection()
    {
        var gen = CreateGenerator();
        var report = CreateMinimalReport();
        // No SetPolicyEvaluation called

        var html = gen.GenerateHtml(report);

        Assert.DoesNotContain("id=\"policy-violations\"", html);
    }

    [Fact]
    public void GenerateHtml_PolicyConfiguredNoViolations_RendersEmptySuccess()
    {
        var gen = CreateGenerator();
        var report = CreateMinimalReport();
        var policyResult = new PolicyEvaluationResult([], ExitCode: 0);
        gen.SetPolicyEvaluation(policyResult);

        var html = gen.GenerateHtml(report);

        Assert.Contains("id=\"policy-violations\"", html);
        Assert.Contains("No policy violations found", html);
    }

    // --- Risk Badge Rendering ---

    [Fact]
    public void GenerateHtml_RoadmapWithRiskAssessment_RendersRiskBadge()
    {
        var gen = CreateGenerator();
        var report = CreateMinimalReport();
        gen.SetRemediationRoadmap(new List<RemediationRoadmapItem>
        {
            new RemediationRoadmapItem
            {
                PackageId = "RiskyPkg",
                CurrentVersion = "1.0.0",
                RecommendedVersion = "2.0.0",
                Effort = UpgradeEffort.Major,
                PriorityScore = 500,
                CveCount = 2,
                CveIds = ["CVE-2024-0001", "CVE-2024-0002"],
                ScoreLift = 5,
                UpgradeTiers =
                [
                    new UpgradeTier("2.0.0", UpgradeEffort.Major, 2, 2, true),
                ],
                TierRiskAssessments = new Dictionary<string, UpgradeRiskAssessment>
                {
                    ["2.0.0"] = new(65, UpgradeRiskLevel.High, 3, 1,
                        ["Major version bump", "3 breaking changes"], 8, TimeSpan.FromDays(400))
                },
            }
        });

        var html = gen.GenerateHtml(report);

        Assert.Contains("risk-badge high", html);
        Assert.Contains("65/100", html);
    }

    [Fact]
    public void GenerateHtml_RoadmapWithoutRiskAssessment_RendersRiskHeader()
    {
        var gen = CreateGenerator();
        var report = CreateMinimalReport();
        gen.SetRemediationRoadmap(new List<RemediationRoadmapItem>
        {
            new RemediationRoadmapItem
            {
                PackageId = "NormalPkg",
                CurrentVersion = "1.0.0",
                RecommendedVersion = "1.0.1",
                Effort = UpgradeEffort.Patch,
                PriorityScore = 100,
                CveCount = 1,
                CveIds = ["CVE-2024-0001"],
                ScoreLift = 2,
                UpgradeTiers = [new UpgradeTier("1.0.1", UpgradeEffort.Patch, 1, 1, true)],
                // TierRiskAssessments is null (no GitHub repo)
            }
        });

        var html = gen.GenerateHtml(report);

        Assert.Contains("<th>Risk</th>", html);
    }

    // --- Helper ---

    private static CraComplianceItem MakeItem(string requirement, CraComplianceStatus status) => new()
    {
        Requirement = requirement,
        Description = "Test description",
        Status = status,
        Evidence = "Test evidence",
    };

    private static CraReportGenerator CreateGenerator() => new();

    private static CraReport CreateMinimalReport() => new()
    {
        GeneratedAt = DateTime.UtcNow,
        ProjectPath = "TestProject.csproj",
        HealthScore = 80,
        HealthStatus = HealthStatus.Healthy,
        ComplianceItems =
        [
            MakeItem("CRA Art. 10 - Software Bill of Materials", CraComplianceStatus.Compliant),
        ],
        OverallComplianceStatus = CraComplianceStatus.Compliant,
        Sbom = new SbomDocument
        {
            SpdxId = "SPDXRef-DOCUMENT",
            Name = "TestProject",
            DocumentNamespace = "https://example.com/test",
            CreationInfo = new SbomCreationInfo
            {
                Created = DateTime.UtcNow.ToString("O"),
                Creators = ["Tool: DepSafe"],
            },
            Packages = [new SbomPackage { SpdxId = "SPDXRef-RootPackage", Name = "TestProject", VersionInfo = "1.0.0", DownloadLocation = "NOASSERTION" }],
            Relationships = [],
        },
        Vex = new VexDocument
        {
            Id = "https://example.com/vex",
            Author = "Test",
            Timestamp = DateTime.UtcNow.ToString("O"),
            Statements = [],
        },
        PackageCount = 1,
        TransitivePackageCount = 0,
        VulnerabilityCount = 0,
        CriticalPackageCount = 0,
    };
}
