using DepSafe.Compliance;
using DepSafe.Models;

namespace DepSafe.Tests;

public class LicensePolicyEvaluatorTests
{
    private static PackageHealth CreatePackage(
        string id = "TestPkg",
        string? license = "MIT") => new()
    {
        PackageId = id,
        Version = "1.0.0",
        Score = 80,
        Status = HealthStatus.Healthy,
        Metrics = new PackageMetrics { TotalDownloads = 1000 },
        License = license,
    };

    // --- AllowedLicenses tests ---

    [Fact]
    public void Evaluate_AllowedLicenses_AllowedPackage_NoViolation()
    {
        var packages = new List<PackageHealth> { CreatePackage(license: "MIT") };
        var config = new CraConfig { AllowedLicenses = ["MIT"] };

        var result = LicensePolicyEvaluator.Evaluate(packages, config);

        Assert.False(result.HasViolations);
    }

    [Fact]
    public void Evaluate_AllowedLicenses_DisallowedPackage_ReturnsViolation()
    {
        var packages = new List<PackageHealth> { CreatePackage(license: "GPL-3.0") };
        var config = new CraConfig { AllowedLicenses = ["MIT", "Apache-2.0"] };

        var result = LicensePolicyEvaluator.Evaluate(packages, config);

        Assert.True(result.HasViolations);
        Assert.Single(result.Violations);
        Assert.Equal("TestPkg", result.Violations[0].PackageId);
        Assert.Contains("GPL-3.0", result.Violations[0].License);
        Assert.Contains("not in allowed list", result.Violations[0].Reason);
    }

    [Fact]
    public void Evaluate_AllowedLicenses_CaseInsensitive()
    {
        var packages = new List<PackageHealth> { CreatePackage(license: "mit") };
        var config = new CraConfig { AllowedLicenses = ["MIT"] };

        var result = LicensePolicyEvaluator.Evaluate(packages, config);

        Assert.False(result.HasViolations);
    }

    [Fact]
    public void Evaluate_AllowedLicenses_SpdxOrExpression_PassesIfAnyConstituent()
    {
        var packages = new List<PackageHealth> { CreatePackage(license: "(MIT OR GPL-3.0)") };
        var config = new CraConfig { AllowedLicenses = ["MIT"] };

        var result = LicensePolicyEvaluator.Evaluate(packages, config);

        Assert.False(result.HasViolations);
    }

    [Fact]
    public void Evaluate_AllowedLicenses_SpdxOrExpression_FailsIfNoneAllowed()
    {
        var packages = new List<PackageHealth> { CreatePackage(license: "(GPL-2.0 OR GPL-3.0)") };
        var config = new CraConfig { AllowedLicenses = ["MIT", "Apache-2.0"] };

        var result = LicensePolicyEvaluator.Evaluate(packages, config);

        Assert.True(result.HasViolations);
    }

    [Fact]
    public void Evaluate_AllowedLicenses_EmptyConfig_NoViolations()
    {
        var packages = new List<PackageHealth> { CreatePackage(license: "GPL-3.0") };
        var config = new CraConfig { AllowedLicenses = [] };

        var result = LicensePolicyEvaluator.Evaluate(packages, config);

        Assert.False(result.HasViolations);
    }

    // --- BlockedLicenses tests ---

    [Fact]
    public void Evaluate_BlockedLicenses_BlockedPackage_ReturnsViolation()
    {
        var packages = new List<PackageHealth> { CreatePackage(license: "AGPL-3.0") };
        var config = new CraConfig { BlockedLicenses = ["AGPL-3.0", "GPL-3.0"] };

        var result = LicensePolicyEvaluator.Evaluate(packages, config);

        Assert.True(result.HasViolations);
        Assert.Single(result.Violations);
        Assert.Contains("blocked", result.Violations[0].Reason);
    }

    [Fact]
    public void Evaluate_BlockedLicenses_UnblockedPackage_NoViolation()
    {
        var packages = new List<PackageHealth> { CreatePackage(license: "MIT") };
        var config = new CraConfig { BlockedLicenses = ["GPL-3.0"] };

        var result = LicensePolicyEvaluator.Evaluate(packages, config);

        Assert.False(result.HasViolations);
    }

    // --- Precedence: AllowedLicenses takes precedence over BlockedLicenses ---

    [Fact]
    public void Evaluate_BothSet_AllowedTakesPrecedence()
    {
        var packages = new List<PackageHealth> { CreatePackage(license: "MIT") };
        var config = new CraConfig
        {
            AllowedLicenses = ["MIT"],
            BlockedLicenses = ["MIT"]
        };

        var result = LicensePolicyEvaluator.Evaluate(packages, config);

        // AllowedLicenses takes precedence — MIT is allowed
        Assert.False(result.HasViolations);
    }

    // --- Null/empty license handling ---

    [Fact]
    public void Evaluate_NullLicense_WithAllowedList_ReturnsViolation()
    {
        var packages = new List<PackageHealth> { CreatePackage(license: null) };
        var config = new CraConfig { AllowedLicenses = ["MIT"] };

        var result = LicensePolicyEvaluator.Evaluate(packages, config);

        Assert.True(result.HasViolations);
        Assert.Contains("unknown", result.Violations[0].Reason, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Evaluate_NullLicense_WithBlockedList_NoViolation()
    {
        var packages = new List<PackageHealth> { CreatePackage(license: null) };
        var config = new CraConfig { BlockedLicenses = ["GPL-3.0"] };

        var result = LicensePolicyEvaluator.Evaluate(packages, config);

        Assert.False(result.HasViolations);
    }

    // --- Multiple violations ---

    [Fact]
    public void Evaluate_MultipleViolations_AllReported()
    {
        var packages = new List<PackageHealth>
        {
            CreatePackage(id: "PkgA", license: "GPL-3.0"),
            CreatePackage(id: "PkgB", license: "MIT"),
            CreatePackage(id: "PkgC", license: "AGPL-3.0"),
        };
        var config = new CraConfig { AllowedLicenses = ["MIT", "Apache-2.0"] };

        var result = LicensePolicyEvaluator.Evaluate(packages, config);

        Assert.Equal(2, result.Violations.Count);
        Assert.Contains(result.Violations, v => v.PackageId == "PkgA");
        Assert.Contains(result.Violations, v => v.PackageId == "PkgC");
    }

    // --- SPDX normalization via alias ---

    [Fact]
    public void Evaluate_AllowedLicenses_SpdxNormalization()
    {
        // Package reports "Apache 2.0" which normalizes to "Apache-2.0"
        var packages = new List<PackageHealth> { CreatePackage(license: "Apache 2.0") };
        var config = new CraConfig { AllowedLicenses = ["Apache-2.0"] };

        var result = LicensePolicyEvaluator.Evaluate(packages, config);

        Assert.False(result.HasViolations);
    }

    [Fact]
    public void Evaluate_BlockedLicenses_SpdxNormalization()
    {
        // "GPLv3" normalizes to "GPL-3.0" which is blocked
        var packages = new List<PackageHealth> { CreatePackage(license: "GPLv3") };
        var config = new CraConfig { BlockedLicenses = ["GPL-3.0"] };

        var result = LicensePolicyEvaluator.Evaluate(packages, config);

        Assert.True(result.HasViolations);
    }

    // --- Mixed-case SPDX OR expression ---

    [Fact]
    public void Evaluate_AllowedLicenses_SpdxOrExpression_LowercaseOr()
    {
        var packages = new List<PackageHealth> { CreatePackage(license: "(MIT or GPL-3.0)") };
        var config = new CraConfig { AllowedLicenses = ["MIT"] };

        var result = LicensePolicyEvaluator.Evaluate(packages, config);

        Assert.False(result.HasViolations);
    }

    [Fact]
    public void Evaluate_AllowedLicenses_SpdxOrExpression_NoParentheses()
    {
        var packages = new List<PackageHealth> { CreatePackage(license: "MIT OR GPL-3.0") };
        var config = new CraConfig { AllowedLicenses = ["MIT"] };

        var result = LicensePolicyEvaluator.Evaluate(packages, config);

        Assert.False(result.HasViolations);
    }

    // --- No policy configured at all ---

    [Fact]
    public void Evaluate_NoPolicyConfigured_NoViolations()
    {
        var packages = new List<PackageHealth> { CreatePackage(license: "GPL-3.0") };
        var config = new CraConfig();

        var result = LicensePolicyEvaluator.Evaluate(packages, config);

        Assert.False(result.HasViolations);
    }
}
