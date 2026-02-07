using DepSafe.Compliance;

namespace DepSafe.Tests;

public class LicenseCompatibilityTests
{
    // ─── GetLicenseInfo ───

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void GetLicenseInfo_NullOrEmpty_ReturnsNull(string? input)
    {
        Assert.Null(LicenseCompatibility.GetLicenseInfo(input));
    }

    [Theory]
    [InlineData("MIT", "MIT", LicenseCategory.Permissive)]
    [InlineData("Apache-2.0", "Apache-2.0", LicenseCategory.Permissive)]
    [InlineData("GPL-3.0", "GPL-3.0", LicenseCategory.StrongCopyleft)]
    [InlineData("LGPL-3.0", "LGPL-3.0", LicenseCategory.WeakCopyleft)]
    [InlineData("CC0-1.0", "CC0-1.0", LicenseCategory.PublicDomain)]
    public void GetLicenseInfo_DirectSpdxId_ReturnsCorrectInfo(string input, string expectedId, LicenseCategory expectedCategory)
    {
        var info = LicenseCompatibility.GetLicenseInfo(input);

        Assert.NotNull(info);
        Assert.Equal(expectedId, info.Identifier);
        Assert.Equal(expectedCategory, info.Category);
    }

    [Theory]
    [InlineData("MIT License", "MIT")]
    [InlineData("Apache 2.0", "Apache-2.0")]
    [InlineData("BSD", "BSD-3-Clause")]
    [InlineData("GPLv3", "GPL-3.0")]
    public void GetLicenseInfo_AliasResolution_ReturnsCorrectLicense(string alias, string expectedId)
    {
        var info = LicenseCompatibility.GetLicenseInfo(alias);

        Assert.NotNull(info);
        Assert.Equal(expectedId, info.Identifier);
    }

    [Theory]
    [InlineData("something mit something", LicenseCategory.Permissive)]
    [InlineData("apache version 2.0 license", LicenseCategory.Permissive)]
    [InlineData("bsd style license", LicenseCategory.Permissive)]
    public void GetLicenseInfo_PartialMatch_ReturnsMatch(string input, LicenseCategory expectedCategory)
    {
        var info = LicenseCompatibility.GetLicenseInfo(input);

        Assert.NotNull(info);
        Assert.Equal(expectedCategory, info.Category);
    }

    [Fact]
    public void GetLicenseInfo_UnknownLicense_ReturnsNull()
    {
        Assert.Null(LicenseCompatibility.GetLicenseInfo("My Custom Proprietary License v42"));
    }

    [Fact]
    public void GetLicenseInfo_SpdxOrExpression_ReturnsMostPermissive()
    {
        var info = LicenseCompatibility.GetLicenseInfo("(MIT OR GPL-3.0)");

        Assert.NotNull(info);
        // MIT is Permissive which is more permissive than GPL StrongCopyleft
        Assert.Equal(LicenseCategory.Permissive, info.Category);
    }

    [Fact]
    public void GetLicenseInfo_SpdxAndExpression_ReturnsMostRestrictive()
    {
        var info = LicenseCompatibility.GetLicenseInfo("MIT AND GPL-3.0");

        Assert.NotNull(info);
        // GPL-3.0 is StrongCopyleft, more restrictive than MIT Permissive
        Assert.Equal(LicenseCategory.StrongCopyleft, info.Category);
    }

    [Fact]
    public void GetLicenseInfo_SpdxWithException_ReturnsBaseLicense()
    {
        var info = LicenseCompatibility.GetLicenseInfo("Apache-2.0 WITH LLVM-exception");

        Assert.NotNull(info);
        Assert.Equal(LicenseCategory.Permissive, info.Category);
        Assert.Contains("with exception", info.Name);
    }

    // ─── CheckCompatibility ───

    [Fact]
    public void CheckCompatibility_PermissiveDep_Compatible()
    {
        var result = LicenseCompatibility.CheckCompatibility("MIT", "Apache-2.0", "TestPkg");

        Assert.True(result.IsCompatible);
        Assert.Equal("Info", result.Severity);
    }

    [Fact]
    public void CheckCompatibility_StrongCopyleftDepWithPermissiveProject_Incompatible()
    {
        var result = LicenseCompatibility.CheckCompatibility("MIT", "GPL-3.0", "TestPkg");

        Assert.False(result.IsCompatible);
        Assert.Equal("Error", result.Severity);
    }

    [Fact]
    public void CheckCompatibility_GplDepWithGplProject_Compatible()
    {
        var result = LicenseCompatibility.CheckCompatibility("GPL-3.0", "GPL-3.0", "TestPkg");

        Assert.True(result.IsCompatible);
        Assert.Equal("Info", result.Severity);
    }

    [Fact]
    public void CheckCompatibility_WeakCopyleft_Warning()
    {
        var result = LicenseCompatibility.CheckCompatibility("MIT", "LGPL-3.0", "TestPkg");

        Assert.True(result.IsCompatible);
        Assert.Equal("Warning", result.Severity);
    }

    [Fact]
    public void CheckCompatibility_UnknownDep_Warning()
    {
        var result = LicenseCompatibility.CheckCompatibility("MIT", "SomeUnknownLicense-1.0", "TestPkg");

        Assert.True(result.IsCompatible); // Assume compatible but warn
        Assert.Equal("Warning", result.Severity);
    }

    [Fact]
    public void CheckCompatibility_AgplDep_Incompatible()
    {
        var result = LicenseCompatibility.CheckCompatibility("MIT", "AGPL-3.0", "TestPkg");

        Assert.False(result.IsCompatible);
        Assert.Equal("Error", result.Severity);
        Assert.Contains("copyleft", result.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void CheckCompatibility_PublicDomain_NoAttribution()
    {
        var result = LicenseCompatibility.CheckCompatibility("MIT", "CC0-1.0", "TestPkg");

        Assert.True(result.IsCompatible);
        Assert.Equal("Info", result.Severity);
        Assert.Null(result.Recommendation); // CC0 does not require attribution
    }

    [Fact]
    public void CheckCompatibility_PermissiveDep_RequiresAttribution()
    {
        var result = LicenseCompatibility.CheckCompatibility("MIT", "MIT", "TestPkg");

        Assert.True(result.IsCompatible);
        Assert.Contains("Attribution", result.Recommendation);
    }

    // ─── AnalyzeLicenses ───

    [Fact]
    public void AnalyzeLicenses_AllPermissive_Compatible()
    {
        var packages = new List<(string PackageId, string? License)>
        {
            ("PkgA", "MIT"),
            ("PkgB", "Apache-2.0"),
            ("PkgC", "BSD-3-Clause"),
        };

        var report = LicenseCompatibility.AnalyzeLicenses(packages, "MIT");

        Assert.Equal("Compatible", report.OverallStatus);
        Assert.Equal(0, report.ErrorCount);
        Assert.Equal(0, report.WarningCount);
        Assert.Equal(3, report.TotalPackages);
    }

    [Fact]
    public void AnalyzeLicenses_OneGpl_Incompatible()
    {
        var packages = new List<(string PackageId, string? License)>
        {
            ("PkgA", "MIT"),
            ("PkgB", "GPL-3.0"),
        };

        var report = LicenseCompatibility.AnalyzeLicenses(packages, "MIT");

        Assert.Equal("Incompatible", report.OverallStatus);
        Assert.Equal(1, report.ErrorCount);
    }

    [Fact]
    public void AnalyzeLicenses_UnknownLicense_ReviewRequired()
    {
        var packages = new List<(string PackageId, string? License)>
        {
            ("PkgA", "MIT"),
            ("PkgB", null),
        };

        var report = LicenseCompatibility.AnalyzeLicenses(packages, "MIT");

        Assert.Equal("Review Required", report.OverallStatus);
        Assert.Equal(1, report.WarningCount);
        Assert.Single(report.UnknownLicenses);
    }

    [Fact]
    public void AnalyzeLicenses_LicenseDistribution_Counted()
    {
        var packages = new List<(string PackageId, string? License)>
        {
            ("PkgA", "MIT"),
            ("PkgB", "MIT"),
            ("PkgC", "Apache-2.0"),
        };

        var report = LicenseCompatibility.AnalyzeLicenses(packages, "MIT");

        Assert.Equal(2, report.LicenseDistribution["MIT"]);
        Assert.Equal(1, report.LicenseDistribution["Apache-2.0"]);
    }

    [Fact]
    public void AnalyzeLicenses_CategoryDistribution_Counted()
    {
        var packages = new List<(string PackageId, string? License)>
        {
            ("PkgA", "MIT"),
            ("PkgB", "LGPL-3.0"),
        };

        var report = LicenseCompatibility.AnalyzeLicenses(packages, "MIT");

        Assert.Equal(1, report.CategoryDistribution[LicenseCategory.Permissive]);
        Assert.Equal(1, report.CategoryDistribution[LicenseCategory.WeakCopyleft]);
    }

    [Fact]
    public void AnalyzeLicenses_EmptyInput_Compatible()
    {
        var packages = new List<(string PackageId, string? License)>();

        var report = LicenseCompatibility.AnalyzeLicenses(packages, "MIT");

        Assert.Equal("Compatible", report.OverallStatus);
        Assert.Equal(0, report.TotalPackages);
    }

    [Fact]
    public void AnalyzeLicenses_UnknownLicenseList_Populated()
    {
        var packages = new List<(string PackageId, string? License)>
        {
            ("PkgA", "SomeWeirdLicense"),
            ("PkgB", null),
        };

        var report = LicenseCompatibility.AnalyzeLicenses(packages, "MIT");

        Assert.Equal(2, report.UnknownLicenses.Count);
        Assert.Contains(report.UnknownLicenses, u => u.Contains("PkgA"));
        Assert.Contains(report.UnknownLicenses, u => u.Contains("PkgB"));
    }
}
