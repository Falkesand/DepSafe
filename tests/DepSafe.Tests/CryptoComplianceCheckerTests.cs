using DepSafe.Compliance;

namespace DepSafe.Tests;

public class CryptoComplianceCheckerTests
{
    [Fact]
    public void Check_EmptyPackages_ReturnsCompliant()
    {
        var result = CryptoComplianceChecker.Check([]);

        Assert.True(result.IsCompliant);
        Assert.Empty(result.Issues);
        Assert.Empty(result.CryptoPackagesFound);
    }

    [Fact]
    public void Check_SafePackages_ReturnsCompliant()
    {
        var packages = new List<(string packageId, string version)>
        {
            ("Newtonsoft.Json", "13.0.3"),
            ("Serilog", "4.0.0"),
        };

        var result = CryptoComplianceChecker.Check(packages);

        Assert.True(result.IsCompliant);
        Assert.Empty(result.Issues);
        Assert.Empty(result.CryptoPackagesFound);
    }

    [Theory]
    [InlineData("MD5CryptoServiceProvider", "MD5")]
    [InlineData("SHA1CryptoServiceProvider", "SHA-1")]
    [InlineData("DESCryptoServiceProvider", "DES")]
    [InlineData("TripleDESCryptoServiceProvider", "3DES")]
    [InlineData("System.Security.Cryptography.RijndaelManaged", "Aes")]
    [InlineData("BouncyCastle", "1.8.9")]
    public void Check_DeprecatedPackage_ReturnsIssue(string packageId, string expectedSubstring)
    {
        var packages = new List<(string packageId, string version)>
        {
            (packageId, "1.0.0"),
        };

        var result = CryptoComplianceChecker.Check(packages);

        Assert.False(result.IsCompliant);
        Assert.Single(result.Issues);
        Assert.Equal(packageId, result.Issues[0].PackageId);
        Assert.Contains(expectedSubstring, result.Issues[0].Issue);
        Assert.Equal("Warning", result.Issues[0].Severity);
    }

    [Fact]
    public void Check_CryptoRelatedPackage_ReportedButNotIssue()
    {
        var packages = new List<(string packageId, string version)>
        {
            ("System.Security.Cryptography.Algorithms", "4.3.0"),
        };

        var result = CryptoComplianceChecker.Check(packages);

        Assert.True(result.IsCompliant);
        Assert.Empty(result.Issues);
        Assert.Single(result.CryptoPackagesFound);
        Assert.Equal("System.Security.Cryptography.Algorithms", result.CryptoPackagesFound[0]);
    }

    [Fact]
    public void Check_MultipleIssues_AllReported()
    {
        var packages = new List<(string packageId, string version)>
        {
            ("MD5CryptoServiceProvider", "1.0.0"),
            ("DESCryptoServiceProvider", "1.0.0"),
            ("SHA1CryptoServiceProvider", "1.0.0"),
        };

        var result = CryptoComplianceChecker.Check(packages);

        Assert.False(result.IsCompliant);
        Assert.Equal(3, result.Issues.Count);
    }

    [Fact]
    public void Check_CaseInsensitive_StillDetects()
    {
        var packages = new List<(string packageId, string version)>
        {
            ("md5cryptoserviceprovider", "1.0.0"),
        };

        var result = CryptoComplianceChecker.Check(packages);

        Assert.False(result.IsCompliant);
        Assert.Single(result.Issues);
    }

    [Fact]
    public void Check_DeprecatedPackage_SetsIsCompliantFalse()
    {
        var packages = new List<(string packageId, string version)>
        {
            ("RC2CryptoServiceProvider", "1.0.0"),
        };

        var result = CryptoComplianceChecker.Check(packages);

        Assert.False(result.IsCompliant);
    }

    [Fact]
    public void Check_CryptoRelatedOnly_StaysCompliant()
    {
        var packages = new List<(string packageId, string version)>
        {
            ("NSec.Cryptography", "0.7.0"),
            ("BCrypt.Net-Next", "4.0.0"),
            ("libsodium", "1.0.18"),
        };

        var result = CryptoComplianceChecker.Check(packages);

        Assert.True(result.IsCompliant);
        Assert.Empty(result.Issues);
        Assert.Equal(3, result.CryptoPackagesFound.Count);
    }

    [Fact]
    public void Check_PackageInBothLists_ReportsIssueAndCryptoFound()
    {
        // Portable.BouncyCastle is in BOTH DeprecatedCryptoPackages AND CryptoRelatedPackages
        var packages = new List<(string packageId, string version)>
        {
            ("Portable.BouncyCastle", "1.7.0"),
        };

        var result = CryptoComplianceChecker.Check(packages);

        Assert.False(result.IsCompliant);
        Assert.Single(result.Issues);
        Assert.Single(result.CryptoPackagesFound);
    }

    [Fact]
    public void Check_VersionPreservedInIssue()
    {
        var packages = new List<(string packageId, string version)>
        {
            ("DESCryptoServiceProvider", "2.5.1"),
        };

        var result = CryptoComplianceChecker.Check(packages);

        Assert.Equal("2.5.1", result.Issues[0].Version);
    }
}
