using System.Reflection;
using DepSafe.DataSources;

namespace DepSafe.Tests;

public class CisaKevServiceTests : IDisposable
{
    private readonly CisaKevService _service;

    public CisaKevServiceTests()
    {
        _service = new CisaKevService();
    }

    /// <summary>
    /// Seeds the internal _kevCves field via reflection to avoid HTTP calls in tests.
    /// </summary>
    private void SeedKevData(params string[] cves)
    {
        var field = typeof(CisaKevService).GetField("_kevCves", BindingFlags.NonPublic | BindingFlags.Instance)!;
        var set = new HashSet<string>(cves, StringComparer.OrdinalIgnoreCase);
        field.SetValue(_service, set);
    }

    [Fact]
    public void IsKnownExploited_BeforeLoad_ReturnsFalse()
    {
        Assert.False(_service.IsKnownExploited("CVE-2024-0001"));
    }

    [Fact]
    public void IsKnownExploited_NullCveId_ReturnsFalse()
    {
        SeedKevData("CVE-2024-0001");

        Assert.False(_service.IsKnownExploited(null!));
    }

    [Fact]
    public void IsKnownExploited_EmptyCveId_ReturnsFalse()
    {
        SeedKevData("CVE-2024-0001");

        Assert.False(_service.IsKnownExploited(""));
    }

    [Fact]
    public void IsKnownExploited_KnownCve_ReturnsTrue()
    {
        SeedKevData("CVE-2024-0001", "CVE-2024-0002");

        Assert.True(_service.IsKnownExploited("CVE-2024-0001"));
    }

    [Fact]
    public void IsKnownExploited_UnknownCve_ReturnsFalse()
    {
        SeedKevData("CVE-2024-0001");

        Assert.False(_service.IsKnownExploited("CVE-2024-9999"));
    }

    [Fact]
    public void GetKnownExploitedCves_BeforeLoad_ReturnsEmpty()
    {
        var result = _service.GetKnownExploitedCves(["CVE-2024-0001", "CVE-2024-0002"]);

        Assert.Empty(result);
    }

    [Fact]
    public void GetKnownExploitedCves_MixedInput_ReturnsOnlyKnown()
    {
        SeedKevData("CVE-2024-0001", "CVE-2024-0003");

        var result = _service.GetKnownExploitedCves(["CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0003"]);

        Assert.Equal(2, result.Count);
        Assert.Contains("CVE-2024-0001", result);
        Assert.Contains("CVE-2024-0003", result);
        Assert.DoesNotContain("CVE-2024-0002", result);
    }

    [Fact]
    public void CatalogSize_BeforeLoad_ReturnsZero()
    {
        Assert.Equal(0, _service.CatalogSize);
    }

    [Fact]
    public void CatalogSize_AfterLoad_ReturnsCount()
    {
        SeedKevData("CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0003");

        Assert.Equal(3, _service.CatalogSize);
    }

    public void Dispose()
    {
        _service.Dispose();
    }
}
