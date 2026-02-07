using DepSafe.Models;
using DepSafe.Typosquatting;

namespace DepSafe.Tests;

public class PopularPackageIndexTests
{
    private static PopularPackageEntry CreateEntry(string name, long downloads = 1000) => new()
    {
        Name = name,
        NormalizedName = name.ToLowerInvariant(),
        HomoglyphNormalizedName = StringDistance.NormalizeHomoglyphs(name.ToLowerInvariant()),
        SeparatorNormalizedName = StringDistance.NormalizeSeparatorsCore(name.ToLowerInvariant()),
        Downloads = downloads,
        Ecosystem = PackageEcosystem.NuGet,
    };

    [Fact]
    public void Add_SingleEntry_CountIs1()
    {
        var index = new PopularPackageIndex();

        index.Add(CreateEntry("Newtonsoft.Json"));

        Assert.Equal(1, index.Count);
    }

    [Fact]
    public void Add_DuplicateName_CountStays1()
    {
        var index = new PopularPackageIndex();

        index.Add(CreateEntry("Newtonsoft.Json"));
        index.Add(CreateEntry("Newtonsoft.Json"));

        Assert.Equal(1, index.Count);
    }

    [Fact]
    public void AddRange_MultipleEntries_AllAdded()
    {
        var index = new PopularPackageIndex();
        var entries = new[]
        {
            CreateEntry("PackageA"),
            CreateEntry("PackageB"),
            CreateEntry("PackageC"),
        };

        index.AddRange(entries);

        Assert.Equal(3, index.Count);
    }

    [Fact]
    public void Contains_AddedName_ReturnsTrue()
    {
        var index = new PopularPackageIndex();
        index.Add(CreateEntry("Serilog"));

        Assert.True(index.Contains("Serilog"));
    }

    [Fact]
    public void Contains_CaseDifferent_ReturnsTrue()
    {
        var index = new PopularPackageIndex();
        index.Add(CreateEntry("Serilog"));

        Assert.True(index.Contains("serilog"));
        Assert.True(index.Contains("SERILOG"));
    }

    [Fact]
    public void Contains_NotAdded_ReturnsFalse()
    {
        var index = new PopularPackageIndex();
        index.Add(CreateEntry("Serilog"));

        Assert.False(index.Contains("NLog"));
    }

    [Fact]
    public void FindCandidates_SameLength_ReturnsCandidates()
    {
        var index = new PopularPackageIndex();
        // "lodash" is 6 chars, "lodesh" is 6 chars — same length bucket
        index.Add(CreateEntry("lodash"));

        var candidates = index.FindCandidates("lodesh").ToList();

        Assert.Single(candidates);
        Assert.Equal("lodash", candidates[0].Name);
    }

    [Fact]
    public void FindCandidates_Within2Chars_ReturnsCandidates()
    {
        var index = new PopularPackageIndex();
        // "axios" is 5 chars, "axiosss" is 7 chars — within +/-2
        index.Add(CreateEntry("axios"));

        var candidates = index.FindCandidates("axiosss").ToList();

        Assert.Single(candidates);
    }

    [Fact]
    public void FindCandidates_Beyond2Chars_ReturnsEmpty()
    {
        var index = new PopularPackageIndex();
        // "ax" is 2 chars, "axios" is 5 chars — difference of 3, beyond tolerance
        index.Add(CreateEntry("axios"));

        var candidates = index.FindCandidates("ax").ToList();

        Assert.Empty(candidates);
    }

    [Fact]
    public void Freeze_ContainsStillWorks()
    {
        var index = new PopularPackageIndex();
        index.Add(CreateEntry("Serilog"));
        index.Freeze();

        Assert.True(index.Contains("Serilog"));
        Assert.False(index.Contains("NLog"));
    }

    [Fact]
    public void Freeze_FindCandidatesStillWorks()
    {
        var index = new PopularPackageIndex();
        index.Add(CreateEntry("lodash"));
        index.Freeze();

        var candidates = index.FindCandidates("lodesh").ToList();

        Assert.Single(candidates);
    }

    [Fact]
    public void AllEntries_ReturnsAll()
    {
        var index = new PopularPackageIndex();
        index.Add(CreateEntry("A"));
        index.Add(CreateEntry("BB"));
        index.Add(CreateEntry("CCC"));

        var all = index.AllEntries.ToList();

        Assert.Equal(3, all.Count);
    }

    [Fact]
    public void Count_EmptyIndex_ReturnsZero()
    {
        var index = new PopularPackageIndex();

        Assert.Equal(0, index.Count);
    }

    [Fact]
    public void Add_MissingNormalizedFields_ComputesAutomatically()
    {
        var index = new PopularPackageIndex();
        // Only set Name — leave NormalizedName, HomoglyphNormalizedName, SeparatorNormalizedName empty
        var entry = new PopularPackageEntry
        {
            Name = "My.Package",
            Downloads = 500,
            Ecosystem = PackageEcosystem.NuGet,
        };

        index.Add(entry);

        Assert.Equal(1, index.Count);
        Assert.True(index.Contains("My.Package"));

        // Verify that the entry in AllEntries has computed fields
        var stored = index.AllEntries.Single();
        Assert.Equal("my.package", stored.NormalizedName);
        Assert.NotNull(stored.HomoglyphNormalizedName);
        Assert.NotNull(stored.SeparatorNormalizedName);
    }
}
