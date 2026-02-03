using NuGetHealthAnalyzer.Scoring;

namespace NuGetHealthAnalyzer.Tests;

public class ScoreWeightsTests
{
    [Fact]
    public void Default_SumsToOne()
    {
        var weights = ScoreWeights.Default;
        Assert.True(weights.IsValid());
    }

    [Fact]
    public void Default_HasExpectedWeights()
    {
        var weights = ScoreWeights.Default;

        Assert.Equal(0.25, weights.Freshness);
        Assert.Equal(0.15, weights.ReleaseCadence);
        Assert.Equal(0.20, weights.DownloadTrend);
        Assert.Equal(0.25, weights.RepositoryActivity);
        Assert.Equal(0.15, weights.Vulnerabilities);
    }

    [Fact]
    public void IsValid_ValidWeights_ReturnsTrue()
    {
        var weights = new ScoreWeights
        {
            Freshness = 0.20,
            ReleaseCadence = 0.20,
            DownloadTrend = 0.20,
            RepositoryActivity = 0.20,
            Vulnerabilities = 0.20
        };

        Assert.True(weights.IsValid());
    }

    [Fact]
    public void IsValid_InvalidWeights_ReturnsFalse()
    {
        var weights = new ScoreWeights
        {
            Freshness = 0.50,
            ReleaseCadence = 0.50,
            DownloadTrend = 0.50,
            RepositoryActivity = 0.50,
            Vulnerabilities = 0.50
        };

        Assert.False(weights.IsValid());
    }
}
