using System.Text.Json;
using DepSafe.DataSources;

namespace DepSafe.Tests;

public class EpssServiceTests
{
    [Fact]
    public void ParseResponse_ValidJson_ReturnsScores()
    {
        // Arrange
        var json = JsonSerializer.Deserialize<JsonElement>("""
        {
            "status": "OK",
            "status-code": 200,
            "version": "1.0",
            "total": 2,
            "offset": 0,
            "limit": 100,
            "data": [
                { "cve": "CVE-2021-44228", "epss": "0.975860000", "percentile": "0.999690000", "date": "2024-01-01" },
                { "cve": "CVE-2023-12345", "epss": "0.002340000", "percentile": "0.453200000", "date": "2024-01-01" }
            ]
        }
        """);

        // Act
        var scores = EpssService.ParseResponse(json);

        // Assert
        Assert.Equal(2, scores.Count);

        var log4j = scores.First(s => s.Cve == "CVE-2021-44228");
        Assert.Equal(0.97586, log4j.Probability, 5);
        Assert.Equal(0.99969, log4j.Percentile, 5);

        var other = scores.First(s => s.Cve == "CVE-2023-12345");
        Assert.Equal(0.00234, other.Probability, 5);
        Assert.Equal(0.4532, other.Percentile, 4);
    }

    [Fact]
    public void ParseResponse_NumericValues_ReturnsScores()
    {
        // EPSS API typically returns strings, but handle numbers too
        var json = JsonSerializer.Deserialize<JsonElement>("""
        {
            "data": [
                { "cve": "CVE-2024-0001", "epss": 0.5, "percentile": 0.9 }
            ]
        }
        """);

        var scores = EpssService.ParseResponse(json);

        Assert.Single(scores);
        Assert.Equal(0.5, scores[0].Probability);
        Assert.Equal(0.9, scores[0].Percentile);
    }

    [Fact]
    public void ParseResponse_EmptyData_ReturnsEmptyList()
    {
        var json = JsonSerializer.Deserialize<JsonElement>("""
        { "data": [] }
        """);

        var scores = EpssService.ParseResponse(json);

        Assert.Empty(scores);
    }

    [Fact]
    public void ParseResponse_MissingDataProperty_ReturnsEmptyList()
    {
        var json = JsonSerializer.Deserialize<JsonElement>("""
        { "status": "OK" }
        """);

        var scores = EpssService.ParseResponse(json);

        Assert.Empty(scores);
    }

    [Fact]
    public void ParseResponse_MissingCve_SkipsEntry()
    {
        var json = JsonSerializer.Deserialize<JsonElement>("""
        {
            "data": [
                { "epss": "0.5", "percentile": "0.9" },
                { "cve": "CVE-2024-0002", "epss": "0.1", "percentile": "0.5" }
            ]
        }
        """);

        var scores = EpssService.ParseResponse(json);

        Assert.Single(scores);
        Assert.Equal("CVE-2024-0002", scores[0].Cve);
    }

    [Fact]
    public void ParseResponse_NormalizesToUpperCase()
    {
        var json = JsonSerializer.Deserialize<JsonElement>("""
        {
            "data": [
                { "cve": "cve-2024-0001", "epss": "0.1", "percentile": "0.5" }
            ]
        }
        """);

        var scores = EpssService.ParseResponse(json);

        Assert.Equal("CVE-2024-0001", scores[0].Cve);
    }

    [Fact]
    public void ParseResponse_MissingEpssField_DefaultsToZero()
    {
        var json = JsonSerializer.Deserialize<JsonElement>("""
        {
            "data": [
                { "cve": "CVE-2024-0001", "percentile": "0.5" }
            ]
        }
        """);

        var scores = EpssService.ParseResponse(json);

        Assert.Single(scores);
        Assert.Equal(0, scores[0].Probability);
        Assert.Equal(0.5, scores[0].Percentile);
    }

    [Fact]
    public async Task GetScoresAsync_EmptyInput_ReturnsEmptyDictionary()
    {
        using var service = new EpssService();
        var result = await service.GetScoresAsync([]);
        Assert.Empty(result);
    }

    [Fact]
    public async Task GetScoresAsync_WhitespaceInput_ReturnsEmptyDictionary()
    {
        using var service = new EpssService();
        var result = await service.GetScoresAsync(["", " ", null!]);
        Assert.Empty(result);
    }
}
