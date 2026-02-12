using System.Text.Json;
using DepSafe.DataSources;
using DepSafe.Models;

namespace DepSafe.Tests;

public class GitHubRepoInfoParsingTests
{
    [Fact]
    public void ParseRepoFromGraphQL_WithMaintainerFields_PopulatesNewProperties()
    {
        var json = JsonSerializer.Deserialize<JsonElement>("""
        {
            "nameWithOwner": "test/repo",
            "stargazerCount": 500,
            "forkCount": 50,
            "isArchived": false,
            "isFork": false,
            "pushedAt": "2026-02-01T00:00:00Z",
            "licenseInfo": { "spdxId": "MIT" },
            "issues": { "totalCount": 10 },
            "defaultBranchRef": {
                "target": {
                    "history": {
                        "nodes": [{ "committedDate": "2026-02-01T00:00:00Z" }],
                        "totalCount": 1234
                    }
                }
            },
            "securityPolicy": { "id": "abc" },
            "mentionableUsers": { "totalCount": 15 },
            "releases": {
                "totalCount": 42,
                "nodes": [
                    { "createdAt": "2026-01-15T00:00:00Z", "tagName": "v2.0.0", "author": { "login": "alice" } },
                    { "createdAt": "2026-01-01T00:00:00Z", "tagName": "v1.9.0", "author": { "login": "bob" } }
                ]
            }
        }
        """);

        var info = GitHubApiClient.ParseRepoFromGraphQL(json, "test", "repo");

        Assert.Equal(15, info.ContributorCount);
        Assert.Equal(1234, info.TotalCommits);
        Assert.Equal(42, info.TotalReleases);
        Assert.Equal(2, info.RecentReleases.Count);
        Assert.Equal("v2.0.0", info.RecentReleases[0].TagName);
        Assert.Equal("alice", info.RecentReleases[0].AuthorLogin);
    }

    [Fact]
    public void ParseRepoFromGraphQL_MissingNewFields_DefaultsToZeroAndEmpty()
    {
        var json = JsonSerializer.Deserialize<JsonElement>("""
        {
            "stargazerCount": 100,
            "forkCount": 10,
            "isArchived": false,
            "isFork": false,
            "pushedAt": "2026-01-01T00:00:00Z",
            "issues": { "totalCount": 5 },
            "defaultBranchRef": {
                "target": {
                    "history": {
                        "nodes": [{ "committedDate": "2026-01-01T00:00:00Z" }]
                    }
                }
            }
        }
        """);

        var info = GitHubApiClient.ParseRepoFromGraphQL(json, "owner", "repo");

        Assert.Equal(0, info.ContributorCount);
        Assert.Equal(0, info.TotalCommits);
        Assert.Equal(0, info.TotalReleases);
        Assert.Empty(info.RecentReleases);
    }

    [Fact]
    public void ParseRepoFromGraphQL_NullReleaseAuthor_HandlesGracefully()
    {
        var json = JsonSerializer.Deserialize<JsonElement>("""
        {
            "stargazerCount": 200,
            "forkCount": 20,
            "isArchived": false,
            "isFork": false,
            "pushedAt": "2026-01-01T00:00:00Z",
            "issues": { "totalCount": 3 },
            "releases": {
                "totalCount": 5,
                "nodes": [
                    { "createdAt": "2026-01-10T00:00:00Z", "tagName": "v1.0.0", "author": null }
                ]
            }
        }
        """);

        var info = GitHubApiClient.ParseRepoFromGraphQL(json, "owner", "repo");

        Assert.Single(info.RecentReleases);
        Assert.Equal("v1.0.0", info.RecentReleases[0].TagName);
        Assert.Null(info.RecentReleases[0].AuthorLogin);
    }
}
