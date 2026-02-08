using System.Text.Json;
using DepSafe.DataSources;
using DepSafe.Models;

namespace DepSafe.Tests;

public class GitHubApiClientTests
{
    [Fact]
    public void ParseGitHubUrl_HttpsUrl_ReturnsOwnerAndRepo()
    {
        var (owner, repo) = GitHubApiClient.ParseGitHubUrl("https://github.com/owner/repo");

        Assert.Equal("owner", owner);
        Assert.Equal("repo", repo);
    }

    [Fact]
    public void ParseGitHubUrl_SshUrl_ReturnsOwnerAndRepo()
    {
        var (owner, repo) = GitHubApiClient.ParseGitHubUrl("git@github.com:owner/repo");

        Assert.Equal("owner", owner);
        Assert.Equal("repo", repo);
    }

    [Fact]
    public void ParseGitHubUrl_DotGitSuffix_StripsIt()
    {
        var (owner, repo) = GitHubApiClient.ParseGitHubUrl("https://github.com/owner/repo.git");

        Assert.Equal("owner", owner);
        Assert.Equal("repo", repo);
    }

    [Fact]
    public void ParseGitHubUrl_ExtraPathSegments_StillParses()
    {
        var (owner, repo) = GitHubApiClient.ParseGitHubUrl("https://github.com/owner/repo/tree/main");

        Assert.Equal("owner", owner);
        Assert.Equal("repo", repo);
    }

    [Fact]
    public void ParseGitHubUrl_InvalidUrl_ReturnsNullTuple()
    {
        var (owner, repo) = GitHubApiClient.ParseGitHubUrl("https://example.com/foo");

        Assert.Null(owner);
        Assert.Null(repo);
    }

    [Fact]
    public void ParseGitHubUrl_EmptyString_ReturnsNullTuple()
    {
        var (owner, repo) = GitHubApiClient.ParseGitHubUrl("");

        Assert.Null(owner);
        Assert.Null(repo);
    }

    [Fact]
    public void SanitizeGraphQLString_CleanString_ReturnsSame()
    {
        var input = "hello";

        var result = GitHubApiClient.SanitizeGraphQLString(input);

        Assert.Same(input, result);
    }

    [Fact]
    public void SanitizeGraphQLString_Quotes_AreEscaped()
    {
        var result = GitHubApiClient.SanitizeGraphQLString("say \"hello\"");

        Assert.Equal("say \\\"hello\\\"", result);
    }

    [Fact]
    public void SanitizeGraphQLString_Backslashes_AreEscaped()
    {
        var result = GitHubApiClient.SanitizeGraphQLString("path\\to\\file");

        Assert.Equal("path\\\\to\\\\file", result);
    }

    [Fact]
    public void SanitizeGraphQLString_Newlines_AreEscaped()
    {
        var result = GitHubApiClient.SanitizeGraphQLString("line1\nline2\rline3\tline4");

        Assert.Equal("line1\\nline2\\rline3\\tline4", result);
    }

    [Fact]
    public void SanitizeGraphQLString_AllSpecialChars_AreEscaped()
    {
        var result = GitHubApiClient.SanitizeGraphQLString("\\\"\n\r\t");

        Assert.Equal("\\\\\\\"\\n\\r\\t", result);
    }

    [Fact]
    public void SanitizeGraphQLString_EmptyString_ReturnsEmpty()
    {
        var result = GitHubApiClient.SanitizeGraphQLString("");

        Assert.Equal("", result);
    }

    [Fact]
    public void ParseRepoFromGraphQL_FullJson_ReturnsAllFields()
    {
        using var doc = JsonDocument.Parse("""
        {
            "stargazerCount": 1500,
            "forkCount": 200,
            "isArchived": false,
            "isFork": false,
            "issues": { "totalCount": 42 },
            "pushedAt": "2025-12-01T10:00:00Z",
            "defaultBranchRef": {
                "target": {
                    "history": {
                        "nodes": [
                            { "committedDate": "2025-12-15T14:30:00Z" }
                        ]
                    }
                }
            },
            "licenseInfo": { "spdxId": "MIT" },
            "securityPolicy": { "url": "https://example.com/SECURITY.md" }
        }
        """);

        var info = GitHubApiClient.ParseRepoFromGraphQL(doc.RootElement, "testowner", "testrepo");

        Assert.Equal("testowner", info.Owner);
        Assert.Equal("testrepo", info.Name);
        Assert.Equal("testowner/testrepo", info.FullName);
        Assert.Equal(1500, info.Stars);
        Assert.Equal(200, info.Forks);
        Assert.Equal(42, info.OpenIssues);
        Assert.False(info.IsArchived);
        Assert.False(info.IsFork);
        Assert.Equal("MIT", info.License);
        Assert.True(info.HasSecurityPolicy);
        Assert.Equal(0, info.CommitsLastYear);
        Assert.Equal(new DateTime(2025, 12, 1, 10, 0, 0, DateTimeKind.Utc), info.LastPushDate.ToUniversalTime());
        Assert.Equal(new DateTime(2025, 12, 15, 14, 30, 0, DateTimeKind.Utc), info.LastCommitDate.ToUniversalTime());
    }

    [Fact]
    public void ParseRepoFromGraphQL_MissingOptionalFields_SetsDefaults()
    {
        using var doc = JsonDocument.Parse("{}");

        var info = GitHubApiClient.ParseRepoFromGraphQL(doc.RootElement, "owner", "repo");

        Assert.Equal("owner", info.Owner);
        Assert.Equal("repo", info.Name);
        Assert.Equal("owner/repo", info.FullName);
        Assert.Equal(0, info.Stars);
        Assert.Equal(0, info.Forks);
        Assert.Equal(0, info.OpenIssues);
        Assert.False(info.IsArchived);
        Assert.False(info.IsFork);
        Assert.Null(info.License);
        Assert.False(info.HasSecurityPolicy);
        Assert.Equal(DateTime.MinValue, info.LastPushDate);
        Assert.Equal(DateTime.MinValue, info.LastCommitDate);
    }

    [Fact]
    public void ParseRepoFromGraphQL_ArchivedRepo_SetsFlag()
    {
        using var doc = JsonDocument.Parse("""
        {
            "isArchived": true,
            "stargazerCount": 50,
            "forkCount": 5
        }
        """);

        var info = GitHubApiClient.ParseRepoFromGraphQL(doc.RootElement, "org", "old-lib");

        Assert.True(info.IsArchived);
        Assert.Equal("org", info.Owner);
        Assert.Equal("old-lib", info.Name);
        Assert.Equal(50, info.Stars);
        Assert.Equal(5, info.Forks);
    }

    [Fact]
    public void ParseVulnerabilityFromGraphQL_CompleteAdvisory_ReturnsVuln()
    {
        using var doc = JsonDocument.Parse("""
        {
            "advisory": {
                "ghsaId": "GHSA-1234-abcd-5678",
                "severity": "HIGH",
                "summary": "SQL injection in query parser",
                "description": "A vulnerability allows SQL injection via untrusted input.",
                "identifiers": [
                    { "type": "CVE", "value": "CVE-2025-12345" },
                    { "type": "GHSA", "value": "GHSA-1234-abcd-5678" },
                    { "type": "CVE", "value": "CVE-2025-12346" }
                ],
                "permalink": "https://github.com/advisories/GHSA-1234-abcd-5678",
                "publishedAt": "2025-06-15T08:00:00Z"
            },
            "firstPatchedVersion": { "identifier": "2.1.0" },
            "vulnerableVersionRange": ">= 1.0.0, < 2.1.0"
        }
        """);

        var vuln = GitHubApiClient.ParseVulnerabilityFromGraphQL(doc.RootElement, "Contoso.Data");

        Assert.NotNull(vuln);
        Assert.Equal("GHSA-1234-abcd-5678", vuln.Id);
        Assert.Equal("HIGH", vuln.Severity);
        Assert.Equal("SQL injection in query parser", vuln.Summary);
        Assert.Equal("A vulnerability allows SQL injection via untrusted input.", vuln.Description);
        Assert.Equal("Contoso.Data", vuln.PackageId);
        Assert.Equal(">= 1.0.0, < 2.1.0", vuln.VulnerableVersionRange);
        Assert.Equal("2.1.0", vuln.PatchedVersion);
        Assert.Equal(2, vuln.Cves.Count);
        Assert.Contains("CVE-2025-12345", vuln.Cves);
        Assert.Contains("CVE-2025-12346", vuln.Cves);
        Assert.Equal("https://github.com/advisories/GHSA-1234-abcd-5678", vuln.Url);
        Assert.Equal(new DateTime(2025, 6, 15, 8, 0, 0, DateTimeKind.Utc), vuln.PublishedAt!.Value.ToUniversalTime());
    }

    [Fact]
    public void ParseVulnerabilityFromGraphQL_MinimalAdvisory_StillParses()
    {
        using var doc = JsonDocument.Parse("""
        {
            "advisory": {
                "ghsaId": "GHSA-0000-0000-0000",
                "severity": "LOW"
            }
        }
        """);

        var vuln = GitHubApiClient.ParseVulnerabilityFromGraphQL(doc.RootElement, "SomePackage");

        Assert.NotNull(vuln);
        Assert.Equal("GHSA-0000-0000-0000", vuln.Id);
        Assert.Equal("LOW", vuln.Severity);
        Assert.Equal("", vuln.Summary);
        Assert.Null(vuln.Description);
        Assert.Equal("SomePackage", vuln.PackageId);
        Assert.Equal("", vuln.VulnerableVersionRange);
        Assert.Null(vuln.PatchedVersion);
        Assert.Empty(vuln.Cves);
        Assert.Null(vuln.Url);
        Assert.Null(vuln.PublishedAt);
    }

    [Fact]
    public void HasToken_WithToken_ReturnsTrue()
    {
        using var client = new GitHubApiClient(token: "test-token");

        Assert.True(client.HasToken);
    }
}
