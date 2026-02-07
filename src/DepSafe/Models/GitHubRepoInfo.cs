namespace DepSafe.Models;

/// <summary>
/// Repository information from GitHub API.
/// </summary>
public sealed class GitHubRepoInfo
{
    public required string Owner { get; init; }
    public required string Name { get; init; }
    public required string FullName { get; init; }
    public required int Stars { get; init; }
    public required int OpenIssues { get; init; }
    public required int Forks { get; init; }
    public required DateTime LastCommitDate { get; init; }
    public required DateTime LastPushDate { get; init; }
    public bool IsArchived { get; init; }
    public bool IsFork { get; init; }
    public string? License { get; init; }
    public int CommitsLastYear { get; init; }

    /// <summary>Whether the repository has a SECURITY.md file (CRA Art. 11(5)).</summary>
    public bool HasSecurityPolicy { get; init; }
}
