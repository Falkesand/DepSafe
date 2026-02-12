namespace DepSafe.Models;

public sealed record MaintainerTrust(
    int Score,
    MaintainerTrustTier Tier,
    int ContributorCount,
    int TotalCommits,
    int TotalReleases,
    int ReleaseAuthorCount,
    string? TopReleaseAuthor);
