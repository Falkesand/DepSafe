# Design: Maintainer Trust Score (Phase 2.2)

## Problem

DepSafe's health score measures package quality (freshness, cadence, downloads, vulnerabilities) but says nothing about the people behind the package. A package can score 85/100 health while having a single anonymous maintainer, no release diversity, and zero community infrastructure. The CRA requires "due diligence" on third-party components (Art. 13(5)), but the current check only uses the health score — it misses maintainer reliability signals like bus factor, release discipline, and community engagement.

## Solution

Add a separate **Maintainer Trust Score (0-100)** computed from data already available in the existing GitHub GraphQL batch query (extended with 4 new fields, zero extra API calls). The score appears as a new column in the package health table, feeds into a new CRA compliance item, and strengthens the audit simulation's Art. 13(5) check.

## Data Collection

### GraphQL Query Extension

Add to the existing `GetRepositoriesBatchAsync` query inside each `repo{i}` block:

```graphql
mentionableUsers { totalCount }
releases(last: 5, orderBy: {field: CREATED_AT, direction: DESC}) {
  totalCount
  nodes { createdAt tagName author { login } }
}
defaultBranchRef {
  target {
    ... on Commit {
      history(first: 0) { totalCount }
    }
  }
}
```

This gives per-repo:
- **Contributor count** (`mentionableUsers.totalCount`)
- **Total commits** (`history.totalCount`)
- **Total releases** (`releases.totalCount`)
- **Last 5 releases** with dates and author logins

Zero additional API calls. Same batch. Same rate limit budget.

### GitHubRepoInfo Model Additions

```csharp
// Existing file: src/DepSafe/Models/GitHubRepoInfo.cs
public int ContributorCount { get; init; }
public int TotalCommits { get; init; }
public int TotalReleases { get; init; }
public List<ReleaseInfo> RecentReleases { get; init; } = [];
```

```csharp
// New file: src/DepSafe/Models/ReleaseInfo.cs
public sealed record ReleaseInfo(string TagName, DateTime CreatedAt, string? AuthorLogin);
```

## Models

### MaintainerTrustTier

```csharp
// File: src/DepSafe/Models/MaintainerTrustTier.cs
public enum MaintainerTrustTier { Critical, Low, Moderate, High }
```

### MaintainerTrust

```csharp
// File: src/DepSafe/Models/MaintainerTrust.cs
public sealed record MaintainerTrust(
    int Score,
    MaintainerTrustTier Tier,
    int ContributorCount,
    int TotalCommits,
    int TotalReleases,
    int ReleaseAuthorCount,
    string? TopReleaseAuthor);
```

### PackageHealth Addition

```csharp
// Existing file: src/DepSafe/Models/PackageHealth.cs
public MaintainerTrust? MaintainerTrust { get; init; }  // null when no GitHub data
```

## Algorithm (MaintainerTrustCalculator)

Static class in `src/DepSafe/Scoring/MaintainerTrustCalculator.cs`. Five weighted factors:

### Factors

| Factor | Weight | Signal | Scoring |
|--------|--------|--------|---------|
| Bus Factor | 30% | Contributor count | 1 = 20, 2 = 50, 3-4 = 75, 5+ = 100 |
| Activity Continuity | 25% | Last commit recency + archived status | <30d = 100, <90d = 80, <180d = 60, <365d = 40, >365d = 10. Archived = 0 |
| Release Discipline | 20% | Release frequency + author diversity | ReleasesPerYear score + penalty if single author did all of last 5 releases |
| Community Health | 15% | Stars, forks, issue ratio | Stars log-scaled (10k+ = 100, 1k+ = 80, 100+ = 60, 10+ = 40, <10 = 20). Issue/star ratio > 0.5 = penalty |
| Security Posture | 10% | Maintenance infrastructure | SECURITY.md (+50), not archived (+30), has license (+20) |

### Tier Mapping

| Score Range | Tier | Badge Color |
|-------------|------|-------------|
| 80-100 | High | Green (--success) |
| 60-79 | Moderate | Blue (--info or similar) |
| 40-59 | Low | Orange (#e67e22) |
| 0-39 | Critical | Red (--danger) |

### Method Signature

```csharp
public static MaintainerTrust? Calculate(
    GitHubRepoInfo? repoInfo,
    PackageMetrics metrics);
```

Returns `null` when `repoInfo` is null (no GitHub data available, e.g., `--skip-github`).

## CRA Integration

### New Compliance Item

**"Art. 13(5) — Maintainer Trust"** (weight 8)

- **Compliant:** All direct dependencies have trust score >= 60
- **ActionRequired:** Any direct dependency has trust score 40-59 (Low tier)
- **NonCompliant:** Any direct dependency has trust score < 40 (Critical tier)
- **Review:** When `--skip-github` and no trust data available

This is distinct from the existing Art. 13(5) check which uses health score. The new item specifically addresses supply chain due diligence on maintainer reliability.

Total compliance items: 18 → 19.

### Audit Simulation Enhancement

Add to AuditSimulator a parallel Art. 13(5) check: trust score < 40 triggers a High audit finding: "Art. 13(5) — Insufficient maintainer due diligence." Separate from the health-based Check 5.

### CI/CD

No new threshold flags. Trust feeds through the existing pipeline:
- CRA compliance item affects CRA readiness score → gated by `FailOnCraScoreBelow`
- Audit simulation finding → gated by `--audit-mode` + existing violation pipeline

## Report Rendering

### Package Table

New "Trust" column after the existing "Health" column. Shows score as colored badge matching tier. Packages without GitHub data show "\u2014" (em dash).

### Summary Section

"Maintainer Trust" summary card showing:
- Distribution bar: X High, Y Moderate, Z Low, W Critical
- Bottom 5 lowest-trust packages with contributor count and last activity date
- Average trust score across all packages with GitHub data

### Navigation

"Maintainer Trust" nav item in sidebar, always visible when data exists.

## Data Flow

```
CraReportCommand
  → GitHubApiClient.GetRepositoriesBatchAsync() (extended GraphQL)
  → GitHubRepoInfo now includes contributor/release data
  → MaintainerTrustCalculator.Calculate(repoInfo, metrics) per package
  → PackageHealth.MaintainerTrust populated
  → reportGenerator.SetMaintainerTrustSummary(trust data)
  → CRA compliance item evaluated
  → If audit mode: AuditSimulator checks trust scores
  → HTML report renders trust column + summary section
```

## Scope

### In scope
- Extend GraphQL query with 4 new fields (zero extra API calls)
- ReleaseInfo record, MaintainerTrust record, MaintainerTrustTier enum
- MaintainerTrustCalculator with 5 weighted factors
- PackageHealth.MaintainerTrust property
- Trust column in package table
- Summary section with distribution and bottom-5 list
- New CRA compliance item (Art. 13(5) Maintainer Trust)
- Audit simulation check for trust < 40
- Unit tests for calculator, parsing, compliance, audit

### Out of scope (YAGNI)
- Separate REST API calls for full contributor lists
- npm registry maintainer fetching
- Ownership transfer detection (requires historical data)
- Release signing key change detection
- Maintainer affiliation / company tracking
- Dedicated CI/CD threshold flag for trust score

## Testing

Unit tests in `MaintainerTrustCalculatorTests.cs`:

1. Single contributor → low bus factor score
2. Five+ contributors → high bus factor score
3. Archived repo → activity continuity = 0
4. Recent commit (<30d) → full activity score
5. Stale commit (>365d) → low activity score
6. Single release author across 5 releases → release discipline penalty
7. Multiple release authors → no penalty
8. High stars + low issue ratio → good community health
9. No security policy → security posture penalty
10. Full clean inputs → high trust score (>= 80)
11. Tier boundary: score 39 → Critical, 40 → Low, 59 → Low, 60 → Moderate, 79 → Moderate, 80 → High
12. Null repoInfo → returns null

GitHubApiClient parsing tests:
13. Parse mentionableUsers.totalCount → ContributorCount
14. Parse releases → TotalReleases + RecentReleases
15. Missing new fields → graceful defaults

CRA integration tests:
16. Trust < 40 → compliance item NonCompliant
17. Trust >= 40 → compliance item Compliant
18. Audit simulator: trust < 40 → High finding
