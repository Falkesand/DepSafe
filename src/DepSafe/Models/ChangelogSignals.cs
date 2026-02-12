namespace DepSafe.Models;

public sealed record ChangelogSignals(
    int BreakingChangeCount,
    int DeprecationCount,
    List<string> BreakingSnippets,
    List<string> DeprecationSnippets,
    int ReleaseCount);
