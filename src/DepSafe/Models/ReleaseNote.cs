namespace DepSafe.Models;

public sealed record ReleaseNote(
    string TagName,
    string? Body,
    DateTime PublishedAt);
