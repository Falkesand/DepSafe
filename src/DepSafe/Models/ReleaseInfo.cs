namespace DepSafe.Models;

public sealed record ReleaseInfo(string TagName, DateTime CreatedAt, string? AuthorLogin);
