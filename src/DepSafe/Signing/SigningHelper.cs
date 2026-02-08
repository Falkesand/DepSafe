using Spectre.Console;

namespace DepSafe.Signing;

/// <summary>
/// Shared orchestration for artifact signing across SbomCommand, VexCommand, and CraReportCommand.
/// Provides graceful degradation when sigil is not installed.
/// </summary>
public static class SigningHelper
{
    /// <summary>
    /// Check sigil availability and create a service instance.
    /// Returns null with a console warning if sigil is not installed.
    /// </summary>
    public static async Task<SigilService?> TryCreateAsync(CancellationToken ct)
    {
        var service = new SigilService();
        var result = await service.CheckAvailabilityAsync(ct);

        if (result.IsFailure)
        {
            AnsiConsole.MarkupLine("[yellow]Warning: sigil CLI not found. Artifact signing skipped.[/]");
            AnsiConsole.MarkupLine("[dim]Install sigil from https://github.com/Falkesand/Sigil.Sign[/]");
            return null;
        }

        AnsiConsole.MarkupLine($"[dim]Using {Markup.Escape(result.Value)}[/]");
        return service;
    }

    /// <summary>
    /// Sign a single artifact and print status to console.
    /// Never throws — returns false on failure with a yellow warning.
    /// </summary>
    public static async Task<bool> TrySignArtifactAsync(
        SigilService service, string artifactPath, string? keyPath, CancellationToken ct)
    {
        var fileName = Path.GetFileName(artifactPath);
        var result = await service.SignAsync(artifactPath, keyPath, ct);

        if (result.IsFailure)
        {
            AnsiConsole.MarkupLine($"[yellow]Warning: Failed to sign {Markup.Escape(fileName)}: {Markup.Escape(result.Error)}[/]");
            return false;
        }

        AnsiConsole.MarkupLine($"[green]Signed:[/] {Markup.Escape(result.Value)}");
        return true;
    }
}
