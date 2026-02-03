using System.CommandLine;
using NuGetHealthAnalyzer.Commands;

var rootCommand = new RootCommand("NuGet Health Analyzer - Health scoring for NuGet dependencies")
{
    AnalyzeCommand.Create(),
    CheckCommand.Create(),
    SbomCommand.Create(),
    VexCommand.Create(),
    CraReportCommand.Create()
};

return await rootCommand.InvokeAsync(args);
