using System.CommandLine;
using DepSafe.Commands;

var rootCommand = new RootCommand("DepSafe - Dependency safety and compliance for .NET and npm projects")
{
    AnalyzeCommand.Create(),
    CheckCommand.Create(),
    SbomCommand.Create(),
    VexCommand.Create(),
    CraReportCommand.Create(),
    LicensesCommand.Create(),
    BadgeCommand.Create()
};

return await rootCommand.InvokeAsync(args);
