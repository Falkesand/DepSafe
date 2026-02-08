using System.CommandLine;
using System.CommandLine.Binding;

namespace DepSafe.Commands;

public sealed class CraReportOptionsBinder : BinderBase<CraReportOptions>
{
    private readonly Argument<string?> _path;
    private readonly Option<CraOutputFormat> _format;
    private readonly Option<string?> _output;
    private readonly Option<bool> _skipGitHub;
    private readonly Option<bool> _deep;
    private readonly Option<LicenseOutputFormat?> _licenses;
    private readonly Option<SbomFormat?> _sbom;
    private readonly Option<bool> _checkTyposquat;
    private readonly Option<bool> _sign;
    private readonly Option<string?> _signKey;
    private readonly Option<string?> _trustBundle;

    public CraReportOptionsBinder(
        Argument<string?> path,
        Option<CraOutputFormat> format,
        Option<string?> output,
        Option<bool> skipGitHub,
        Option<bool> deep,
        Option<LicenseOutputFormat?> licenses,
        Option<SbomFormat?> sbom,
        Option<bool> checkTyposquat,
        Option<bool> sign,
        Option<string?> signKey,
        Option<string?> trustBundle)
    {
        _path = path;
        _format = format;
        _output = output;
        _skipGitHub = skipGitHub;
        _deep = deep;
        _licenses = licenses;
        _sbom = sbom;
        _checkTyposquat = checkTyposquat;
        _sign = sign;
        _signKey = signKey;
        _trustBundle = trustBundle;
    }

    public CraReportOptions Bind(BindingContext bindingContext) => GetBoundValue(bindingContext);

    protected override CraReportOptions GetBoundValue(BindingContext bindingContext) => new(
        bindingContext.ParseResult.GetValueForArgument(_path),
        bindingContext.ParseResult.GetValueForOption(_format),
        bindingContext.ParseResult.GetValueForOption(_output),
        bindingContext.ParseResult.GetValueForOption(_skipGitHub),
        bindingContext.ParseResult.GetValueForOption(_deep),
        bindingContext.ParseResult.GetValueForOption(_licenses),
        bindingContext.ParseResult.GetValueForOption(_sbom),
        bindingContext.ParseResult.GetValueForOption(_checkTyposquat),
        bindingContext.ParseResult.GetValueForOption(_sign),
        bindingContext.ParseResult.GetValueForOption(_signKey),
        bindingContext.ParseResult.GetValueForOption(_trustBundle));
}
