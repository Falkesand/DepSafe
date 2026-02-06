using System.Text.Json;
using System.Text.Json.Serialization;

namespace DepSafe;

/// <summary>
/// Shared, pre-allocated JsonSerializerOptions instances.
/// Avoids repeated allocation of identical options across commands.
/// </summary>
internal static class JsonDefaults
{
    public static readonly JsonSerializerOptions Indented = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase
    };

    public static readonly JsonSerializerOptions IndentedDefault = new()
    {
        WriteIndented = true
    };

    public static readonly JsonSerializerOptions CaseInsensitive = new()
    {
        PropertyNameCaseInsensitive = true
    };

    public static readonly JsonSerializerOptions CamelCase = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase
    };

    public static readonly JsonSerializerOptions IndentedIgnoreNull = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };
}
