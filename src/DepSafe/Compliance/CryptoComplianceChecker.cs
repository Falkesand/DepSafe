using System.Collections.Frozen;

namespace DepSafe.Compliance;

/// <summary>
/// Checks for use of deprecated or insecure cryptographic libraries.
/// CRA Article 10 requires products to be designed to limit attack surfaces.
/// </summary>
public static class CryptoComplianceChecker
{
    /// <summary>
    /// Packages known to use deprecated cryptographic algorithms.
    /// </summary>
    private static readonly FrozenDictionary<string, string> DeprecatedCryptoPackages = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
    {
        // MD5 implementations
        ["MD5CryptoServiceProvider"] = "MD5 is cryptographically broken",
        ["System.Security.Cryptography.MD5"] = "MD5 - consider SHA-256 or higher",

        // SHA1 implementations
        ["SHA1CryptoServiceProvider"] = "SHA-1 is deprecated for security use",
        ["System.Security.Cryptography.SHA1"] = "SHA-1 - consider SHA-256 or higher",

        // DES/3DES
        ["DESCryptoServiceProvider"] = "DES is insecure - use AES",
        ["TripleDESCryptoServiceProvider"] = "3DES is deprecated - use AES",

        // RC2/RC4
        ["RC2CryptoServiceProvider"] = "RC2 is insecure - use AES",

        // Old .NET Crypto
        ["System.Security.Cryptography.RijndaelManaged"] = "Use Aes class instead",

        // BouncyCastle with known issues (very old versions)
        ["BouncyCastle"] = "Ensure version >= 1.8.9 for security fixes",
        ["Portable.BouncyCastle"] = "Ensure version >= 1.8.9 for security fixes",

        // JWT libraries with known vulnerabilities
        ["System.IdentityModel.Tokens.Jwt"] = "Ensure version >= 6.x for security fixes",
    }.ToFrozenDictionary(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Packages that are crypto-related and should be reviewed.
    /// </summary>
    private static readonly FrozenSet<string> CryptoRelatedPackages = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "System.Security.Cryptography.Algorithms",
        "System.Security.Cryptography.Csp",
        "System.Security.Cryptography.Cng",
        "System.Security.Cryptography.OpenSsl",
        "System.Security.Cryptography.Pkcs",
        "System.Security.Cryptography.X509Certificates",
        "System.Security.Cryptography.Xml",
        "Microsoft.AspNetCore.Cryptography.KeyDerivation",
        "BouncyCastle.Cryptography",
        "Portable.BouncyCastle",
        "libsodium",
        "NSec.Cryptography",
        "BCrypt.Net-Next",
        "Konscious.Security.Cryptography.Argon2",
    }.ToFrozenSet(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Check packages for crypto compliance issues.
    /// </summary>
    public static CryptoComplianceResult Check(IEnumerable<(string packageId, string version)> packages)
    {
        var issues = new List<CryptoIssue>();
        var cryptoPackagesFound = new List<string>();

        foreach (var (packageId, version) in packages)
        {
            if (DeprecatedCryptoPackages.TryGetValue(packageId, out var reason))
            {
                issues.Add(new CryptoIssue
                {
                    PackageId = packageId,
                    Version = version,
                    Issue = reason,
                    Severity = "Warning"
                });
            }

            if (CryptoRelatedPackages.Contains(packageId))
            {
                cryptoPackagesFound.Add(packageId);
            }
        }

        return new CryptoComplianceResult
        {
            Issues = issues,
            CryptoPackagesFound = cryptoPackagesFound,
            IsCompliant = issues.Count == 0
        };
    }
}

/// <summary>
/// Result of crypto compliance check.
/// </summary>
public sealed class CryptoComplianceResult
{
    public required List<CryptoIssue> Issues { get; init; }
    public required List<string> CryptoPackagesFound { get; init; }
    public required bool IsCompliant { get; init; }
}

/// <summary>
/// A crypto compliance issue.
/// </summary>
public sealed class CryptoIssue
{
    public required string PackageId { get; init; }
    public required string Version { get; init; }
    public required string Issue { get; init; }
    public required string Severity { get; init; }
}
