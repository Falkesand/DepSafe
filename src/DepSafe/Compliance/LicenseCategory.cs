namespace DepSafe.Compliance;

/// <summary>
/// License categories based on restrictions and copyleft requirements.
/// </summary>
public enum LicenseCategory
{
    /// <summary>Very permissive, no copyleft (MIT, BSD, Apache, ISC, Unlicense)</summary>
    Permissive,
    /// <summary>Weak copyleft, allows linking (LGPL, MPL, EPL)</summary>
    WeakCopyleft,
    /// <summary>Strong copyleft, requires source disclosure (GPL, AGPL)</summary>
    StrongCopyleft,
    /// <summary>Proprietary or commercial license</summary>
    Proprietary,
    /// <summary>Public domain or equivalent (CC0, WTFPL)</summary>
    PublicDomain,
    /// <summary>Unknown or unrecognized license</summary>
    Unknown
}
