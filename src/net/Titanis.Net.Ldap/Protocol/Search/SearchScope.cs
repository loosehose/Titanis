namespace Titanis.Net.Ldap.Protocol.Search;

/// <summary>
/// LDAP search scope per RFC 4511 Section 4.5.1.
/// </summary>
public enum SearchScope
{
    /// <summary>
    /// Search only the base object.
    /// </summary>
    BaseObject = 0,

    /// <summary>
    /// Search one level below the base.
    /// </summary>
    SingleLevel = 1,

    /// <summary>
    /// Search the whole subtree.
    /// </summary>
    WholeSubtree = 2,
}

/// <summary>
/// Alias dereferencing behavior per RFC 4511 Section 4.5.1.
/// </summary>
public enum DerefAliases
{
    /// <summary>
    /// Never dereference aliases.
    /// </summary>
    NeverDerefAliases = 0,

    /// <summary>
    /// Dereference while searching.
    /// </summary>
    DerefInSearching = 1,

    /// <summary>
    /// Dereference when finding the base object.
    /// </summary>
    DerefFindingBaseObj = 2,

    /// <summary>
    /// Always dereference aliases.
    /// </summary>
    DerefAlways = 3,
}
