using Titanis.Net.Ldap.Protocol;

namespace Titanis.Net.Ldap.Client;

/// <summary>
/// Exception thrown for LDAP protocol errors.
/// </summary>
public class LdapException : Exception
{
    /// <summary>
    /// Gets the LDAP result code.
    /// </summary>
    public LdapResultCode ResultCode { get; }

    /// <summary>
    /// Gets the matched DN from the server response.
    /// </summary>
    public string? MatchedDn { get; }

    /// <summary>
    /// Initializes a new instance of the <see cref="LdapException"/> class.
    /// </summary>
    public LdapException(LdapResultCode resultCode, string? message = null)
        : base(message ?? $"LDAP error: {resultCode}")
    {
        ResultCode = resultCode;
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="LdapException"/> class.
    /// </summary>
    public LdapException(LdapResultCode resultCode, string? matchedDn, string? message)
        : base(message ?? $"LDAP error: {resultCode}")
    {
        ResultCode = resultCode;
        MatchedDn = matchedDn;
    }

    /// <summary>
    /// Initializes a new instance from an LDAP result.
    /// </summary>
    public LdapException(LdapResult result)
        : base(string.IsNullOrEmpty(result.DiagnosticMessage)
            ? $"LDAP error: {result.ResultCode}"
            : result.DiagnosticMessage)
    {
        ResultCode = result.ResultCode;
        MatchedDn = result.MatchedDn;
    }
}
