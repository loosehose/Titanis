using System.Text;
using Titanis.Asn1;
using Titanis.Asn1.Serialization;

namespace Titanis.Net.Ldap.Protocol;

/// <summary>
/// Base class for LDAP result messages per RFC 4511 Section 4.1.9.
/// </summary>
/// <remarks>
/// LDAPResult ::= SEQUENCE {
///     resultCode         ENUMERATED { ... },
///     matchedDN          LDAPDN,
///     diagnosticMessage  LDAPString,
///     referral           [3] Referral OPTIONAL }
/// </remarks>
public abstract class LdapResult
{
    /// <summary>
    /// Gets or sets the result code.
    /// </summary>
    public LdapResultCode ResultCode { get; set; }

    /// <summary>
    /// Gets or sets the matched DN.
    /// </summary>
    public string MatchedDn { get; set; } = "";

    /// <summary>
    /// Gets or sets the diagnostic message.
    /// </summary>
    public string DiagnosticMessage { get; set; } = "";

    /// <summary>
    /// Gets or sets optional referral URLs.
    /// </summary>
    public IReadOnlyList<string>? Referrals { get; set; }

    /// <summary>
    /// Gets whether this result indicates success.
    /// </summary>
    public bool IsSuccess => ResultCode == LdapResultCode.Success;

    /// <summary>
    /// Encodes the LDAPResult fields.
    /// </summary>
    protected void EncodeResultFields(Asn1DerEncoder encoder)
    {
        // Encode referrals if present
        if (Referrals is { Count: > 0 })
        {
            var refPos = encoder.Position;
            foreach (var referral in Referrals.Reverse())
            {
                encoder.EncodeOctetStringTlv(Encoding.UTF8.GetBytes(referral), LdapTags.OctetString);
            }
            encoder.EncodeCloseTlvHeader(LdapTags.Context3.AsConstructed(), refPos);
        }

        // Encode diagnostic message
        encoder.EncodeOctetStringTlv(Encoding.UTF8.GetBytes(DiagnosticMessage), LdapTags.OctetString);

        // Encode matched DN
        encoder.EncodeOctetStringTlv(Encoding.UTF8.GetBytes(MatchedDn), LdapTags.OctetString);

        // Encode result code
        encoder.EncodeEnumeratedTlv((int)ResultCode, LdapTags.Enumerated);
    }

    /// <summary>
    /// Decodes the LDAPResult fields.
    /// </summary>
    protected void DecodeResultFields(Asn1DerDecoder decoder)
    {
        ResultCode = (LdapResultCode)decoder.DecodeEnumeratedTlv(LdapTags.Enumerated);
        MatchedDn = Encoding.UTF8.GetString(decoder.DecodeOctetStringTlv(LdapTags.OctetString));
        DiagnosticMessage = Encoding.UTF8.GetString(decoder.DecodeOctetStringTlv(LdapTags.OctetString));

        // Decode optional referrals
        if (!decoder.IsEndOfTuple && decoder.PeekTag() == LdapTags.Context3)
        {
            var referrals = new List<string>();
            var refFrame = decoder.DecodeTlvStart(LdapTags.Context3.AsConstructed());
            while (!decoder.IsEndOfTuple)
            {
                referrals.Add(Encoding.UTF8.GetString(decoder.DecodeOctetStringTlv(LdapTags.OctetString)));
            }
            decoder.CloseTlv(refFrame);
            Referrals = referrals;
        }
    }
}
