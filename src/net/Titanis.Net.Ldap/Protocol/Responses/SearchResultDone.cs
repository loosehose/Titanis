using Titanis.Asn1;
using Titanis.Asn1.Serialization;

namespace Titanis.Net.Ldap.Protocol.Responses;

/// <summary>
/// LDAP search result done per RFC 4511 Section 4.5.2.
/// </summary>
/// <remarks>
/// SearchResultDone ::= [APPLICATION 5] LDAPResult
/// </remarks>
public sealed class SearchResultDone : LdapResult, ILdapProtocolOp, ILdapProtocolOpDecodable<SearchResultDone>
{
    /// <summary>
    /// Gets the ASN.1 tag for this operation.
    /// </summary>
    public Asn1Tag Tag => LdapTags.SearchResultDone;

    /// <inheritdoc/>
    public void EncodeTlv(Asn1DerEncoder encoder)
    {
        var pos = encoder.Position;
        EncodeResultFields(encoder);
        encoder.EncodeCloseTlvHeader(LdapTags.SearchResultDone.AsConstructed(), pos);
    }

    /// <inheritdoc/>
    public static SearchResultDone DecodeTlvFrom(Asn1DerDecoder decoder)
    {
        var frame = decoder.DecodeTlvStart(LdapTags.SearchResultDone.AsConstructed());
        var response = new SearchResultDone();
        response.DecodeResultFields(decoder);
        decoder.CloseTlv(frame);
        return response;
    }
}

/// <summary>
/// LDAP search result reference per RFC 4511 Section 4.5.3.
/// </summary>
/// <remarks>
/// SearchResultReference ::= [APPLICATION 19] SEQUENCE SIZE (1..MAX) OF uri URI
/// </remarks>
public sealed class SearchResultReference : ILdapProtocolOp, ILdapProtocolOpDecodable<SearchResultReference>
{
    /// <summary>
    /// Gets the ASN.1 tag for this operation.
    /// </summary>
    public Asn1Tag Tag => LdapTags.SearchResultReference;

    /// <summary>
    /// Gets or sets the referral URIs.
    /// </summary>
    public IReadOnlyList<string> Uris { get; set; } = Array.Empty<string>();

    /// <inheritdoc/>
    public void EncodeTlv(Asn1DerEncoder encoder)
    {
        var pos = encoder.Position;
        foreach (var uri in Uris.Reverse())
        {
            encoder.EncodeOctetStringTlv(System.Text.Encoding.UTF8.GetBytes(uri), LdapTags.OctetString);
        }
        encoder.EncodeCloseTlvHeader(LdapTags.SearchResultReference.AsConstructed(), pos);
    }

    /// <inheritdoc/>
    public static SearchResultReference DecodeTlvFrom(Asn1DerDecoder decoder)
    {
        var frame = decoder.DecodeTlvStart(LdapTags.SearchResultReference.AsConstructed());
        var uris = new List<string>();
        while (!decoder.IsEndOfTuple)
        {
            uris.Add(System.Text.Encoding.UTF8.GetString(decoder.DecodeOctetStringTlv(LdapTags.OctetString)));
        }
        decoder.CloseTlv(frame);
        return new SearchResultReference { Uris = uris };
    }
}
