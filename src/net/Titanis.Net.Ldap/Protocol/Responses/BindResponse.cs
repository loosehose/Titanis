using Titanis.Asn1;
using Titanis.Asn1.Serialization;

namespace Titanis.Net.Ldap.Protocol.Responses;

/// <summary>
/// LDAP bind response per RFC 4511 Section 4.2.2.
/// </summary>
/// <remarks>
/// BindResponse ::= [APPLICATION 1] SEQUENCE {
///     COMPONENTS OF LDAPResult,
///     serverSaslCreds    [7] OCTET STRING OPTIONAL }
/// </remarks>
public sealed class BindResponse : LdapResult, ILdapProtocolOp, ILdapProtocolOpDecodable<BindResponse>
{
    /// <summary>
    /// Gets the ASN.1 tag for this operation.
    /// </summary>
    public Asn1Tag Tag => LdapTags.BindResponse;

    /// <summary>
    /// Gets or sets the server SASL credentials (for multi-stage SASL authentication).
    /// </summary>
    public byte[]? ServerSaslCreds { get; set; }

    /// <summary>
    /// Gets whether SASL bind is still in progress.
    /// </summary>
    public bool IsSaslBindInProgress => ResultCode == LdapResultCode.SaslBindInProgress;

    /// <inheritdoc/>
    public void EncodeTlv(Asn1DerEncoder encoder)
    {
        var pos = encoder.Position;

        // Encode serverSaslCreds if present
        if (ServerSaslCreds != null)
        {
            encoder.EncodeOctetStringTlv(ServerSaslCreds, LdapTags.ServerSaslCreds);
        }

        EncodeResultFields(encoder);

        encoder.EncodeCloseTlvHeader(LdapTags.BindResponse.AsConstructed(), pos);
    }

    /// <inheritdoc/>
    public static BindResponse DecodeTlvFrom(Asn1DerDecoder decoder)
    {
        var frame = decoder.DecodeTlvStart(LdapTags.BindResponse.AsConstructed());

        var response = new BindResponse();
        response.DecodeResultFields(decoder);

        // Decode optional serverSaslCreds
        if (!decoder.IsEndOfTuple && decoder.PeekTag() == LdapTags.ServerSaslCreds)
        {
            response.ServerSaslCreds = decoder.DecodeOctetStringTlv(LdapTags.ServerSaslCreds);
        }

        decoder.CloseTlv(frame);
        return response;
    }
}
