using System.Text;
using Titanis.Asn1;
using Titanis.Asn1.Serialization;

namespace Titanis.Net.Ldap.Protocol.Requests;

/// <summary>
/// LDAP bind request per RFC 4511 Section 4.2.
/// </summary>
/// <remarks>
/// BindRequest ::= [APPLICATION 0] SEQUENCE {
///     version                 INTEGER (1 ..  127),
///     name                    LDAPDN,
///     authentication          AuthenticationChoice }
/// </remarks>
public sealed class BindRequest : ILdapProtocolOp, ILdapProtocolOpDecodable<BindRequest>
{
    /// <summary>
    /// Gets the ASN.1 tag for this operation.
    /// </summary>
    public Asn1Tag Tag => LdapTags.BindRequest;

    /// <summary>
    /// Gets or sets the LDAP version (typically 3).
    /// </summary>
    public int Version { get; set; } = 3;

    /// <summary>
    /// Gets or sets the distinguished name for binding.
    /// </summary>
    public string Name { get; set; } = "";

    /// <summary>
    /// Gets or sets simple (password) authentication credentials.
    /// </summary>
    public byte[]? SimpleCredentials { get; set; }

    /// <summary>
    /// Gets or sets SASL authentication mechanism.
    /// </summary>
    public string? SaslMechanism { get; set; }

    /// <summary>
    /// Gets or sets SASL credentials.
    /// </summary>
    public byte[]? SaslCredentials { get; set; }

    /// <summary>
    /// Gets whether this is a simple bind.
    /// </summary>
    public bool IsSimpleBind => SaslMechanism == null;

    /// <summary>
    /// Creates a simple bind request.
    /// </summary>
    public static BindRequest CreateSimple(string dn, string password)
    {
        return new BindRequest
        {
            Name = dn,
            SimpleCredentials = Encoding.UTF8.GetBytes(password)
        };
    }

    /// <summary>
    /// Creates a SASL bind request.
    /// </summary>
    public static BindRequest CreateSasl(string mechanism, byte[]? credentials = null)
    {
        return new BindRequest
        {
            SaslMechanism = mechanism,
            SaslCredentials = credentials
        };
    }

    /// <inheritdoc/>
    public void EncodeTlv(Asn1DerEncoder encoder)
    {
        var pos = encoder.Position;

        // Encode authentication choice
        if (SaslMechanism != null)
        {
            // SASL authentication [3]
            var saslPos = encoder.Position;
            if (SaslCredentials != null)
            {
                encoder.EncodeOctetStringTlv(SaslCredentials, LdapTags.OctetString);
            }
            encoder.EncodeOctetStringTlv(Encoding.UTF8.GetBytes(SaslMechanism), LdapTags.OctetString);
            encoder.EncodeCloseTlvHeader(LdapTags.AuthSasl.AsConstructed(), saslPos);
        }
        else
        {
            // Simple authentication [0]
            encoder.EncodeOctetStringTlv(SimpleCredentials ?? Array.Empty<byte>(), LdapTags.AuthSimple);
        }

        // Encode name
        encoder.EncodeOctetStringTlv(Encoding.UTF8.GetBytes(Name), LdapTags.OctetString);

        // Encode version
        encoder.EncodeInt32Tlv(Version, LdapTags.Integer);

        encoder.EncodeCloseTlvHeader(LdapTags.BindRequest.AsConstructed(), pos);
    }

    /// <inheritdoc/>
    public static BindRequest DecodeTlvFrom(Asn1DerDecoder decoder)
    {
        var frame = decoder.DecodeTlvStart(LdapTags.BindRequest.AsConstructed());

        var request = new BindRequest
        {
            Version = decoder.DecodeIntegerTlvAsInt32(LdapTags.Integer),
            Name = Encoding.UTF8.GetString(decoder.DecodeOctetStringTlv(LdapTags.OctetString))
        };

        // Decode authentication choice
        var authTag = decoder.PeekTag();
        if (authTag == LdapTags.AuthSimple)
        {
            request.SimpleCredentials = decoder.DecodeOctetStringTlv(LdapTags.AuthSimple);
        }
        else if (authTag == LdapTags.AuthSasl)
        {
            var saslFrame = decoder.DecodeTlvStart(LdapTags.AuthSasl.AsConstructed());
            request.SaslMechanism = Encoding.UTF8.GetString(decoder.DecodeOctetStringTlv(LdapTags.OctetString));
            if (!decoder.IsEndOfTuple)
            {
                request.SaslCredentials = decoder.DecodeOctetStringTlv(LdapTags.OctetString);
            }
            decoder.CloseTlv(saslFrame);
        }

        decoder.CloseTlv(frame);
        return request;
    }
}
