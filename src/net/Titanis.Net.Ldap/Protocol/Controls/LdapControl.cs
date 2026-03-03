using Titanis.Asn1;
using Titanis.Asn1.Serialization;
using Titanis.IO;

namespace Titanis.Net.Ldap.Protocol.Controls;

/// <summary>
/// LDAP control per RFC 4511 Section 4.1.11.
/// </summary>
/// <remarks>
/// Control ::= SEQUENCE {
///     controlType             LDAPOID,
///     criticality             BOOLEAN DEFAULT FALSE,
///     controlValue            OCTET STRING OPTIONAL }
/// </remarks>
public class LdapControl
{
    /// <summary>
    /// Gets or sets the control OID.
    /// </summary>
    public string Oid { get; set; } = "";

    /// <summary>
    /// Gets or sets whether the control is critical.
    /// </summary>
    public bool Criticality { get; set; }

    /// <summary>
    /// Gets or sets the control value.
    /// </summary>
    public byte[]? Value { get; set; }

    /// <summary>
    /// Encodes this control.
    /// </summary>
    public virtual void EncodeTlv(Asn1DerEncoder encoder)
    {
        var pos = encoder.Position;

        // Encode value if present
        if (Value is { Length: > 0 })
        {
            encoder.EncodeOctetStringTlv(Value, LdapTags.OctetString);
        }

        // Encode criticality (only if true, since FALSE is default)
        if (Criticality)
        {
            encoder.EncodeBoolTlv(true, LdapTags.Boolean);
        }

        // Encode OID as OCTET STRING (LDAPOID is OCTET STRING UTF8)
        encoder.EncodeUtf8StringTlv(Oid, LdapTags.OctetString);

        encoder.EncodeCloseTlvHeader(LdapTags.Sequence.AsConstructed(), pos);
    }

    /// <summary>
    /// Decodes a control from the decoder.
    /// </summary>
    public static LdapControl DecodeTlvFrom(Asn1DerDecoder decoder)
    {
        var frame = decoder.DecodeTlvStart(LdapTags.Sequence.AsConstructed());

        var control = new LdapControl
        {
            Oid = decoder.DecodeUtf8StringTlv(LdapTags.OctetString)
        };

        // Criticality is optional, default false
        if (!decoder.IsEndOfTuple && decoder.PeekTag() == LdapTags.Boolean)
        {
            control.Criticality = decoder.DecodeBoolTlv(LdapTags.Boolean);
        }

        // Value is optional
        if (!decoder.IsEndOfTuple && decoder.PeekTag() == LdapTags.OctetString)
        {
            control.Value = decoder.DecodeOctetStringTlv(LdapTags.OctetString);
        }

        decoder.CloseTlv(frame);
        return control;
    }
}

/// <summary>
/// Paged results control for large result sets.
/// OID: 1.2.840.113556.1.4.319
/// </summary>
public sealed class PagedResultsControl : LdapControl
{
    /// <summary>
    /// The control OID.
    /// </summary>
    public const string ControlOid = "1.2.840.113556.1.4.319";

    /// <summary>
    /// Gets or sets the page size.
    /// </summary>
    public int PageSize { get; set; }

    /// <summary>
    /// Gets or sets the cookie for the next page.
    /// </summary>
    public byte[]? Cookie { get; set; }

    /// <summary>
    /// Initializes a new instance of the <see cref="PagedResultsControl"/> class.
    /// </summary>
    public PagedResultsControl()
    {
        Oid = ControlOid;
    }

    /// <summary>
    /// Initializes a new instance with the specified page size.
    /// </summary>
    public PagedResultsControl(int pageSize, byte[]? cookie = null)
    {
        Oid = ControlOid;
        PageSize = pageSize;
        Cookie = cookie;
    }

    /// <inheritdoc/>
    public override void EncodeTlv(Asn1DerEncoder encoder)
    {
        // Encode the control value
        var valueWriter = new ByteWriter(64, ByteWriterOptions.Reverse);
        var valueEncoder = new Asn1DerEncoder(Asn1DerEncoding.Instance, valueWriter);

        var seqPos = valueEncoder.Position;
        valueEncoder.EncodeOctetStringTlv(Cookie ?? Array.Empty<byte>(), LdapTags.OctetString);
        valueEncoder.EncodeInt32Tlv(PageSize, LdapTags.Integer);
        valueEncoder.EncodeCloseTlvHeader(LdapTags.Sequence.AsConstructed(), seqPos);

        Value = valueWriter.GetData().ToArray();

        base.EncodeTlv(encoder);
    }

    /// <summary>
    /// Parses a paged results control from raw control data.
    /// </summary>
    public static PagedResultsControl Parse(LdapControl control)
    {
        if (control.Oid != ControlOid)
            throw new ArgumentException($"Invalid control OID: {control.Oid}");

        var result = new PagedResultsControl
        {
            Criticality = control.Criticality
        };

        if (control.Value is { Length: > 0 })
        {
            var decoder = new Asn1DerDecoder(new ByteMemoryReader(control.Value), allowBer: true);
            var frame = decoder.DecodeTlvStart(LdapTags.Sequence.AsConstructed());

            result.PageSize = decoder.DecodeIntegerTlvAsInt32(LdapTags.Integer);
            result.Cookie = decoder.DecodeOctetStringTlv(LdapTags.OctetString);

            decoder.CloseTlv(frame);
        }

        return result;
    }
}
