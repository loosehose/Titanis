using System.Text;
using Titanis.Asn1;
using Titanis.Asn1.Serialization;

namespace Titanis.Net.Ldap.Protocol.Responses;

/// <summary>
/// LDAP search result entry per RFC 4511 Section 4.5.2.
/// </summary>
/// <remarks>
/// SearchResultEntry ::= [APPLICATION 4] SEQUENCE {
///     objectName      LDAPDN,
///     attributes      PartialAttributeList }
/// </remarks>
public sealed class SearchResultEntry : ILdapProtocolOp, ILdapProtocolOpDecodable<SearchResultEntry>
{
    /// <summary>
    /// Gets the ASN.1 tag for this operation.
    /// </summary>
    public Asn1Tag Tag => LdapTags.SearchResultEntry;

    /// <summary>
    /// Gets or sets the object DN.
    /// </summary>
    public string ObjectName { get; set; } = "";

    /// <summary>
    /// Gets or sets the attributes.
    /// </summary>
    public IReadOnlyList<PartialAttribute> Attributes { get; set; } = Array.Empty<PartialAttribute>();

    /// <inheritdoc/>
    public void EncodeTlv(Asn1DerEncoder encoder)
    {
        var pos = encoder.Position;

        // Encode attributes (SEQUENCE OF PartialAttribute)
        var attrsPos = encoder.Position;
        foreach (var attr in Attributes.Reverse())
        {
            attr.EncodeTlv(encoder);
        }
        encoder.EncodeCloseTlvHeader(LdapTags.Sequence.AsConstructed(), attrsPos);

        // Encode objectName
        encoder.EncodeOctetStringTlv(Encoding.UTF8.GetBytes(ObjectName), LdapTags.OctetString);

        encoder.EncodeCloseTlvHeader(LdapTags.SearchResultEntry.AsConstructed(), pos);
    }

    /// <inheritdoc/>
    public static SearchResultEntry DecodeTlvFrom(Asn1DerDecoder decoder)
    {
        var frame = decoder.DecodeTlvStart(LdapTags.SearchResultEntry.AsConstructed());

        var entry = new SearchResultEntry
        {
            ObjectName = Encoding.UTF8.GetString(decoder.DecodeOctetStringTlv(LdapTags.OctetString))
        };

        // Decode attributes
        var attrs = new List<PartialAttribute>();
        var attrsFrame = decoder.DecodeTlvStart(LdapTags.Sequence.AsConstructed());
        while (!decoder.IsEndOfTuple)
        {
            attrs.Add(PartialAttribute.DecodeTlvFrom(decoder));
        }
        decoder.CloseTlv(attrsFrame);
        entry.Attributes = attrs;

        decoder.CloseTlv(frame);
        return entry;
    }
}

/// <summary>
/// Partial attribute (type + set of values).
/// </summary>
/// <remarks>
/// PartialAttribute ::= SEQUENCE {
///     type       AttributeDescription,
///     vals       SET OF value AttributeValue }
/// </remarks>
public sealed class PartialAttribute
{
    /// <summary>
    /// Gets or sets the attribute type (name).
    /// </summary>
    public string Type { get; set; } = "";

    /// <summary>
    /// Gets or sets the attribute values.
    /// </summary>
    public IReadOnlyList<byte[]> Values { get; set; } = Array.Empty<byte[]>();

    /// <summary>
    /// Gets the attribute values as strings.
    /// </summary>
    public IEnumerable<string> StringValues => Values.Select(v => Encoding.UTF8.GetString(v));

    /// <summary>
    /// Gets the first value as a string, or null if no values.
    /// </summary>
    public string? FirstStringValue => Values.Count > 0 ? Encoding.UTF8.GetString(Values[0]) : null;

    /// <summary>
    /// Encodes this attribute.
    /// </summary>
    public void EncodeTlv(Asn1DerEncoder encoder)
    {
        var pos = encoder.Position;

        // Encode values (SET OF)
        var valsPos = encoder.Position;
        foreach (var value in Values.Reverse())
        {
            encoder.EncodeOctetStringTlv(value, LdapTags.OctetString);
        }
        encoder.EncodeCloseTlvHeader(LdapTags.Set.AsConstructed(), valsPos);

        // Encode type
        encoder.EncodeOctetStringTlv(Encoding.UTF8.GetBytes(Type), LdapTags.OctetString);

        encoder.EncodeCloseTlvHeader(LdapTags.Sequence.AsConstructed(), pos);
    }

    /// <summary>
    /// Decodes a partial attribute.
    /// </summary>
    public static PartialAttribute DecodeTlvFrom(Asn1DerDecoder decoder)
    {
        var frame = decoder.DecodeTlvStart(LdapTags.Sequence.AsConstructed());

        var attr = new PartialAttribute
        {
            Type = Encoding.UTF8.GetString(decoder.DecodeOctetStringTlv(LdapTags.OctetString))
        };

        // Decode values
        var values = new List<byte[]>();
        var valsFrame = decoder.DecodeTlvStart(LdapTags.Set.AsConstructed());
        while (!decoder.IsEndOfTuple)
        {
            values.Add(decoder.DecodeOctetStringTlv(LdapTags.OctetString));
        }
        decoder.CloseTlv(valsFrame);
        attr.Values = values;

        decoder.CloseTlv(frame);
        return attr;
    }
}
