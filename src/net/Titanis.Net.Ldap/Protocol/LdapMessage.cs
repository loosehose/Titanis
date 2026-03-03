using System.Diagnostics.CodeAnalysis;
using Titanis.Asn1;
using Titanis.Asn1.Serialization;
using Titanis.IO;
using Titanis.Net.Ldap.Protocol.Controls;
using Titanis.Net.Ldap.Protocol.Requests;
using Titanis.Net.Ldap.Protocol.Responses;

namespace Titanis.Net.Ldap.Protocol;

/// <summary>
/// LDAP message envelope per RFC 4511 Section 4.1.1.
/// </summary>
/// <remarks>
/// LDAPMessage ::= SEQUENCE {
///     messageID       MessageID,
///     protocolOp      CHOICE { ... },
///     controls        [0] Controls OPTIONAL }
/// </remarks>
public sealed class LdapMessage
{
    /// <summary>
    /// Gets or sets the message ID.
    /// </summary>
    public int MessageId { get; set; }

    /// <summary>
    /// Gets or sets the protocol operation.
    /// </summary>
    public ILdapProtocolOp? ProtocolOp { get; set; }

    /// <summary>
    /// Gets or sets the optional controls.
    /// </summary>
    public IReadOnlyList<LdapControl>? Controls { get; set; }

    /// <summary>
    /// Encodes this message to bytes.
    /// </summary>
    /// <returns>The encoded message bytes.</returns>
    public byte[] Encode()
    {
        var writer = new ByteWriter(256, ByteWriterOptions.Reverse);
        var encoder = new Asn1DerEncoder(Asn1DerEncoding.Instance, writer);

        EncodeTlv(encoder);

        return writer.GetData().ToArray();
    }

    /// <summary>
    /// Encodes this message using the provided encoder.
    /// </summary>
    /// <param name="encoder">The ASN.1 DER encoder.</param>
    public void EncodeTlv(Asn1DerEncoder encoder)
    {
        var pos = encoder.Position;

        // Encode controls if present (optional, context tag [0])
        if (Controls is { Count: > 0 })
        {
            var controlsPos = encoder.Position;
            foreach (var control in Controls.Reverse())
            {
                control.EncodeTlv(encoder);
            }
            encoder.EncodeCloseTlvHeader(LdapTags.Controls.AsConstructed(), controlsPos);
        }

        // Encode protocol operation
        ProtocolOp?.EncodeTlv(encoder);

        // Encode message ID
        encoder.EncodeInt32Tlv(MessageId, LdapTags.Integer);

        // Close the SEQUENCE
        encoder.EncodeCloseTlvHeader(LdapTags.LdapMessage, pos);
    }

    /// <summary>
    /// Decodes an LDAP message from bytes.
    /// </summary>
    /// <param name="data">The encoded message bytes.</param>
    /// <returns>The decoded message.</returns>
    public static LdapMessage Decode(ReadOnlyMemory<byte> data)
    {
        var decoder = new Asn1DerDecoder(new ByteMemoryReader(data), allowBer: true);
        return DecodeTlvFrom(decoder);
    }

    /// <summary>
    /// Decodes an LDAP message from the decoder.
    /// </summary>
    /// <param name="decoder">The ASN.1 DER decoder.</param>
    /// <returns>The decoded message.</returns>
    public static LdapMessage DecodeTlvFrom(Asn1DerDecoder decoder)
    {
        var frame = decoder.DecodeTlvStart(LdapTags.LdapMessage);

        var message = new LdapMessage
        {
            MessageId = decoder.DecodeIntegerTlvAsInt32(LdapTags.Integer)
        };

        // Decode protocol operation based on tag
        var opTag = decoder.PeekTag();
        message.ProtocolOp = DecodeProtocolOp(decoder, opTag);

        // Decode optional controls
        if (!decoder.IsEndOfTuple && decoder.PeekTag() == LdapTags.Controls)
        {
            message.Controls = DecodeControls(decoder);
        }

        decoder.CloseTlv(frame);
        return message;
    }

    private static ILdapProtocolOp? DecodeProtocolOp(Asn1DerDecoder decoder, Asn1Tag tag)
    {
        // Match on APPLICATION tag number
        return tag.TagNumber switch
        {
            0 => BindRequest.DecodeTlvFrom(decoder),
            1 => BindResponse.DecodeTlvFrom(decoder),
            // 2 => UnbindRequest (no content)
            3 => SearchRequest.DecodeTlvFrom(decoder),
            4 => SearchResultEntry.DecodeTlvFrom(decoder),
            5 => SearchResultDone.DecodeTlvFrom(decoder),
            7 => ModifyResponse.DecodeTlvFrom(decoder),
            9 => AddResponse.DecodeTlvFrom(decoder),
            11 => DeleteResponse.DecodeTlvFrom(decoder),
            13 => ModifyDnResponse.DecodeTlvFrom(decoder),
            15 => CompareResponse.DecodeTlvFrom(decoder),
            19 => SearchResultReference.DecodeTlvFrom(decoder),
            24 => ExtendedResponse.DecodeTlvFrom(decoder),
            25 => IntermediateResponse.DecodeTlvFrom(decoder),
            _ => throw new InvalidDataException($"Unknown LDAP protocol operation tag: {tag}")
        };
    }

    private static IReadOnlyList<LdapControl> DecodeControls(Asn1DerDecoder decoder)
    {
        var controls = new List<LdapControl>();
        var frame = decoder.DecodeTlvStart(LdapTags.Controls.AsConstructed());

        while (!decoder.IsEndOfTuple)
        {
            controls.Add(LdapControl.DecodeTlvFrom(decoder));
        }

        decoder.CloseTlv(frame);
        return controls;
    }
}
