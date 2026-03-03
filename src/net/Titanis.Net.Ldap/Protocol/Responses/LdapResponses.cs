using System.Text;
using Titanis.Asn1;
using Titanis.Asn1.Serialization;

namespace Titanis.Net.Ldap.Protocol.Responses;

/// <summary>
/// LDAP modify response per RFC 4511 Section 4.6.
/// </summary>
public sealed class ModifyResponse : LdapResult, ILdapProtocolOp, ILdapProtocolOpDecodable<ModifyResponse>
{
    public Asn1Tag Tag => LdapTags.ModifyResponse;

    public void EncodeTlv(Asn1DerEncoder encoder)
    {
        var pos = encoder.Position;
        EncodeResultFields(encoder);
        encoder.EncodeCloseTlvHeader(LdapTags.ModifyResponse.AsConstructed(), pos);
    }

    public static ModifyResponse DecodeTlvFrom(Asn1DerDecoder decoder)
    {
        var frame = decoder.DecodeTlvStart(LdapTags.ModifyResponse.AsConstructed());
        var response = new ModifyResponse();
        response.DecodeResultFields(decoder);
        decoder.CloseTlv(frame);
        return response;
    }
}

/// <summary>
/// LDAP add response per RFC 4511 Section 4.7.
/// </summary>
public sealed class AddResponse : LdapResult, ILdapProtocolOp, ILdapProtocolOpDecodable<AddResponse>
{
    public Asn1Tag Tag => LdapTags.AddResponse;

    public void EncodeTlv(Asn1DerEncoder encoder)
    {
        var pos = encoder.Position;
        EncodeResultFields(encoder);
        encoder.EncodeCloseTlvHeader(LdapTags.AddResponse.AsConstructed(), pos);
    }

    public static AddResponse DecodeTlvFrom(Asn1DerDecoder decoder)
    {
        var frame = decoder.DecodeTlvStart(LdapTags.AddResponse.AsConstructed());
        var response = new AddResponse();
        response.DecodeResultFields(decoder);
        decoder.CloseTlv(frame);
        return response;
    }
}

/// <summary>
/// LDAP delete response per RFC 4511 Section 4.8.
/// </summary>
public sealed class DeleteResponse : LdapResult, ILdapProtocolOp, ILdapProtocolOpDecodable<DeleteResponse>
{
    public Asn1Tag Tag => LdapTags.DeleteResponse;

    public void EncodeTlv(Asn1DerEncoder encoder)
    {
        var pos = encoder.Position;
        EncodeResultFields(encoder);
        encoder.EncodeCloseTlvHeader(LdapTags.DeleteResponse.AsConstructed(), pos);
    }

    public static DeleteResponse DecodeTlvFrom(Asn1DerDecoder decoder)
    {
        var frame = decoder.DecodeTlvStart(LdapTags.DeleteResponse.AsConstructed());
        var response = new DeleteResponse();
        response.DecodeResultFields(decoder);
        decoder.CloseTlv(frame);
        return response;
    }
}

/// <summary>
/// LDAP modify DN response per RFC 4511 Section 4.9.
/// </summary>
public sealed class ModifyDnResponse : LdapResult, ILdapProtocolOp, ILdapProtocolOpDecodable<ModifyDnResponse>
{
    public Asn1Tag Tag => LdapTags.ModifyDnResponse;

    public void EncodeTlv(Asn1DerEncoder encoder)
    {
        var pos = encoder.Position;
        EncodeResultFields(encoder);
        encoder.EncodeCloseTlvHeader(LdapTags.ModifyDnResponse.AsConstructed(), pos);
    }

    public static ModifyDnResponse DecodeTlvFrom(Asn1DerDecoder decoder)
    {
        var frame = decoder.DecodeTlvStart(LdapTags.ModifyDnResponse.AsConstructed());
        var response = new ModifyDnResponse();
        response.DecodeResultFields(decoder);
        decoder.CloseTlv(frame);
        return response;
    }
}

/// <summary>
/// LDAP compare response per RFC 4511 Section 4.10.
/// </summary>
public sealed class CompareResponse : LdapResult, ILdapProtocolOp, ILdapProtocolOpDecodable<CompareResponse>
{
    public Asn1Tag Tag => LdapTags.CompareResponse;

    public void EncodeTlv(Asn1DerEncoder encoder)
    {
        var pos = encoder.Position;
        EncodeResultFields(encoder);
        encoder.EncodeCloseTlvHeader(LdapTags.CompareResponse.AsConstructed(), pos);
    }

    public static CompareResponse DecodeTlvFrom(Asn1DerDecoder decoder)
    {
        var frame = decoder.DecodeTlvStart(LdapTags.CompareResponse.AsConstructed());
        var response = new CompareResponse();
        response.DecodeResultFields(decoder);
        decoder.CloseTlv(frame);
        return response;
    }
}

/// <summary>
/// LDAP extended response per RFC 4511 Section 4.12.
/// </summary>
public sealed class ExtendedResponse : LdapResult, ILdapProtocolOp, ILdapProtocolOpDecodable<ExtendedResponse>
{
    public Asn1Tag Tag => LdapTags.ExtendedResponse;

    /// <summary>
    /// Gets or sets the response name (OID).
    /// </summary>
    public string? ResponseName { get; set; }

    /// <summary>
    /// Gets or sets the response value.
    /// </summary>
    public byte[]? ResponseValue { get; set; }

    public void EncodeTlv(Asn1DerEncoder encoder)
    {
        var pos = encoder.Position;

        if (ResponseValue != null)
        {
            encoder.EncodeOctetStringTlv(ResponseValue, LdapTags.ExtendedResponseValue);
        }
        if (ResponseName != null)
        {
            encoder.EncodeOctetStringTlv(Encoding.UTF8.GetBytes(ResponseName), LdapTags.ExtendedResponseName);
        }

        EncodeResultFields(encoder);
        encoder.EncodeCloseTlvHeader(LdapTags.ExtendedResponse.AsConstructed(), pos);
    }

    public static ExtendedResponse DecodeTlvFrom(Asn1DerDecoder decoder)
    {
        var frame = decoder.DecodeTlvStart(LdapTags.ExtendedResponse.AsConstructed());
        var response = new ExtendedResponse();
        response.DecodeResultFields(decoder);

        if (!decoder.IsEndOfTuple && decoder.PeekTag() == LdapTags.ExtendedResponseName)
        {
            response.ResponseName = Encoding.UTF8.GetString(decoder.DecodeOctetStringTlv(LdapTags.ExtendedResponseName));
        }
        if (!decoder.IsEndOfTuple && decoder.PeekTag() == LdapTags.ExtendedResponseValue)
        {
            response.ResponseValue = decoder.DecodeOctetStringTlv(LdapTags.ExtendedResponseValue);
        }

        decoder.CloseTlv(frame);
        return response;
    }
}

/// <summary>
/// LDAP intermediate response per RFC 4511 Section 4.13.
/// </summary>
public sealed class IntermediateResponse : ILdapProtocolOp, ILdapProtocolOpDecodable<IntermediateResponse>
{
    public Asn1Tag Tag => LdapTags.IntermediateResponse;

    /// <summary>
    /// Gets or sets the response name (OID).
    /// </summary>
    public string? ResponseName { get; set; }

    /// <summary>
    /// Gets or sets the response value.
    /// </summary>
    public byte[]? ResponseValue { get; set; }

    public void EncodeTlv(Asn1DerEncoder encoder)
    {
        var pos = encoder.Position;

        if (ResponseValue != null)
        {
            encoder.EncodeOctetStringTlv(ResponseValue, LdapTags.Context1);
        }
        if (ResponseName != null)
        {
            encoder.EncodeOctetStringTlv(Encoding.UTF8.GetBytes(ResponseName), LdapTags.Context0);
        }

        encoder.EncodeCloseTlvHeader(LdapTags.IntermediateResponse.AsConstructed(), pos);
    }

    public static IntermediateResponse DecodeTlvFrom(Asn1DerDecoder decoder)
    {
        var frame = decoder.DecodeTlvStart(LdapTags.IntermediateResponse.AsConstructed());
        var response = new IntermediateResponse();

        if (!decoder.IsEndOfTuple && decoder.PeekTag() == LdapTags.Context0)
        {
            response.ResponseName = Encoding.UTF8.GetString(decoder.DecodeOctetStringTlv(LdapTags.Context0));
        }
        if (!decoder.IsEndOfTuple && decoder.PeekTag() == LdapTags.Context1)
        {
            response.ResponseValue = decoder.DecodeOctetStringTlv(LdapTags.Context1);
        }

        decoder.CloseTlv(frame);
        return response;
    }
}
