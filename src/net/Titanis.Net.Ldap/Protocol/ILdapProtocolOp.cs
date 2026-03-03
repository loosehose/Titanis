using Titanis.Asn1;
using Titanis.Asn1.Serialization;

namespace Titanis.Net.Ldap.Protocol;

/// <summary>
/// Interface for LDAP protocol operations.
/// </summary>
public interface ILdapProtocolOp
{
    /// <summary>
    /// Gets the ASN.1 tag for this operation.
    /// </summary>
    Asn1Tag Tag { get; }

    /// <summary>
    /// Encodes this protocol operation to the encoder.
    /// </summary>
    /// <param name="encoder">The ASN.1 DER encoder.</param>
    void EncodeTlv(Asn1DerEncoder encoder);
}

/// <summary>
/// Interface for LDAP protocol operations that can be decoded.
/// </summary>
/// <typeparam name="T">The concrete type implementing this interface.</typeparam>
public interface ILdapProtocolOpDecodable<T> : ILdapProtocolOp where T : ILdapProtocolOpDecodable<T>
{
    /// <summary>
    /// Decodes a protocol operation from the decoder.
    /// </summary>
    /// <param name="decoder">The ASN.1 DER decoder.</param>
    /// <returns>The decoded protocol operation.</returns>
    static abstract T DecodeTlvFrom(Asn1DerDecoder decoder);
}
