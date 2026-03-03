using Titanis.Asn1;

namespace Titanis.Net.Ldap.Protocol;

/// <summary>
/// LDAP ASN.1 tag constants per RFC 4511.
/// </summary>
internal static class LdapTags
{
    // Universal tags
    public static readonly Asn1Tag Sequence = new(Asn1TagClass.Universal, 16);
    public static readonly Asn1Tag Set = new(Asn1TagClass.Universal, 17);
    public static readonly Asn1Tag OctetString = Asn1PredefTag.OctetString;
    public static readonly Asn1Tag Integer = Asn1PredefTag.Integer;
    public static readonly Asn1Tag Boolean = Asn1PredefTag.Boolean;
    public static readonly Asn1Tag Enumerated = Asn1PredefTag.Enumerated;

    // LDAPMessage ::= SEQUENCE
    public static readonly Asn1Tag LdapMessage = Sequence.AsConstructed();

    // Protocol operations (APPLICATION tags)
    public static readonly Asn1Tag BindRequest = new(Asn1TagClass.Application, 0);
    public static readonly Asn1Tag BindResponse = new(Asn1TagClass.Application, 1);
    public static readonly Asn1Tag UnbindRequest = new(Asn1TagClass.Application, 2);
    public static readonly Asn1Tag SearchRequest = new(Asn1TagClass.Application, 3);
    public static readonly Asn1Tag SearchResultEntry = new(Asn1TagClass.Application, 4);
    public static readonly Asn1Tag SearchResultDone = new(Asn1TagClass.Application, 5);
    public static readonly Asn1Tag SearchResultReference = new(Asn1TagClass.Application, 19);
    public static readonly Asn1Tag ModifyRequest = new(Asn1TagClass.Application, 6);
    public static readonly Asn1Tag ModifyResponse = new(Asn1TagClass.Application, 7);
    public static readonly Asn1Tag AddRequest = new(Asn1TagClass.Application, 8);
    public static readonly Asn1Tag AddResponse = new(Asn1TagClass.Application, 9);
    public static readonly Asn1Tag DeleteRequest = new(Asn1TagClass.Application, 10);
    public static readonly Asn1Tag DeleteResponse = new(Asn1TagClass.Application, 11);
    public static readonly Asn1Tag ModifyDnRequest = new(Asn1TagClass.Application, 12);
    public static readonly Asn1Tag ModifyDnResponse = new(Asn1TagClass.Application, 13);
    public static readonly Asn1Tag CompareRequest = new(Asn1TagClass.Application, 14);
    public static readonly Asn1Tag CompareResponse = new(Asn1TagClass.Application, 15);
    public static readonly Asn1Tag AbandonRequest = new(Asn1TagClass.Application, 16);
    public static readonly Asn1Tag ExtendedRequest = new(Asn1TagClass.Application, 23);
    public static readonly Asn1Tag ExtendedResponse = new(Asn1TagClass.Application, 24);
    public static readonly Asn1Tag IntermediateResponse = new(Asn1TagClass.Application, 25);

    // Context-specific tags for various fields
    public static readonly Asn1Tag Context0 = new(Asn1TagClass.Context, 0);
    public static readonly Asn1Tag Context1 = new(Asn1TagClass.Context, 1);
    public static readonly Asn1Tag Context2 = new(Asn1TagClass.Context, 2);
    public static readonly Asn1Tag Context3 = new(Asn1TagClass.Context, 3);
    public static readonly Asn1Tag Context4 = new(Asn1TagClass.Context, 4);
    public static readonly Asn1Tag Context5 = new(Asn1TagClass.Context, 5);
    public static readonly Asn1Tag Context6 = new(Asn1TagClass.Context, 6);
    public static readonly Asn1Tag Context7 = new(Asn1TagClass.Context, 7);
    public static readonly Asn1Tag Context8 = new(Asn1TagClass.Context, 8);
    public static readonly Asn1Tag Context9 = new(Asn1TagClass.Context, 9);
    public static readonly Asn1Tag Context10 = new(Asn1TagClass.Context, 10);

    // Search filter tags (context-specific within Filter CHOICE)
    public static readonly Asn1Tag FilterAnd = new(Asn1TagClass.Context, 0);
    public static readonly Asn1Tag FilterOr = new(Asn1TagClass.Context, 1);
    public static readonly Asn1Tag FilterNot = new(Asn1TagClass.Context, 2);
    public static readonly Asn1Tag FilterEquality = new(Asn1TagClass.Context, 3);
    public static readonly Asn1Tag FilterSubstrings = new(Asn1TagClass.Context, 4);
    public static readonly Asn1Tag FilterGreaterOrEqual = new(Asn1TagClass.Context, 5);
    public static readonly Asn1Tag FilterLessOrEqual = new(Asn1TagClass.Context, 6);
    public static readonly Asn1Tag FilterPresent = new(Asn1TagClass.Context, 7);
    public static readonly Asn1Tag FilterApproxMatch = new(Asn1TagClass.Context, 8);
    public static readonly Asn1Tag FilterExtensibleMatch = new(Asn1TagClass.Context, 9);

    // Bind authentication choice tags
    public static readonly Asn1Tag AuthSimple = new(Asn1TagClass.Context, 0);
    public static readonly Asn1Tag AuthSasl = new(Asn1TagClass.Context, 3);

    // Controls
    public static readonly Asn1Tag Controls = new(Asn1TagClass.Context, 0);

    // Extended operation fields
    public static readonly Asn1Tag ExtendedRequestName = new(Asn1TagClass.Context, 0);
    public static readonly Asn1Tag ExtendedRequestValue = new(Asn1TagClass.Context, 1);
    public static readonly Asn1Tag ExtendedResponseName = new(Asn1TagClass.Context, 10);
    public static readonly Asn1Tag ExtendedResponseValue = new(Asn1TagClass.Context, 11);

    // SASL credentials in bind response
    public static readonly Asn1Tag ServerSaslCreds = new(Asn1TagClass.Context, 7);
}
