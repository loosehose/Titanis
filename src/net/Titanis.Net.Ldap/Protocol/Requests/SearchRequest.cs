using System.Text;
using Titanis.Asn1;
using Titanis.Asn1.Serialization;
using Titanis.Net.Ldap.Protocol.Search;

namespace Titanis.Net.Ldap.Protocol.Requests;

/// <summary>
/// LDAP search request per RFC 4511 Section 4.5.1.
/// </summary>
/// <remarks>
/// SearchRequest ::= [APPLICATION 3] SEQUENCE {
///     baseObject      LDAPDN,
///     scope           ENUMERATED { baseObject (0), singleLevel (1), wholeSubtree (2) },
///     derefAliases    ENUMERATED { neverDerefAliases (0), derefInSearching (1),
///                                  derefFindingBaseObj (2), derefAlways (3) },
///     sizeLimit       INTEGER (0 ..  maxInt),
///     timeLimit       INTEGER (0 ..  maxInt),
///     typesOnly       BOOLEAN,
///     filter          Filter,
///     attributes      AttributeSelection }
/// </remarks>
public sealed class SearchRequest : ILdapProtocolOp, ILdapProtocolOpDecodable<SearchRequest>
{
    /// <summary>
    /// Gets the ASN.1 tag for this operation.
    /// </summary>
    public Asn1Tag Tag => LdapTags.SearchRequest;

    /// <summary>
    /// Gets or sets the base object DN.
    /// </summary>
    public string BaseDn { get; set; } = "";

    /// <summary>
    /// Gets or sets the search scope.
    /// </summary>
    public SearchScope Scope { get; set; } = SearchScope.WholeSubtree;

    /// <summary>
    /// Gets or sets alias dereferencing behavior.
    /// </summary>
    public DerefAliases DerefAliases { get; set; } = DerefAliases.NeverDerefAliases;

    /// <summary>
    /// Gets or sets the maximum number of entries to return (0 = no limit).
    /// </summary>
    public int SizeLimit { get; set; }

    /// <summary>
    /// Gets or sets the time limit in seconds (0 = no limit).
    /// </summary>
    public int TimeLimit { get; set; }

    /// <summary>
    /// Gets or sets whether to return only attribute types (no values).
    /// </summary>
    public bool TypesOnly { get; set; }

    /// <summary>
    /// Gets or sets the search filter.
    /// </summary>
    public LdapFilter Filter { get; set; } = LdapFilter.Present("objectClass");

    /// <summary>
    /// Gets or sets the list of attributes to return (empty = all user attributes).
    /// </summary>
    public IReadOnlyList<string> Attributes { get; set; } = Array.Empty<string>();

    /// <inheritdoc/>
    public void EncodeTlv(Asn1DerEncoder encoder)
    {
        var pos = encoder.Position;

        // Encode attributes (SEQUENCE OF)
        var attrsPos = encoder.Position;
        foreach (var attr in Attributes.Reverse())
        {
            encoder.EncodeOctetStringTlv(Encoding.UTF8.GetBytes(attr), LdapTags.OctetString);
        }
        encoder.EncodeCloseTlvHeader(LdapTags.Sequence.AsConstructed(), attrsPos);

        // Encode filter
        Filter.EncodeTlv(encoder);

        // Encode typesOnly
        encoder.EncodeBoolTlv(TypesOnly, LdapTags.Boolean);

        // Encode timeLimit
        encoder.EncodeInt32Tlv(TimeLimit, LdapTags.Integer);

        // Encode sizeLimit
        encoder.EncodeInt32Tlv(SizeLimit, LdapTags.Integer);

        // Encode derefAliases
        encoder.EncodeEnumeratedTlv((int)DerefAliases, LdapTags.Enumerated);

        // Encode scope
        encoder.EncodeEnumeratedTlv((int)Scope, LdapTags.Enumerated);

        // Encode baseDN
        encoder.EncodeOctetStringTlv(Encoding.UTF8.GetBytes(BaseDn), LdapTags.OctetString);

        encoder.EncodeCloseTlvHeader(LdapTags.SearchRequest.AsConstructed(), pos);
    }

    /// <inheritdoc/>
    public static SearchRequest DecodeTlvFrom(Asn1DerDecoder decoder)
    {
        var frame = decoder.DecodeTlvStart(LdapTags.SearchRequest.AsConstructed());

        var request = new SearchRequest
        {
            BaseDn = Encoding.UTF8.GetString(decoder.DecodeOctetStringTlv(LdapTags.OctetString)),
            Scope = (SearchScope)decoder.DecodeEnumeratedTlv(LdapTags.Enumerated),
            DerefAliases = (DerefAliases)decoder.DecodeEnumeratedTlv(LdapTags.Enumerated),
            SizeLimit = decoder.DecodeIntegerTlvAsInt32(LdapTags.Integer),
            TimeLimit = decoder.DecodeIntegerTlvAsInt32(LdapTags.Integer),
            TypesOnly = decoder.DecodeBoolTlv(LdapTags.Boolean),
            Filter = LdapFilter.DecodeTlvFrom(decoder)
        };

        // Decode attributes
        var attrs = new List<string>();
        var attrsFrame = decoder.DecodeTlvStart(LdapTags.Sequence.AsConstructed());
        while (!decoder.IsEndOfTuple)
        {
            attrs.Add(Encoding.UTF8.GetString(decoder.DecodeOctetStringTlv(LdapTags.OctetString)));
        }
        decoder.CloseTlv(attrsFrame);
        request.Attributes = attrs;

        decoder.CloseTlv(frame);
        return request;
    }
}
