using System.Text;
using Titanis.Asn1;
using Titanis.Asn1.Serialization;

namespace Titanis.Net.Ldap.Protocol.Search;

/// <summary>
/// Base class for LDAP search filters per RFC 4515.
/// </summary>
public abstract class LdapFilter
{
    /// <summary>
    /// Encodes this filter to the encoder.
    /// </summary>
    public abstract void EncodeTlv(Asn1DerEncoder encoder);

    /// <summary>
    /// Returns the string representation of this filter.
    /// </summary>
    public abstract override string ToString();

    /// <summary>
    /// Parses an LDAP filter string per RFC 4515.
    /// </summary>
    /// <param name="filter">The filter string.</param>
    /// <returns>The parsed filter.</returns>
    public static LdapFilter Parse(string filter)
    {
        if (string.IsNullOrWhiteSpace(filter))
            throw new ArgumentException("Filter cannot be empty", nameof(filter));

        var parser = new LdapFilterParser(filter);
        return parser.Parse();
    }

    /// <summary>
    /// Creates an equality filter: (attr=value)
    /// </summary>
    public static LdapFilter Equal(string attribute, string value)
        => new EqualityFilter(attribute, value);

    /// <summary>
    /// Creates a presence filter: (attr=*)
    /// </summary>
    public static LdapFilter Present(string attribute)
        => new PresenceFilter(attribute);

    /// <summary>
    /// Creates an AND filter: (&amp;(filter1)(filter2)...)
    /// </summary>
    public static LdapFilter And(params LdapFilter[] filters)
        => new AndFilter(filters);

    /// <summary>
    /// Creates an OR filter: (|(filter1)(filter2)...)
    /// </summary>
    public static LdapFilter Or(params LdapFilter[] filters)
        => new OrFilter(filters);

    /// <summary>
    /// Creates a NOT filter: (!(filter))
    /// </summary>
    public static LdapFilter Not(LdapFilter filter)
        => new NotFilter(filter);

    /// <summary>
    /// Creates a greater-or-equal filter: (attr>=value)
    /// </summary>
    public static LdapFilter GreaterOrEqual(string attribute, string value)
        => new GreaterOrEqualFilter(attribute, value);

    /// <summary>
    /// Creates a less-or-equal filter: (attr&lt;=value)
    /// </summary>
    public static LdapFilter LessOrEqual(string attribute, string value)
        => new LessOrEqualFilter(attribute, value);

    /// <summary>
    /// Creates an approximate match filter: (attr~=value)
    /// </summary>
    public static LdapFilter ApproxMatch(string attribute, string value)
        => new ApproxMatchFilter(attribute, value);

    /// <summary>
    /// Creates a substring filter: (attr=initial*any*final)
    /// </summary>
    public static LdapFilter Substring(string attribute, string? initial, string[]? any, string? final)
        => new SubstringFilter(attribute, initial, any, final);

    /// <summary>
    /// Decodes a filter from the decoder.
    /// </summary>
    public static LdapFilter DecodeTlvFrom(Asn1DerDecoder decoder)
    {
        var tag = decoder.PeekTag();
        return tag.TagNumber switch
        {
            0 => AndFilter.DecodeTlvFrom(decoder),
            1 => OrFilter.DecodeTlvFrom(decoder),
            2 => NotFilter.DecodeTlvFrom(decoder),
            3 => EqualityFilter.DecodeTlvFrom(decoder),
            4 => SubstringFilter.DecodeTlvFrom(decoder),
            5 => GreaterOrEqualFilter.DecodeTlvFrom(decoder),
            6 => LessOrEqualFilter.DecodeTlvFrom(decoder),
            7 => PresenceFilter.DecodeTlvFrom(decoder),
            8 => ApproxMatchFilter.DecodeTlvFrom(decoder),
            9 => ExtensibleMatchFilter.DecodeTlvFrom(decoder),
            _ => throw new InvalidDataException($"Unknown filter tag: {tag}")
        };
    }

    /// <summary>
    /// Helper to encode an AttributeValueAssertion.
    /// </summary>
    protected static void EncodeAttributeValueAssertion(Asn1DerEncoder encoder, Asn1Tag tag, string attribute, string value)
    {
        var pos = encoder.Position;
        encoder.EncodeOctetStringTlv(Encoding.UTF8.GetBytes(value), LdapTags.OctetString);
        encoder.EncodeOctetStringTlv(Encoding.UTF8.GetBytes(attribute), LdapTags.OctetString);
        encoder.EncodeCloseTlvHeader(tag.AsConstructed(), pos);
    }

    /// <summary>
    /// Helper to decode an AttributeValueAssertion.
    /// </summary>
    protected static (string Attribute, string Value) DecodeAttributeValueAssertion(Asn1DerDecoder decoder, Asn1Tag tag)
    {
        var frame = decoder.DecodeTlvStart(tag.AsConstructed());
        var attribute = Encoding.UTF8.GetString(decoder.DecodeOctetStringTlv(LdapTags.OctetString));
        var value = Encoding.UTF8.GetString(decoder.DecodeOctetStringTlv(LdapTags.OctetString));
        decoder.CloseTlv(frame);
        return (attribute, value);
    }
}

/// <summary>
/// AND filter: (&amp;(filter1)(filter2)...)
/// </summary>
public sealed class AndFilter : LdapFilter
{
    public IReadOnlyList<LdapFilter> Filters { get; }

    public AndFilter(IEnumerable<LdapFilter> filters)
    {
        Filters = filters.ToList();
    }

    public override void EncodeTlv(Asn1DerEncoder encoder)
    {
        var pos = encoder.Position;
        foreach (var filter in Filters.Reverse())
        {
            filter.EncodeTlv(encoder);
        }
        encoder.EncodeCloseTlvHeader(LdapTags.FilterAnd.AsConstructed(), pos);
    }

    public override string ToString() => $"(&{string.Concat(Filters.Select(f => f.ToString()))})";

    public static new AndFilter DecodeTlvFrom(Asn1DerDecoder decoder)
    {
        var filters = new List<LdapFilter>();
        var frame = decoder.DecodeTlvStart(LdapTags.FilterAnd.AsConstructed());
        while (!decoder.IsEndOfTuple)
        {
            filters.Add(LdapFilter.DecodeTlvFrom(decoder));
        }
        decoder.CloseTlv(frame);
        return new AndFilter(filters);
    }
}

/// <summary>
/// OR filter: (|(filter1)(filter2)...)
/// </summary>
public sealed class OrFilter : LdapFilter
{
    public IReadOnlyList<LdapFilter> Filters { get; }

    public OrFilter(IEnumerable<LdapFilter> filters)
    {
        Filters = filters.ToList();
    }

    public override void EncodeTlv(Asn1DerEncoder encoder)
    {
        var pos = encoder.Position;
        foreach (var filter in Filters.Reverse())
        {
            filter.EncodeTlv(encoder);
        }
        encoder.EncodeCloseTlvHeader(LdapTags.FilterOr.AsConstructed(), pos);
    }

    public override string ToString() => $"(|{string.Concat(Filters.Select(f => f.ToString()))})";

    public static new OrFilter DecodeTlvFrom(Asn1DerDecoder decoder)
    {
        var filters = new List<LdapFilter>();
        var frame = decoder.DecodeTlvStart(LdapTags.FilterOr.AsConstructed());
        while (!decoder.IsEndOfTuple)
        {
            filters.Add(LdapFilter.DecodeTlvFrom(decoder));
        }
        decoder.CloseTlv(frame);
        return new OrFilter(filters);
    }
}

/// <summary>
/// NOT filter: (!(filter))
/// </summary>
public sealed class NotFilter : LdapFilter
{
    public LdapFilter Filter { get; }

    public NotFilter(LdapFilter filter)
    {
        Filter = filter ?? throw new ArgumentNullException(nameof(filter));
    }

    public override void EncodeTlv(Asn1DerEncoder encoder)
    {
        var pos = encoder.Position;
        Filter.EncodeTlv(encoder);
        encoder.EncodeCloseTlvHeader(LdapTags.FilterNot.AsConstructed(), pos);
    }

    public override string ToString() => $"(!{Filter})";

    public static new NotFilter DecodeTlvFrom(Asn1DerDecoder decoder)
    {
        var frame = decoder.DecodeTlvStart(LdapTags.FilterNot.AsConstructed());
        var filter = LdapFilter.DecodeTlvFrom(decoder);
        decoder.CloseTlv(frame);
        return new NotFilter(filter);
    }
}

/// <summary>
/// Equality filter: (attr=value)
/// </summary>
public sealed class EqualityFilter : LdapFilter
{
    public string Attribute { get; }
    public string Value { get; }

    public EqualityFilter(string attribute, string value)
    {
        Attribute = attribute ?? throw new ArgumentNullException(nameof(attribute));
        Value = value ?? throw new ArgumentNullException(nameof(value));
    }

    public override void EncodeTlv(Asn1DerEncoder encoder)
    {
        EncodeAttributeValueAssertion(encoder, LdapTags.FilterEquality, Attribute, Value);
    }

    public override string ToString() => $"({Attribute}={EscapeValue(Value)})";

    public static new EqualityFilter DecodeTlvFrom(Asn1DerDecoder decoder)
    {
        var (attr, val) = DecodeAttributeValueAssertion(decoder, LdapTags.FilterEquality);
        return new EqualityFilter(attr, val);
    }

    private static string EscapeValue(string value)
    {
        return value
            .Replace("\\", "\\5c")
            .Replace("*", "\\2a")
            .Replace("(", "\\28")
            .Replace(")", "\\29")
            .Replace("\0", "\\00");
    }
}

/// <summary>
/// Presence filter: (attr=*)
/// </summary>
public sealed class PresenceFilter : LdapFilter
{
    public string Attribute { get; }

    public PresenceFilter(string attribute)
    {
        Attribute = attribute ?? throw new ArgumentNullException(nameof(attribute));
    }

    public override void EncodeTlv(Asn1DerEncoder encoder)
    {
        encoder.EncodeOctetStringTlv(Encoding.UTF8.GetBytes(Attribute), LdapTags.FilterPresent);
    }

    public override string ToString() => $"({Attribute}=*)";

    public static new PresenceFilter DecodeTlvFrom(Asn1DerDecoder decoder)
    {
        var attr = Encoding.UTF8.GetString(decoder.DecodeOctetStringTlv(LdapTags.FilterPresent));
        return new PresenceFilter(attr);
    }
}

/// <summary>
/// Greater-or-equal filter: (attr>=value)
/// </summary>
public sealed class GreaterOrEqualFilter : LdapFilter
{
    public string Attribute { get; }
    public string Value { get; }

    public GreaterOrEqualFilter(string attribute, string value)
    {
        Attribute = attribute ?? throw new ArgumentNullException(nameof(attribute));
        Value = value ?? throw new ArgumentNullException(nameof(value));
    }

    public override void EncodeTlv(Asn1DerEncoder encoder)
    {
        EncodeAttributeValueAssertion(encoder, LdapTags.FilterGreaterOrEqual, Attribute, Value);
    }

    public override string ToString() => $"({Attribute}>={Value})";

    public static new GreaterOrEqualFilter DecodeTlvFrom(Asn1DerDecoder decoder)
    {
        var (attr, val) = DecodeAttributeValueAssertion(decoder, LdapTags.FilterGreaterOrEqual);
        return new GreaterOrEqualFilter(attr, val);
    }
}

/// <summary>
/// Less-or-equal filter: (attr&lt;=value)
/// </summary>
public sealed class LessOrEqualFilter : LdapFilter
{
    public string Attribute { get; }
    public string Value { get; }

    public LessOrEqualFilter(string attribute, string value)
    {
        Attribute = attribute ?? throw new ArgumentNullException(nameof(attribute));
        Value = value ?? throw new ArgumentNullException(nameof(value));
    }

    public override void EncodeTlv(Asn1DerEncoder encoder)
    {
        EncodeAttributeValueAssertion(encoder, LdapTags.FilterLessOrEqual, Attribute, Value);
    }

    public override string ToString() => $"({Attribute}<={Value})";

    public static new LessOrEqualFilter DecodeTlvFrom(Asn1DerDecoder decoder)
    {
        var (attr, val) = DecodeAttributeValueAssertion(decoder, LdapTags.FilterLessOrEqual);
        return new LessOrEqualFilter(attr, val);
    }
}

/// <summary>
/// Approximate match filter: (attr~=value)
/// </summary>
public sealed class ApproxMatchFilter : LdapFilter
{
    public string Attribute { get; }
    public string Value { get; }

    public ApproxMatchFilter(string attribute, string value)
    {
        Attribute = attribute ?? throw new ArgumentNullException(nameof(attribute));
        Value = value ?? throw new ArgumentNullException(nameof(value));
    }

    public override void EncodeTlv(Asn1DerEncoder encoder)
    {
        EncodeAttributeValueAssertion(encoder, LdapTags.FilterApproxMatch, Attribute, Value);
    }

    public override string ToString() => $"({Attribute}~={Value})";

    public static new ApproxMatchFilter DecodeTlvFrom(Asn1DerDecoder decoder)
    {
        var (attr, val) = DecodeAttributeValueAssertion(decoder, LdapTags.FilterApproxMatch);
        return new ApproxMatchFilter(attr, val);
    }
}

/// <summary>
/// Substring filter: (attr=initial*any*final)
/// </summary>
public sealed class SubstringFilter : LdapFilter
{
    public string Attribute { get; }
    public string? Initial { get; }
    public IReadOnlyList<string>? Any { get; }
    public string? Final { get; }

    public SubstringFilter(string attribute, string? initial, IEnumerable<string>? any, string? final)
    {
        Attribute = attribute ?? throw new ArgumentNullException(nameof(attribute));
        Initial = initial;
        Any = any?.ToList();
        Final = final;
    }

    public override void EncodeTlv(Asn1DerEncoder encoder)
    {
        var pos = encoder.Position;

        // Encode substrings sequence
        var subsPos = encoder.Position;
        if (Final != null)
        {
            encoder.EncodeOctetStringTlv(Encoding.UTF8.GetBytes(Final), LdapTags.Context2);
        }
        if (Any != null)
        {
            foreach (var a in Any.Reverse())
            {
                encoder.EncodeOctetStringTlv(Encoding.UTF8.GetBytes(a), LdapTags.Context1);
            }
        }
        if (Initial != null)
        {
            encoder.EncodeOctetStringTlv(Encoding.UTF8.GetBytes(Initial), LdapTags.Context0);
        }
        encoder.EncodeCloseTlvHeader(LdapTags.Sequence.AsConstructed(), subsPos);

        // Encode attribute
        encoder.EncodeOctetStringTlv(Encoding.UTF8.GetBytes(Attribute), LdapTags.OctetString);

        encoder.EncodeCloseTlvHeader(LdapTags.FilterSubstrings.AsConstructed(), pos);
    }

    public override string ToString()
    {
        var sb = new StringBuilder();
        sb.Append('(').Append(Attribute).Append('=');
        if (Initial != null) sb.Append(Initial);
        sb.Append('*');
        if (Any != null)
        {
            foreach (var a in Any)
            {
                sb.Append(a).Append('*');
            }
        }
        if (Final != null) sb.Append(Final);
        sb.Append(')');
        return sb.ToString();
    }

    public static new SubstringFilter DecodeTlvFrom(Asn1DerDecoder decoder)
    {
        var frame = decoder.DecodeTlvStart(LdapTags.FilterSubstrings.AsConstructed());

        var attribute = Encoding.UTF8.GetString(decoder.DecodeOctetStringTlv(LdapTags.OctetString));

        string? initial = null;
        var any = new List<string>();
        string? final = null;

        var subsFrame = decoder.DecodeTlvStart(LdapTags.Sequence.AsConstructed());
        while (!decoder.IsEndOfTuple)
        {
            var tag = decoder.PeekTag();
            var value = Encoding.UTF8.GetString(decoder.DecodeOctetStringTlv(tag));
            switch (tag.TagNumber)
            {
                case 0: initial = value; break;
                case 1: any.Add(value); break;
                case 2: final = value; break;
            }
        }
        decoder.CloseTlv(subsFrame);

        decoder.CloseTlv(frame);
        return new SubstringFilter(attribute, initial, any.Count > 0 ? any : null, final);
    }
}

/// <summary>
/// Extensible match filter: (attr:dn:matchingRule:=value)
/// </summary>
public sealed class ExtensibleMatchFilter : LdapFilter
{
    public string? MatchingRule { get; }
    public string? Attribute { get; }
    public string Value { get; }
    public bool DnAttributes { get; }

    public ExtensibleMatchFilter(string? matchingRule, string? attribute, string value, bool dnAttributes = false)
    {
        MatchingRule = matchingRule;
        Attribute = attribute;
        Value = value ?? throw new ArgumentNullException(nameof(value));
        DnAttributes = dnAttributes;
    }

    public override void EncodeTlv(Asn1DerEncoder encoder)
    {
        var pos = encoder.Position;

        if (DnAttributes)
        {
            encoder.EncodeBoolTlv(true, LdapTags.Context4);
        }
        encoder.EncodeOctetStringTlv(Encoding.UTF8.GetBytes(Value), LdapTags.Context3);
        if (Attribute != null)
        {
            encoder.EncodeOctetStringTlv(Encoding.UTF8.GetBytes(Attribute), LdapTags.Context2);
        }
        if (MatchingRule != null)
        {
            encoder.EncodeOctetStringTlv(Encoding.UTF8.GetBytes(MatchingRule), LdapTags.Context1);
        }

        encoder.EncodeCloseTlvHeader(LdapTags.FilterExtensibleMatch.AsConstructed(), pos);
    }

    public override string ToString()
    {
        var sb = new StringBuilder("(");
        if (Attribute != null) sb.Append(Attribute);
        if (DnAttributes) sb.Append(":dn");
        if (MatchingRule != null) sb.Append(':').Append(MatchingRule);
        sb.Append(":=").Append(Value).Append(')');
        return sb.ToString();
    }

    public static new ExtensibleMatchFilter DecodeTlvFrom(Asn1DerDecoder decoder)
    {
        var frame = decoder.DecodeTlvStart(LdapTags.FilterExtensibleMatch.AsConstructed());

        string? matchingRule = null;
        string? attribute = null;
        string value = "";
        bool dnAttributes = false;

        while (!decoder.IsEndOfTuple)
        {
            var tag = decoder.PeekTag();
            switch (tag.TagNumber)
            {
                case 1:
                    matchingRule = Encoding.UTF8.GetString(decoder.DecodeOctetStringTlv(tag));
                    break;
                case 2:
                    attribute = Encoding.UTF8.GetString(decoder.DecodeOctetStringTlv(tag));
                    break;
                case 3:
                    value = Encoding.UTF8.GetString(decoder.DecodeOctetStringTlv(tag));
                    break;
                case 4:
                    dnAttributes = decoder.DecodeBoolTlv(tag);
                    break;
                default:
                    throw new InvalidDataException($"Unexpected tag in extensible match: {tag}");
            }
        }

        decoder.CloseTlv(frame);
        return new ExtensibleMatchFilter(matchingRule, attribute, value, dnAttributes);
    }
}
