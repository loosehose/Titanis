using System.Text;

namespace Titanis.Net.Ldap.Protocol.Search;

/// <summary>
/// Parser for LDAP filter strings per RFC 4515.
/// </summary>
internal sealed class LdapFilterParser
{
    private readonly string _filter;
    private int _pos;

    public LdapFilterParser(string filter)
    {
        _filter = filter ?? throw new ArgumentNullException(nameof(filter));
        _pos = 0;
    }

    public LdapFilter Parse()
    {
        var filter = ParseFilter();

        if (_pos < _filter.Length)
            throw new FormatException($"Unexpected character at position {_pos}");

        return filter;
    }

    private LdapFilter ParseFilter()
    {
        Expect('(');
        var filter = ParseFilterComp();
        Expect(')');
        return filter;
    }

    private LdapFilter ParseFilterComp()
    {
        var c = Peek();
        return c switch
        {
            '&' => ParseAndFilter(),
            '|' => ParseOrFilter(),
            '!' => ParseNotFilter(),
            _ => ParseItem()
        };
    }

    private LdapFilter ParseAndFilter()
    {
        Expect('&');
        return new AndFilter(ParseFilterList());
    }

    private LdapFilter ParseOrFilter()
    {
        Expect('|');
        return new OrFilter(ParseFilterList());
    }

    private LdapFilter ParseNotFilter()
    {
        Expect('!');
        return new NotFilter(ParseFilter());
    }

    private List<LdapFilter> ParseFilterList()
    {
        var filters = new List<LdapFilter>();

        while (Peek() == '(')
        {
            filters.Add(ParseFilter());
        }

        if (filters.Count == 0)
            throw new FormatException("Expected at least one filter in filter list");

        return filters;
    }

    private LdapFilter ParseItem()
    {
        // Parse attribute description
        var attr = ParseAttributeDescription();

        // Check for extensible match
        if (attr.Contains(':') || Peek() == ':')
        {
            return ParseExtensibleMatch(attr);
        }

        // Parse filtertype
        var filterType = ParseFilterType();

        // Parse assertion value
        var value = ParseAssertionValue();

        return filterType switch
        {
            FilterType.Equal when value == "*" => new PresenceFilter(attr),
            FilterType.Equal when value.Contains('*') => ParseSubstringFilter(attr, value),
            FilterType.Equal => new EqualityFilter(attr, value),
            FilterType.GreaterOrEqual => new GreaterOrEqualFilter(attr, value),
            FilterType.LessOrEqual => new LessOrEqualFilter(attr, value),
            FilterType.Approx => new ApproxMatchFilter(attr, value),
            _ => throw new FormatException($"Unknown filter type: {filterType}")
        };
    }

    private LdapFilter ParseExtensibleMatch(string attrPart)
    {
        // RFC 4515 extensible match syntax:
        //   attr [":dn"] [":" matchingrule] ":=" assertionvalue
        //   [":dn"] ":" matchingrule ":=" assertionvalue
        //
        // When we enter, attrPart is the attribute name (or empty if started with ':').
        // Current position in _filter is at the first ':' after the attribute name.

        string? attr = string.IsNullOrEmpty(attrPart) ? null : attrPart;
        string? matchingRule = null;
        bool dnAttributes = false;

        // Parse colon-separated components until we hit ":="
        while (Peek() == ':')
        {
            Advance(); // consume ':'

            // Check if this is the ":=" that ends the match descriptor
            if (Peek() == '=')
            {
                Advance(); // consume '='
                var value = ParseAssertionValue();
                return new ExtensibleMatchFilter(matchingRule, attr, value, dnAttributes);
            }

            // Read the token between this ':' and the next ':' or '='
            var token = ReadUntilColonOrEquals();

            if (string.Equals(token, "dn", StringComparison.OrdinalIgnoreCase))
            {
                dnAttributes = true;
            }
            else if (!string.IsNullOrEmpty(token))
            {
                matchingRule = token;
            }
        }

        throw new FormatException($"Expected ':=' in extensible match at position {_pos}");
    }

    /// <summary>
    /// Reads characters until ':' or '=' or ')' is encountered.
    /// </summary>
    private string ReadUntilColonOrEquals()
    {
        var sb = new StringBuilder();
        while (_pos < _filter.Length)
        {
            var c = _filter[_pos];
            if (c == ':' || c == '=' || c == ')')
                break;
            sb.Append(c);
            _pos++;
        }
        return sb.ToString();
    }

    private LdapFilter ParseSubstringFilter(string attr, string value)
    {
        var parts = SplitSubstring(value);
        string? initial = null;
        var any = new List<string>();
        string? final = null;

        for (int i = 0; i < parts.Count; i++)
        {
            if (i == 0 && !value.StartsWith('*'))
            {
                initial = parts[i];
            }
            else if (i == parts.Count - 1 && !value.EndsWith('*'))
            {
                final = parts[i];
            }
            else if (!string.IsNullOrEmpty(parts[i]))
            {
                any.Add(parts[i]);
            }
        }

        return new SubstringFilter(attr, initial, any.Count > 0 ? any : null, final);
    }

    private static List<string> SplitSubstring(string value)
    {
        var parts = new List<string>();
        var current = new StringBuilder();

        for (int i = 0; i < value.Length; i++)
        {
            if (value[i] == '*')
            {
                parts.Add(current.ToString());
                current.Clear();
            }
            else if (value[i] == '\\' && i + 2 < value.Length)
            {
                // Escaped character
                var hex = value.Substring(i + 1, 2);
                if (byte.TryParse(hex, System.Globalization.NumberStyles.HexNumber, null, out var b))
                {
                    current.Append((char)b);
                    i += 2;
                }
                else
                {
                    current.Append(value[i]);
                }
            }
            else
            {
                current.Append(value[i]);
            }
        }

        parts.Add(current.ToString());
        return parts;
    }

    private string ParseAttributeDescription()
    {
        var sb = new StringBuilder();

        while (_pos < _filter.Length)
        {
            var c = _filter[_pos];
            if (c == '=' || c == '>' || c == '<' || c == '~' || c == ')' || c == ':')
                break;

            sb.Append(c);
            _pos++;
        }

        return sb.ToString();
    }

    private FilterType ParseFilterType()
    {
        var c = Peek();
        return c switch
        {
            '=' => Consume('=', FilterType.Equal),
            '>' when PeekNext() == '=' => Consume2('>', '=', FilterType.GreaterOrEqual),
            '<' when PeekNext() == '=' => Consume2('<', '=', FilterType.LessOrEqual),
            '~' when PeekNext() == '=' => Consume2('~', '=', FilterType.Approx),
            ':' when PeekNext() == '=' => Consume2(':', '=', FilterType.Extensible),
            _ => throw new FormatException($"Expected filter type at position {_pos}, got '{c}'")
        };
    }

    private string ParseAssertionValue()
    {
        var sb = new StringBuilder();

        while (_pos < _filter.Length)
        {
            var c = _filter[_pos];
            if (c == ')')
                break;

            if (c == '\\' && _pos + 2 < _filter.Length)
            {
                // Escaped character
                var hex = _filter.Substring(_pos + 1, 2);
                if (byte.TryParse(hex, System.Globalization.NumberStyles.HexNumber, null, out var b))
                {
                    sb.Append((char)b);
                    _pos += 3;
                    continue;
                }
            }

            sb.Append(c);
            _pos++;
        }

        return sb.ToString();
    }

    private char Peek() => _pos < _filter.Length ? _filter[_pos] : '\0';
    private char PeekNext() => _pos + 1 < _filter.Length ? _filter[_pos + 1] : '\0';
    private void Advance() => _pos++;

    private void Expect(char expected)
    {
        if (_pos >= _filter.Length || _filter[_pos] != expected)
            throw new FormatException($"Expected '{expected}' at position {_pos}");
        _pos++;
    }

    private FilterType Consume(char c, FilterType type)
    {
        Expect(c);
        return type;
    }

    private FilterType Consume2(char c1, char c2, FilterType type)
    {
        Expect(c1);
        Expect(c2);
        return type;
    }

    private enum FilterType
    {
        Equal,
        GreaterOrEqual,
        LessOrEqual,
        Approx,
        Extensible,
    }
}
