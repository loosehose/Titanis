using System.Runtime.CompilerServices;
using System.Text;
using Titanis.Net.Ldap.Protocol;
using Titanis.Net.Ldap.Protocol.Controls;
using Titanis.Net.Ldap.Protocol.Requests;
using Titanis.Net.Ldap.Protocol.Responses;
using Titanis.Net.Ldap.Protocol.Search;

namespace Titanis.Net.Ldap.Client;

/// <summary>
/// High-level LDAP client with a user-friendly API.
/// </summary>
public sealed class LdapClient : IAsyncDisposable
{
    private readonly LdapConnectionOptions _options;
    private LdapConnection? _connection;

    /// <summary>
    /// Initializes a new instance of the <see cref="LdapClient"/> class.
    /// </summary>
    public LdapClient(string host, int port = 389)
    {
        _options = new LdapConnectionOptions
        {
            Host = host,
            Port = port
        };
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="LdapClient"/> class.
    /// </summary>
    public LdapClient(LdapConnectionOptions options)
    {
        _options = options ?? throw new ArgumentNullException(nameof(options));
    }

    /// <summary>
    /// Gets whether the client is connected.
    /// </summary>
    public bool IsConnected => _connection?.IsConnected ?? false;

    /// <summary>
    /// Connects to the LDAP server.
    /// </summary>
    public async Task ConnectAsync(CancellationToken cancellationToken = default)
    {
        _connection = new LdapConnection(_options);
        await _connection.ConnectAsync(cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Performs a simple bind (username/password authentication).
    /// </summary>
    public async Task BindSimpleAsync(string dn, string password, CancellationToken cancellationToken = default)
    {
        EnsureConnected();

        var request = BindRequest.CreateSimple(dn, password);
        var response = await _connection!.SendAsync(request, cancellationToken: cancellationToken).ConfigureAwait(false);

        if (response.ProtocolOp is not BindResponse bindResponse)
            throw new InvalidOperationException("Unexpected response type");

        if (!bindResponse.IsSuccess)
            throw new LdapException(bindResponse);
    }

    /// <summary>
    /// Performs a SASL bind.
    /// </summary>
    public async Task<BindResponse> BindSaslAsync(string mechanism, byte[]? credentials = null, CancellationToken cancellationToken = default)
    {
        EnsureConnected();

        var request = BindRequest.CreateSasl(mechanism, credentials);
        var response = await _connection!.SendAsync(request, cancellationToken: cancellationToken).ConfigureAwait(false);

        if (response.ProtocolOp is not BindResponse bindResponse)
            throw new InvalidOperationException("Unexpected response type");

        return bindResponse;
    }

    /// <summary>
    /// Performs an LDAP search.
    /// </summary>
    public async IAsyncEnumerable<LdapEntry> SearchAsync(
        string baseDn,
        string filter,
        SearchScope scope = SearchScope.WholeSubtree,
        string[]? attributes = null,
        int sizeLimit = 0,
        int timeLimit = 0,
        [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        EnsureConnected();

        var request = new SearchRequest
        {
            BaseDn = baseDn,
            Filter = LdapFilter.Parse(filter),
            Scope = scope,
            Attributes = attributes ?? Array.Empty<string>(),
            SizeLimit = sizeLimit,
            TimeLimit = timeLimit
        };

        await foreach (var msg in _connection!.SendSearchAsync(request, cancellationToken: cancellationToken).ConfigureAwait(false))
        {
            if (msg.ProtocolOp is SearchResultEntry entry)
            {
                yield return LdapEntry.FromSearchResultEntry(entry);
            }
            else if (msg.ProtocolOp is SearchResultDone done)
            {
                if (!done.IsSuccess && done.ResultCode != LdapResultCode.SizeLimitExceeded)
                    throw new LdapException(done);
                break;
            }
            else if (msg.ProtocolOp is SearchResultReference)
            {
                // Ignore referrals for now
            }
        }
    }

    /// <summary>
    /// Performs a paged LDAP search for large result sets.
    /// </summary>
    public async IAsyncEnumerable<LdapEntry> SearchPagedAsync(
        string baseDn,
        string filter,
        int pageSize = 1000,
        SearchScope scope = SearchScope.WholeSubtree,
        string[]? attributes = null,
        [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        EnsureConnected();

        byte[]? cookie = null;

        do
        {
            var request = new SearchRequest
            {
                BaseDn = baseDn,
                Filter = LdapFilter.Parse(filter),
                Scope = scope,
                Attributes = attributes ?? Array.Empty<string>()
            };

            var controls = new List<LdapControl>
            {
                new PagedResultsControl(pageSize, cookie)
            };

            SearchResultDone? done = null;

            await foreach (var msg in _connection!.SendSearchAsync(request, controls, cancellationToken).ConfigureAwait(false))
            {
                if (msg.ProtocolOp is SearchResultEntry entry)
                {
                    yield return LdapEntry.FromSearchResultEntry(entry);
                }
                else if (msg.ProtocolOp is SearchResultDone d)
                {
                    done = d;
                    break;
                }
            }

            if (done == null)
                throw new InvalidOperationException("Search did not complete");

            if (!done.IsSuccess)
                throw new LdapException(done);

            // Extract cookie from response controls
            cookie = null;
            if (done is LdapResult result)
            {
                // The cookie is in the controls of the response message
                // For now, we'll need to track this differently
            }

            // TODO: Extract paged results cookie from response controls
            // For now, break after first page
            break;

        } while (cookie != null && cookie.Length > 0);
    }

    /// <summary>
    /// Reads the RootDSE (directory service info).
    /// </summary>
    public async Task<LdapEntry?> GetRootDseAsync(CancellationToken cancellationToken = default)
    {
        await foreach (var entry in SearchAsync(
            "",
            "(objectClass=*)",
            SearchScope.BaseObject,
            new[] { "*", "+" },
            cancellationToken: cancellationToken).ConfigureAwait(false))
        {
            return entry;
        }

        return null;
    }

    private void EnsureConnected()
    {
        if (_connection == null || !_connection.IsConnected)
            throw new InvalidOperationException("Not connected. Call ConnectAsync first.");
    }

    /// <inheritdoc/>
    public async ValueTask DisposeAsync()
    {
        if (_connection != null)
        {
            await _connection.DisposeAsync().ConfigureAwait(false);
            _connection = null;
        }
    }
}

/// <summary>
/// Represents an LDAP directory entry.
/// </summary>
public sealed class LdapEntry
{
    /// <summary>
    /// Gets the distinguished name.
    /// </summary>
    public string DistinguishedName { get; init; } = "";

    /// <summary>
    /// Gets the attributes.
    /// </summary>
    public IReadOnlyDictionary<string, LdapAttribute> Attributes { get; init; } = new Dictionary<string, LdapAttribute>();

    /// <summary>
    /// Gets a single attribute value.
    /// </summary>
    public string? GetSingleValue(string attributeName)
    {
        return Attributes.TryGetValue(attributeName.ToLowerInvariant(), out var attr)
            ? attr.StringValues.FirstOrDefault()
            : null;
    }

    /// <summary>
    /// Gets all values for an attribute.
    /// </summary>
    public IEnumerable<string> GetValues(string attributeName)
    {
        return Attributes.TryGetValue(attributeName.ToLowerInvariant(), out var attr)
            ? attr.StringValues
            : [];
    }

    /// <summary>
    /// Gets raw binary values for an attribute.
    /// </summary>
    public IEnumerable<byte[]> GetBinaryValues(string attributeName)
    {
        return Attributes.TryGetValue(attributeName.ToLowerInvariant(), out var attr)
            ? attr.BinaryValues
            : [];
    }

    /// <summary>
    /// Creates an entry from a search result.
    /// </summary>
    internal static LdapEntry FromSearchResultEntry(SearchResultEntry entry)
    {
        var attributes = new Dictionary<string, LdapAttribute>(StringComparer.OrdinalIgnoreCase);

        foreach (var attr in entry.Attributes)
        {
            attributes[attr.Type.ToLowerInvariant()] = new LdapAttribute
            {
                Name = attr.Type,
                BinaryValues = attr.Values.ToList()
            };
        }

        return new LdapEntry
        {
            DistinguishedName = entry.ObjectName,
            Attributes = attributes
        };
    }
}

/// <summary>
/// Represents an LDAP attribute with values.
/// </summary>
public sealed class LdapAttribute
{
    /// <summary>
    /// Gets the attribute name.
    /// </summary>
    public string Name { get; init; } = "";

    /// <summary>
    /// Gets the raw binary values.
    /// </summary>
    public IReadOnlyList<byte[]> BinaryValues { get; init; } = Array.Empty<byte[]>();

    /// <summary>
    /// Gets the values as strings.
    /// </summary>
    public IEnumerable<string> StringValues => BinaryValues.Select(v => Encoding.UTF8.GetString(v));

    /// <summary>
    /// Gets the first value as a string.
    /// </summary>
    public string? FirstStringValue => BinaryValues.Count > 0 ? Encoding.UTF8.GetString(BinaryValues[0]) : null;
}
