using System.Runtime.CompilerServices;
using Titanis.Net.Ldap.Client;
using Titanis.Net.Ldap.Protocol.Search;

namespace Titanis.Net.Ldap.ActiveDirectory;

/// <summary>
/// Active Directory-specific LDAP client.
/// </summary>
public sealed class AdClient : IAsyncDisposable
{
    private readonly LdapClient _ldap;
    private string? _defaultNamingContext;
    private string? _configurationNamingContext;
    private string? _schemaNamingContext;
    private string? _rootDomainNamingContext;

    /// <summary>
    /// Gets the default naming context (domain DN).
    /// </summary>
    public string DefaultNamingContext => _defaultNamingContext ?? throw new InvalidOperationException("Not connected");

    /// <summary>
    /// Gets the configuration naming context.
    /// </summary>
    public string ConfigurationNamingContext => _configurationNamingContext ?? throw new InvalidOperationException("Not connected");

    /// <summary>
    /// Initializes a new instance of the <see cref="AdClient"/> class.
    /// </summary>
    public AdClient(string domainController, int port = 389)
    {
        _ldap = new LdapClient(domainController, port);
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="AdClient"/> class.
    /// </summary>
    public AdClient(LdapConnectionOptions options)
    {
        _ldap = new LdapClient(options);
    }

    /// <summary>
    /// Connects and binds to the Active Directory server.
    /// </summary>
    public async Task ConnectAsync(string? dn = null, string? password = null, CancellationToken cancellationToken = default)
    {
        await _ldap.ConnectAsync(cancellationToken).ConfigureAwait(false);

        if (dn != null && password != null)
        {
            await _ldap.BindSimpleAsync(dn, password, cancellationToken).ConfigureAwait(false);
        }

        // Read RootDSE to get naming contexts
        var rootDse = await _ldap.GetRootDseAsync(cancellationToken).ConfigureAwait(false);
        if (rootDse != null)
        {
            _defaultNamingContext = rootDse.GetSingleValue("defaultNamingContext");
            _configurationNamingContext = rootDse.GetSingleValue("configurationNamingContext");
            _schemaNamingContext = rootDse.GetSingleValue("schemaNamingContext");
            _rootDomainNamingContext = rootDse.GetSingleValue("rootDomainNamingContext");
        }
    }

    /// <summary>
    /// Enumerates domain computers.
    /// </summary>
    /// <remarks>
    /// This is the key method for Snaffler target discovery.
    /// </remarks>
    public async IAsyncEnumerable<AdComputerEntry> GetComputersAsync(
        bool enabledOnly = true,
        [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        // Filter for computer objects
        // userAccountControl bit 2 = ACCOUNTDISABLE
        var filter = enabledOnly
            ? "(&(objectCategory=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
            : "(objectCategory=computer)";

        var attributes = new[]
        {
            "dNSHostName",
            "name",
            "sAMAccountName",
            "operatingSystem",
            "operatingSystemVersion",
            "operatingSystemServicePack",
            "lastLogonTimestamp",
            "userAccountControl",
            "distinguishedName"
        };

        await foreach (var entry in _ldap.SearchAsync(
            DefaultNamingContext,
            filter,
            SearchScope.WholeSubtree,
            attributes,
            cancellationToken: cancellationToken))
        {
            yield return AdComputerEntry.FromLdapEntry(entry);
        }
    }

    /// <summary>
    /// Enumerates domain users.
    /// </summary>
    public async IAsyncEnumerable<AdUserEntry> GetUsersAsync(
        bool enabledOnly = true,
        [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        var filter = enabledOnly
            ? "(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
            : "(&(objectCategory=person)(objectClass=user))";

        var attributes = new[]
        {
            "sAMAccountName",
            "userPrincipalName",
            "displayName",
            "mail",
            "memberOf",
            "lastLogonTimestamp",
            "userAccountControl",
            "distinguishedName"
        };

        await foreach (var entry in _ldap.SearchAsync(
            DefaultNamingContext,
            filter,
            SearchScope.WholeSubtree,
            attributes,
            cancellationToken: cancellationToken))
        {
            yield return AdUserEntry.FromLdapEntry(entry);
        }
    }

    /// <summary>
    /// Enumerates domain groups.
    /// </summary>
    public async IAsyncEnumerable<AdGroupEntry> GetGroupsAsync(
        [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        var filter = "(objectCategory=group)";

        var attributes = new[]
        {
            "name",
            "sAMAccountName",
            "description",
            "member",
            "memberOf",
            "groupType",
            "distinguishedName"
        };

        await foreach (var entry in _ldap.SearchAsync(
            DefaultNamingContext,
            filter,
            SearchScope.WholeSubtree,
            attributes,
            cancellationToken: cancellationToken))
        {
            yield return AdGroupEntry.FromLdapEntry(entry);
        }
    }

    /// <summary>
    /// Gets the members of a group.
    /// </summary>
    public async IAsyncEnumerable<string> GetGroupMembersAsync(
        string groupDn,
        bool recursive = false,
        [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        var visited = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var queue = new Queue<string>();
        queue.Enqueue(groupDn);

        while (queue.Count > 0)
        {
            var currentGroup = queue.Dequeue();
            if (!visited.Add(currentGroup))
                continue;

            var filter = $"(memberOf={EscapeFilter(currentGroup)})";

            await foreach (var entry in _ldap.SearchAsync(
                DefaultNamingContext,
                filter,
                SearchScope.WholeSubtree,
                new[] { "objectClass", "distinguishedName" },
                cancellationToken: cancellationToken))
            {
                yield return entry.DistinguishedName;

                // If recursive and this is a group, add it to the queue
                if (recursive)
                {
                    var objectClasses = entry.GetValues("objectClass").ToList();
                    if (objectClasses.Contains("group", StringComparer.OrdinalIgnoreCase))
                    {
                        queue.Enqueue(entry.DistinguishedName);
                    }
                }
            }
        }
    }

    /// <summary>
    /// Performs a raw LDAP search.
    /// </summary>
    public IAsyncEnumerable<LdapEntry> SearchAsync(
        string baseDn,
        string filter,
        SearchScope scope = SearchScope.WholeSubtree,
        string[]? attributes = null,
        CancellationToken cancellationToken = default)
    {
        return _ldap.SearchAsync(baseDn, filter, scope, attributes, cancellationToken: cancellationToken);
    }

    private static string EscapeFilter(string value)
    {
        return value
            .Replace("\\", "\\5c")
            .Replace("*", "\\2a")
            .Replace("(", "\\28")
            .Replace(")", "\\29")
            .Replace("\0", "\\00");
    }

    /// <inheritdoc/>
    public async ValueTask DisposeAsync()
    {
        await _ldap.DisposeAsync().ConfigureAwait(false);
    }
}

/// <summary>
/// Represents an Active Directory computer entry.
/// </summary>
public sealed class AdComputerEntry
{
    public string DistinguishedName { get; init; } = "";
    public string? DnsHostName { get; init; }
    public string? Name { get; init; }
    public string? SamAccountName { get; init; }
    public string? OperatingSystem { get; init; }
    public string? OperatingSystemVersion { get; init; }
    public string? OperatingSystemServicePack { get; init; }
    public DateTime? LastLogon { get; init; }
    public int UserAccountControl { get; init; }
    public bool Enabled => (UserAccountControl & 0x0002) == 0; // ACCOUNTDISABLE = 0x0002

    /// <summary>
    /// Gets the target hostname for scanning.
    /// </summary>
    public string GetTargetHostname()
    {
        if (!string.IsNullOrEmpty(DnsHostName))
            return DnsHostName;

        if (!string.IsNullOrEmpty(Name))
            return Name;

        // Extract CN from DN
        if (DistinguishedName.StartsWith("CN=", StringComparison.OrdinalIgnoreCase))
        {
            var commaIdx = DistinguishedName.IndexOf(',');
            return commaIdx > 3
                ? DistinguishedName[3..commaIdx]
                : DistinguishedName[3..];
        }

        return DistinguishedName;
    }

    internal static AdComputerEntry FromLdapEntry(LdapEntry entry)
    {
        return new AdComputerEntry
        {
            DistinguishedName = entry.DistinguishedName,
            DnsHostName = entry.GetSingleValue("dNSHostName"),
            Name = entry.GetSingleValue("name"),
            SamAccountName = entry.GetSingleValue("sAMAccountName"),
            OperatingSystem = entry.GetSingleValue("operatingSystem"),
            OperatingSystemVersion = entry.GetSingleValue("operatingSystemVersion"),
            OperatingSystemServicePack = entry.GetSingleValue("operatingSystemServicePack"),
            LastLogon = ParseFileTime(entry.GetSingleValue("lastLogonTimestamp")),
            UserAccountControl = ParseInt(entry.GetSingleValue("userAccountControl"))
        };
    }

    private static DateTime? ParseFileTime(string? value)
    {
        if (string.IsNullOrEmpty(value) || !long.TryParse(value, out var fileTime) || fileTime == 0)
            return null;

        try
        {
            return DateTime.FromFileTimeUtc(fileTime);
        }
        catch
        {
            return null;
        }
    }

    private static int ParseInt(string? value)
    {
        return int.TryParse(value, out var result) ? result : 0;
    }
}

/// <summary>
/// Represents an Active Directory user entry.
/// </summary>
public sealed class AdUserEntry
{
    public string DistinguishedName { get; init; } = "";
    public string? SamAccountName { get; init; }
    public string? UserPrincipalName { get; init; }
    public string? DisplayName { get; init; }
    public string? Mail { get; init; }
    public IReadOnlyList<string> MemberOf { get; init; } = Array.Empty<string>();
    public DateTime? LastLogon { get; init; }
    public int UserAccountControl { get; init; }
    public bool Enabled => (UserAccountControl & 0x0002) == 0;

    internal static AdUserEntry FromLdapEntry(LdapEntry entry)
    {
        return new AdUserEntry
        {
            DistinguishedName = entry.DistinguishedName,
            SamAccountName = entry.GetSingleValue("sAMAccountName"),
            UserPrincipalName = entry.GetSingleValue("userPrincipalName"),
            DisplayName = entry.GetSingleValue("displayName"),
            Mail = entry.GetSingleValue("mail"),
            MemberOf = entry.GetValues("memberOf").ToList(),
            LastLogon = ParseFileTime(entry.GetSingleValue("lastLogonTimestamp")),
            UserAccountControl = ParseInt(entry.GetSingleValue("userAccountControl"))
        };
    }

    private static DateTime? ParseFileTime(string? value)
    {
        if (string.IsNullOrEmpty(value) || !long.TryParse(value, out var fileTime) || fileTime == 0)
            return null;

        try
        {
            return DateTime.FromFileTimeUtc(fileTime);
        }
        catch
        {
            return null;
        }
    }

    private static int ParseInt(string? value)
    {
        return int.TryParse(value, out var result) ? result : 0;
    }
}

/// <summary>
/// Represents an Active Directory group entry.
/// </summary>
public sealed class AdGroupEntry
{
    public string DistinguishedName { get; init; } = "";
    public string? Name { get; init; }
    public string? SamAccountName { get; init; }
    public string? Description { get; init; }
    public IReadOnlyList<string> Members { get; init; } = Array.Empty<string>();
    public IReadOnlyList<string> MemberOf { get; init; } = Array.Empty<string>();
    public int GroupType { get; init; }

    internal static AdGroupEntry FromLdapEntry(LdapEntry entry)
    {
        return new AdGroupEntry
        {
            DistinguishedName = entry.DistinguishedName,
            Name = entry.GetSingleValue("name"),
            SamAccountName = entry.GetSingleValue("sAMAccountName"),
            Description = entry.GetSingleValue("description"),
            Members = entry.GetValues("member").ToList(),
            MemberOf = entry.GetValues("memberOf").ToList(),
            GroupType = ParseInt(entry.GetSingleValue("groupType"))
        };
    }

    private static int ParseInt(string? value)
    {
        return int.TryParse(value, out var result) ? result : 0;
    }
}
