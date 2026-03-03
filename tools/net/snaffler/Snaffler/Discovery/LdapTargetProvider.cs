using System.Runtime.CompilerServices;
using Titanis.Net.Ldap.ActiveDirectory;
using Titanis.Net.Ldap.Client;

namespace Titanis.Snaffler.Cli.Discovery;

/// <summary>
/// Provides targets from LDAP/Active Directory computer enumeration.
/// </summary>
public sealed class LdapTargetProvider : ITargetProvider
{
    private readonly string _domainController;
    private readonly LdapConnectionOptions _options;
    private readonly string? _bindDn;
    private readonly string? _bindPassword;

    /// <summary>
    /// Initializes a new instance of the <see cref="LdapTargetProvider"/> class.
    /// </summary>
    /// <param name="domainController">The domain controller hostname.</param>
    /// <param name="port">The LDAP port (default: 389).</param>
    /// <param name="bindDn">Optional DN for binding.</param>
    /// <param name="bindPassword">Optional password for binding.</param>
    public LdapTargetProvider(
        string domainController,
        int port = 389,
        string? bindDn = null,
        string? bindPassword = null)
    {
        _domainController = domainController ?? throw new ArgumentNullException(nameof(domainController));
        _options = new LdapConnectionOptions
        {
            Host = domainController,
            Port = port,
            UseSsl = port == 636
        };
        _bindDn = bindDn;
        _bindPassword = bindPassword;
    }

    /// <inheritdoc/>
    public async IAsyncEnumerable<TargetSpec> GetTargetsAsync(
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        await using var client = new AdClient(_options);

        await client.ConnectAsync(_bindDn, _bindPassword, cancellationToken);

        await foreach (var computer in client.GetComputersAsync(enabledOnly: true, cancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();

            var hostname = computer.GetTargetHostname();
            if (!string.IsNullOrWhiteSpace(hostname))
            {
                yield return TargetSpec.FromHost(hostname);
            }
        }
    }
}
