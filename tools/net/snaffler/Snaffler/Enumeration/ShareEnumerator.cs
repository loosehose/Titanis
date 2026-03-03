using System.ComponentModel.Design;
using System.Runtime.CompilerServices;
using Titanis.DceRpc;
using Titanis.DceRpc.Client;
using Titanis.Msrpc;
using Titanis.Msrpc.Mswkst;
using Titanis.Security;
using Titanis.Smb2;
using Titanis.Snaffler.Cli.Output;
using Titanis.Snaffler.Cli.Smb;

namespace Titanis.Snaffler.Cli.Enumeration;

/// <summary>
/// Enumerates shares on a target host.
/// </summary>
public sealed class ShareEnumerator
{
    private readonly IServiceContainer _services;
    private readonly Func<Smb2Client> _clientFactory;
    private readonly Action<string>? _verboseLog;

    /// <summary>
    /// Initializes a new instance of the <see cref="ShareEnumerator"/> class.
    /// </summary>
    /// <param name="services">Service container for dependency resolution.</param>
    /// <param name="clientFactory">Factory function to create SMB clients.</param>
    /// <param name="verboseLog">Optional callback for verbose logging.</param>
    public ShareEnumerator(
        IServiceContainer services,
        Func<Smb2Client> clientFactory,
        Action<string>? verboseLog = null)
    {
        _services = services ?? throw new ArgumentNullException(nameof(services));
        _clientFactory = clientFactory ?? throw new ArgumentNullException(nameof(clientFactory));
        _verboseLog = verboseLog;
    }

    /// <summary>
    /// Enumerates shares on a host.
    /// </summary>
    /// <param name="hostname">The hostname to enumerate.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>An async enumerable of ShareResult.</returns>
    public async IAsyncEnumerable<ShareResult> EnumerateSharesAsync(
        string hostname,
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        if (string.IsNullOrEmpty(hostname))
            throw new ArgumentException("Hostname cannot be null or empty.", nameof(hostname));

        IList<ShareInfo> shares;

        await using var client = _clientFactory();

        var serverService = new ServerServiceClient();
        var rpcClient = _services.CreateRpcClient();
        rpcClient.DefaultAuthLevel = RpcAuthLevel.None;

        var pipePath = new UncPath(hostname, Smb2Client.IpcName, ServerServiceClient.PipeName);
        await rpcClient.ConnectPipe(serverService, client, pipePath, cancellationToken)
            .ConfigureAwait(false);

        shares = await serverService.GetShares(@"\\" + hostname, ShareInfoLevel.Level1, ServerServiceClient.DefaultReturnBufferSize, cancellationToken)
            .ConfigureAwait(false);

        foreach (var share in shares)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var shareName = share.ShareName;

            // Skip null or empty share names
            if (string.IsNullOrEmpty(shareName))
                continue;

            // Skip IPC$ and PRINT$ shares
            if (string.Equals(shareName, "IPC$", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(shareName, "PRINT$", StringComparison.OrdinalIgnoreCase))
                continue;

            var result = new ShareResult
            {
                SharePath = $@"\\{hostname}\{shareName}",
                ShareComment = share.Remark,
                Listable = true
            };

            // Try to determine if share is accessible
            await TryCheckShareAccessAsync(hostname, shareName, result, cancellationToken)
                .ConfigureAwait(false);

            yield return result;
        }
    }

    /// <summary>
    /// Attempts to check if a share is accessible.
    /// </summary>
    private async Task TryCheckShareAccessAsync(
        string hostname,
        string shareName,
        ShareResult result,
        CancellationToken cancellationToken)
    {
        try
        {
            await using var testClient = _clientFactory();
            var testUncPath = new UncPath(hostname, shareName, "");
            var createInfo = CreateInfoFactory.OpenDirectoryReadOnly();

            await using var dir = await testClient.CreateFileAsync(
                testUncPath,
                createInfo,
                FileAccess.Read,
                cancellationToken).ConfigureAwait(false);

            result.RootReadable = true;
            result.RootWritable = false; // Would need separate check with write access
        }
        catch (OperationCanceledException)
        {
            throw; // Don't swallow cancellation
        }
        catch (Exception ex)
        {
            _verboseLog?.Invoke($"Cannot access \\\\{hostname}\\{shareName}: {ex.GetType().Name}");
            result.Listable = false;
            result.RootReadable = false;
        }
    }
}
