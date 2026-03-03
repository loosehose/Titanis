using System.ComponentModel;
using System.Runtime.CompilerServices;
using Titanis.Cli;
using Titanis.DceRpc;
using Titanis.DceRpc.Client;
using Titanis.Msrpc;
using Titanis.Msrpc.Mswkst;
using Titanis.Smb2;
using Titanis.Snaffler.Cli.Classification;
using Titanis.Snaffler.Cli.Discovery;
using Titanis.Snaffler.Cli.Output;
using Titanis.Snaffler.Cli.Smb;

namespace Titanis.Snaffler.Cli;

/// <summary>
/// Lists shares on target hosts without scanning content.
/// </summary>
[OutputRecordType(typeof(ShareResult))]
[Description("Enumerate shares on target hosts")]
[Example("List shares on a host", @"{0} dc01.corp.local -u admin -ud CORP -p password")]
public class ListSharesCommand : Command
{
    /// <summary>
    /// Target hosts to enumerate (comma-separated).
    /// </summary>
    [Parameter(0)]
    [Description("Target hosts to enumerate (comma-separated)")]
    [Placeholder("host1,host2,...")]
    public string[]? Targets { get; set; }

    /// <summary>
    /// File containing target hosts (one per line).
    /// </summary>
    [Parameter]
    [Alias("T")]
    [Description("File containing target hosts (one per line)")]
    public string? TargetFile { get; set; }

    /// <summary>
    /// Authentication parameters.
    /// </summary>
    [ParameterGroup(ParameterGroupOptions.AlwaysInstantiate)]
    public AuthenticationParameters AuthenticationParameters { get; set; }

    /// <summary>
    /// Network parameters.
    /// </summary>
    [ParameterGroup(ParameterGroupOptions.AlwaysInstantiate)]
    public NetworkParameters? NetParameters { get; set; }

    /// <summary>
    /// SMB parameters.
    /// </summary>
    [ParameterGroup(ParameterGroupOptions.AlwaysInstantiate)]
    public SmbParameters SmbParameters { get; set; }

    /// <inheritdoc/>
    protected override void ValidateParameters(ParameterValidationContext context)
    {
        base.ValidateParameters(context);

        NetParameters?.ValidateParameters(context);
        AuthenticationParameters.Validate(true, context);
        SmbParameters.Validate(context, AuthenticationParameters);

        bool hasTargets = (Targets != null && Targets.Length > 0) || !string.IsNullOrEmpty(TargetFile);
        if (!hasTargets)
        {
            context.LogError(nameof(Targets), "At least one target must be specified");
        }
    }

    /// <inheritdoc/>
    protected override async Task<int> RunAsync(CancellationToken cancellationToken)
    {
        var targetProvider = new CompositeTargetProvider();

        if (Targets != null && Targets.Length > 0)
        {
            targetProvider.Add(new ArgumentTargetProvider(Targets));
        }

        if (!string.IsNullOrEmpty(TargetFile))
        {
            targetProvider.Add(new FileTargetProvider(TargetFile));
        }

        await foreach (var target in targetProvider.GetTargetsAsync(cancellationToken)
            .ConfigureAwait(false))
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (string.IsNullOrEmpty(target.Hostname))
                continue;

            await EnumerateSharesAsync(target.Hostname, cancellationToken)
                .ConfigureAwait(false);
        }

        return 0;
    }

    private async Task EnumerateSharesAsync(string hostname, CancellationToken cancellationToken)
    {
        WriteVerbose($"Enumerating shares on {hostname}");

        try
        {
            await using var client = SmbParameters.CreateClient();

            var serverService = new ServerServiceClient();
            var rpcClient = this.Services.CreateRpcClient();
            rpcClient.DefaultAuthLevel = RpcAuthLevel.None;

            var pipePath = new UncPath(hostname, Smb2Client.IpcName, ServerServiceClient.PipeName);
            await rpcClient.ConnectPipe(serverService, client, pipePath, cancellationToken)
                .ConfigureAwait(false);

            var shares = await serverService.GetShares(@"\\" + hostname, ShareInfoLevel.Level1, ServerServiceClient.DefaultReturnBufferSize, cancellationToken)
                .ConfigureAwait(false);

            foreach (var shareInfo in shares)
            {
                var shareName = shareInfo.ShareName;

                // Skip null or empty share names
                if (string.IsNullOrEmpty(shareName))
                    continue;

                var sharePath = $@"\\{hostname}\{shareName}";

                var result = new ShareResult
                {
                    SharePath = sharePath,
                    ShareComment = shareInfo.Remark,
                    Listable = true,
                    Triage = Triage.Gray
                };

                // Try to access the share to determine readability
                await TryCheckShareAccessAsync(hostname, shareName, result, cancellationToken)
                    .ConfigureAwait(false);

                WriteRecord(result);
            }
        }
        catch (OperationCanceledException)
        {
            throw; // Don't swallow cancellation
        }
        catch (Exception ex)
        {
            WriteError($"Failed to enumerate shares on {hostname}: {ex.GetType().Name}: {ex.Message}");
        }
    }

    private async Task TryCheckShareAccessAsync(
        string hostname,
        string shareName,
        ShareResult result,
        CancellationToken cancellationToken)
    {
        try
        {
            await using var testClient = SmbParameters.CreateClient();
            var testUncPath = new UncPath(hostname, shareName, "");
            var createInfo = CreateInfoFactory.OpenDirectoryReadOnly();

            await using var dir = await testClient.CreateFileAsync(
                testUncPath,
                createInfo,
                FileAccess.Read,
                cancellationToken).ConfigureAwait(false);

            result.RootReadable = true;
        }
        catch (OperationCanceledException)
        {
            throw; // Don't swallow cancellation
        }
        catch
        {
            result.RootReadable = false;
        }
    }
}
