using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Threading.Channels;
using Titanis.Cli;
using Titanis.DceRpc;
using Titanis.DceRpc.Client;
using Titanis.Msrpc;
using Titanis.Msrpc.Mswkst;
using Titanis.Security;
using Titanis.Smb2;
using Titanis.Smb2.Pdus;
using Titanis.Snaffler.Cli.Classification;
using Titanis.Snaffler.Cli.Discovery;
using Titanis.Snaffler.Cli.Enumeration;
using Titanis.Snaffler.Cli.Output;
using Titanis.Snaffler.Cli.Smb;
using Titanis.Snaffler.Cli.Utilities;

namespace Titanis.Snaffler.Cli;

/// <summary>
/// Scans SMB shares for credentials and secrets.
/// </summary>
[OutputRecordType(typeof(SnaffleResult), DefaultOutputStyle = OutputStyle.Freeform, DefaultFields = new string[] {
    nameof(SnaffleResult.FilePath),
    nameof(SnaffleResult.Size),
    nameof(SnaffleResult.Triage),
    nameof(SnaffleResult.RuleName),
    nameof(SnaffleResult.MatchContext)
})]
[Description("Scan SMB shares for credentials and secrets")]
[Example("Scan a single host", @"{0} dc01.corp.local -u admin -ud CORP -p password")]
[Example("Scan from file", @"{0} -T targets.txt -u admin -ud CORP -p password")]
[Example("Scan specific shares", @"{0} -s \\dc01\SYSVOL -s \\dc01\NETLOGON -u admin -ud CORP -p password")]
[Example("LDAP discovery", @"{0} -d dc01.corp.local -u admin -ud CORP -p password")]
public class ScanCommand : Command
{
    /// <summary>
    /// Target hosts (comma-separated or multiple arguments).
    /// </summary>
    [Parameter(0)]
    [Description("Target hosts to scan (comma-separated)")]
    [Placeholder("host1,host2,...")]
    public string[]? Targets { get; set; }

    /// <summary>
    /// File containing target hosts.
    /// </summary>
    [Parameter]
    [Alias("T")]
    [Description("File containing target hosts (one per line)")]
    public string? TargetFile { get; set; }

    /// <summary>
    /// Direct UNC paths to scan.
    /// </summary>
    [Parameter]
    [Alias("s")]
    [Description("Direct UNC share paths to scan")]
    public string[]? Shares { get; set; }

    /// <summary>
    /// Domain controller for LDAP discovery.
    /// </summary>
    [Parameter]
    [Alias("d")]
    [Description("Domain controller for LDAP computer discovery")]
    public string? DomainController { get; set; }

    /// <summary>
    /// LDAP port (default: 389).
    /// </summary>
    [Parameter]
    [Description("LDAP port (default: 389, use 636 for LDAPS)")]
    public int LdapPort { get; set; } = 389;

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

    /// <summary>
    /// Output log file path.
    /// </summary>
    [Parameter]
    [Alias("o")]
    [Description("Write results to a log file (plain text, no color codes)")]
    public string? OutputFile { get; set; }

    /// <summary>
    /// Snaffler-specific parameters.
    /// </summary>
    [ParameterGroup(ParameterGroupOptions.AlwaysInstantiate)]
    public SnafflerParameters SnafflerParameters { get; set; }

    private readonly RuleLoader _ruleLoader = new();
    private readonly ScanStatistics _stats = new();
    private StreamWriter? _logWriter;
    private string _identityPrefix = "";
    private readonly object _scannedSharesLock = new();
    private readonly HashSet<string> _scannedSysvol = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _scannedNetlogon = new(StringComparer.OrdinalIgnoreCase);

    /// <inheritdoc/>
    protected override void ValidateParameters(ParameterValidationContext context)
    {
        base.ValidateParameters(context);

        NetParameters?.ValidateParameters(context);
        AuthenticationParameters.Validate(true, context);
        SmbParameters.Validate(context, AuthenticationParameters);
        SnafflerParameters.Validate(context);

        // Ensure we have at least one target source
        bool hasTargets = (Targets != null && Targets.Length > 0)
            || !string.IsNullOrEmpty(TargetFile)
            || (Shares != null && Shares.Length > 0)
            || !string.IsNullOrEmpty(DomainController);

        if (!hasTargets)
        {
            context.LogError(nameof(Targets), "At least one target source must be specified: targets, -T, -s, or -d");
        }
    }

    private static void PrintSnafflerBanner()
    {
        string[] lines =
        {
            @" .::::::.:::.    :::.  :::.    .-:::::'.-:::::':::    .,:::::: :::::::..   ",
            @";;;`    ``;;;;,  `;;;  ;;`;;   ;;;'''' ;;;'''' ;;;    ;;;;'''' ;;;;``;;;;  ",
            @"'[==/[[[[, [[[[[. '[[ ,[[ '[[, [[[,,== [[[,,== [[[     [[cccc   [[[,/[[['  ",
            @"  '''    $ $$$ 'Y$c$$c$$$cc$$$c`$$$'`` `$$$'`` $$'     $$""""   $$$$$$c    ",
            @" 88b    dP 888    Y88 888   888,888     888   o88oo,.__888oo,__ 888b '88bo,",
            @"  'YMmMY'  MMM     YM YMM   ''` 'MM,    'MM,  ''''YUMMM''''YUMMMMMMM   'W' ",
            @"                         by l0ss and Sh3r4 - github.com/SnaffCon/Snaffler  ",
            @"                         Ported with <3 by github.com/loosehose            ",
        };

        string[] colors =
        {
            "\x1b[91m",  // Red (bright)
            "\x1b[33m",  // DarkYellow
            "\x1b[93m",  // Yellow (bright)
            "\x1b[32m",  // Green
            "\x1b[34m",  // Blue
            "\x1b[35m",  // DarkMagenta
            "\x1b[37m",  // White
            "\x1b[36m",  // Cyan
        };

        for (int i = 0; i < lines.Length; i++)
        {
            Console.Error.Write(colors[i]);
            Console.Error.WriteLine(lines[i]);
        }
        Console.Error.Write("\x1b[0m");
        Console.Error.WriteLine();
    }

    /// <inheritdoc/>
    protected override async Task<int> RunAsync(CancellationToken cancellationToken)
    {
        PrintSnafflerBanner();

        // Build identity parts for per-target prefix: [DOMAIN\user@target]
        var user = AuthenticationParameters.UserName?.UserName;
        var domain = AuthenticationParameters.UserDomain;
        _identityPrefix = !string.IsNullOrEmpty(domain) && !string.IsNullOrEmpty(user)
            ? $"{domain}\\{user}"
            : user ?? "";

        if (!string.IsNullOrEmpty(OutputFile))
        {
            _logWriter = new StreamWriter(OutputFile, append: false, encoding: System.Text.Encoding.UTF8)
            {
                AutoFlush = true
            };
        }

        var stopwatch = Stopwatch.StartNew();

        // Load rules
        if (!TryLoadRules())
            return 1;

        // Build and process targets
        var targetProvider = BuildTargetProvider();

        WriteVerbose($"Using parallelism: hosts={SnafflerParameters.MaxHostWorkers}, shares={SnafflerParameters.MaxShareWorkers}, files={SnafflerParameters.MaxFileWorkers}");

        // Collect targets and process in parallel
        var targets = new List<TargetSpec>();
        await foreach (var target in targetProvider.GetTargetsAsync(cancellationToken)
            .ConfigureAwait(false))
        {
            targets.Add(target);
        }

        WriteVerbose($"Discovered {targets.Count} targets");

        var parallelOptions = new ParallelOptions
        {
            MaxDegreeOfParallelism = SnafflerParameters.MaxHostWorkers,
            CancellationToken = cancellationToken
        };

        await Parallel.ForEachAsync(targets, parallelOptions, async (target, ct) =>
        {
            try
            {
                await ProcessTargetAsync(target, ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                throw; // Propagate cancellation
            }
            catch (Exception ex)
            {
                Interlocked.Increment(ref _stats._errors);
                WriteError($"Error processing {target}: {ex.GetType().Name}: {ex.Message}");
            }
        }).ConfigureAwait(false);

        stopwatch.Stop();
        _stats.Duration = stopwatch.Elapsed;

        PrintSummary();

        if (_logWriter != null)
        {
            WriteVerbose($"Results written to {OutputFile}");
            _logWriter.Dispose();
            _logWriter = null;
        }

        return 0;
    }

    private bool TryLoadRules()
    {
        try
        {
            if (!string.IsNullOrEmpty(SnafflerParameters.RulePath))
            {
                WriteVerbose($"Loading rules from {SnafflerParameters.RulePath}");
                _ruleLoader.LoadRulesFromDirectory(SnafflerParameters.RulePath);
            }
            else
            {
                WriteVerbose("Loading embedded rules");
                _ruleLoader.LoadEmbeddedRules();
            }

            if (SnafflerParameters.InterestLevel > 0)
            {
                _ruleLoader.FilterByInterestLevel(SnafflerParameters.InterestLevel);
            }

            WriteVerbose($"Loaded {_ruleLoader.AllRules.Count} rules");
            return true;
        }
        catch (Exception ex)
        {
            WriteError($"Failed to load rules: {ex.GetType().Name}: {ex.Message}");
            return false;
        }
    }

    private CompositeTargetProvider BuildTargetProvider()
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

        if (Shares != null && Shares.Length > 0)
        {
            targetProvider.Add(new ArgumentTargetProvider(Shares));
        }

        if (!string.IsNullOrEmpty(DomainController))
        {
            // Build LDAP bind DN from authentication parameters if available
            string? bindDn = null;
            string? bindPassword = null;

            if (AuthenticationParameters.UserName != null)
            {
                // Format: user@domain or DOMAIN\user
                var domain = AuthenticationParameters.UserDomain ?? AuthenticationParameters.UserName.Realm;
                var user = AuthenticationParameters.UserName.UserName;

                if (!string.IsNullOrEmpty(domain))
                {
                    // Try UPN format first (user@domain.local)
                    bindDn = $"{user}@{domain}";
                }
                else
                {
                    bindDn = user;
                }

                bindPassword = AuthenticationParameters.Password;
            }

            WriteVerbose($"LDAP discovery from {DomainController}:{LdapPort}");
            targetProvider.Add(new LdapTargetProvider(DomainController, LdapPort, bindDn, bindPassword));
        }

        return targetProvider;
    }

    private void PrintSummary()
    {
        WriteVerbose($"\nScan complete:");
        WriteVerbose($"  Shares:      {_stats.SharesScanned}");
        WriteVerbose($"  Directories: {_stats.DirectoriesScanned}");
        WriteVerbose($"  Files:       {_stats.FilesScanned}");
        WriteVerbose($"  Matches:     {_stats.FilesMatched}");
        WriteVerbose($"  Errors:      {_stats.Errors}");
        WriteVerbose($"  Duration:    {_stats.Duration}");

        if (_stats.FilesMatched > 0)
        {
            WriteVerbose($"\nBy severity:");
            WriteVerbose($"  Black:  {_stats.BlackCount}");
            WriteVerbose($"  Red:    {_stats.RedCount}");
            WriteVerbose($"  Yellow: {_stats.YellowCount}");
            WriteVerbose($"  Green:  {_stats.GreenCount}");
        }
    }

    private async Task ProcessTargetAsync(TargetSpec target, CancellationToken cancellationToken)
    {
        WriteVerbose($"Processing target: {target}");

        if (!string.IsNullOrEmpty(target.ShareName) && !string.IsNullOrEmpty(target.Hostname))
        {
            await ScanShareAsync(target.Hostname, target.ShareName, cancellationToken)
                .ConfigureAwait(false);
        }
        else if (!string.IsNullOrEmpty(target.Hostname))
        {
            await EnumerateAndScanHostAsync(target.Hostname, cancellationToken)
                .ConfigureAwait(false);
        }
    }

    private async Task EnumerateAndScanHostAsync(string hostname, CancellationToken cancellationToken)
    {
        WriteVerbose($"Enumerating shares on {hostname}");

        IList<ShareInfo> shares;
        try
        {
            shares = await EnumerateSharesRpcAsync(hostname, cancellationToken)
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            WriteError($"Failed to enumerate shares on {hostname}: {ex.GetType().Name}: {ex.Message}");
            Interlocked.Increment(ref _stats._errors);
            return;
        }

        // Filter shares to scan
        var sharesToScan = new List<string>();
        foreach (var share in shares)
        {
            var shareName = share.ShareName;

            // Skip null/empty share names
            if (string.IsNullOrEmpty(shareName))
                continue;

            // Skip IPC$ and PRINT$
            if (shareName.Equals("IPC$", StringComparison.OrdinalIgnoreCase) ||
                shareName.Equals("PRINT$", StringComparison.OrdinalIgnoreCase))
                continue;

            // Handle SYSVOL/NETLOGON deduplication
            if (!ShouldScanShare(hostname, shareName))
                continue;

            // Apply share classifiers
            if (ShouldSkipShareByRules(hostname, shareName))
                continue;

            sharesToScan.Add(shareName);
        }

        // Process shares in parallel
        var parallelOptions = new ParallelOptions
        {
            MaxDegreeOfParallelism = SnafflerParameters.MaxShareWorkers,
            CancellationToken = cancellationToken
        };

        await Parallel.ForEachAsync(sharesToScan, parallelOptions, async (shareName, ct) =>
        {
            try
            {
                await ScanShareAsync(hostname, shareName, ct)
                    .ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception ex)
            {
                WriteError($"Error scanning \\\\{hostname}\\{shareName}: {ex.GetType().Name}: {ex.Message}");
                Interlocked.Increment(ref _stats._errors);
            }
        }).ConfigureAwait(false);
    }

    private bool ShouldScanShare(string hostname, string shareName)
    {
        lock (_scannedSharesLock)
        {
            if (shareName.Equals("SYSVOL", StringComparison.OrdinalIgnoreCase))
            {
                if (!SnafflerParameters.ScanSysvol.GetValue(true))
                    return false;
                if (_scannedSysvol.Count > 0)
                {
                    WriteVerbose($"Skipping SYSVOL on {hostname} (already scanned)");
                    return false;
                }
                _scannedSysvol.Add(hostname);
            }
            else if (shareName.Equals("NETLOGON", StringComparison.OrdinalIgnoreCase))
            {
                if (!SnafflerParameters.ScanNetlogon.GetValue(true))
                    return false;
                if (_scannedNetlogon.Count > 0)
                {
                    WriteVerbose($"Skipping NETLOGON on {hostname} (already scanned)");
                    return false;
                }
                _scannedNetlogon.Add(hostname);
            }
            return true;
        }
    }

    private bool ShouldSkipShareByRules(string hostname, string shareName)
    {
        var sharePath = $@"\\{hostname}\{shareName}";

        foreach (var rule in _ruleLoader.ShareClassifiers)
        {
            var classifier = new ShareClassifier(rule);
            var (skip, _, _) = classifier.ClassifyShare(sharePath);

            if (skip)
            {
                WriteVerbose($"Skipping share (rule: {rule.RuleName}): {sharePath}");
                return true;
            }
        }
        return false;
    }

    private async Task ScanShareAsync(string hostname, string shareName, CancellationToken cancellationToken)
    {
        var sharePath = $@"\\{hostname}\{shareName}";
        WriteVerbose($"Scanning share: {sharePath}");
        Interlocked.Increment(ref _stats._sharesScanned);

        var treeWalker = new TreeWalker(
            this.Services,
            () => SmbParameters.CreateClient(),
            _ruleLoader,
            SnafflerParameters.MaxDepth,
            msg => WriteVerbose(msg)
        );

        // Use a bounded channel to control backpressure
        var fileChannel = Channel.CreateBounded<FileEntry>(new BoundedChannelOptions(1000)
        {
            FullMode = BoundedChannelFullMode.Wait
        });

        // Start file producer (tree walker)
        var producerTask = Task.Run(async () =>
        {
            try
            {
                await foreach (var file in treeWalker.WalkAsync(hostname, shareName, null, cancellationToken)
                    .ConfigureAwait(false))
                {
                    await fileChannel.Writer.WriteAsync(file, cancellationToken)
                        .ConfigureAwait(false);
                }
            }
            finally
            {
                fileChannel.Writer.Complete();
            }
        }, cancellationToken);

        // Start file consumers (parallel file processing)
        var consumerTasks = new List<Task>();
        for (int i = 0; i < SnafflerParameters.MaxFileWorkers; i++)
        {
            consumerTasks.Add(Task.Run(async () =>
            {
                await foreach (var file in fileChannel.Reader.ReadAllAsync(cancellationToken)
                    .ConfigureAwait(false))
                {
                    try
                    {
                        await ProcessFileAsync(file, hostname, shareName, cancellationToken)
                            .ConfigureAwait(false);
                    }
                    catch (OperationCanceledException)
                    {
                        throw;
                    }
                    catch (Exception ex)
                    {
                        WriteVerbose($"Error processing {file.FilePath}: {ex.GetType().Name}: {ex.Message}");
                        Interlocked.Increment(ref _stats._errors);
                    }
                }
            }, cancellationToken));
        }

        // Wait for producer and all consumers to complete
        await producerTask.ConfigureAwait(false);
        await Task.WhenAll(consumerTasks).ConfigureAwait(false);

        Interlocked.Add(ref _stats._directoriesScanned, treeWalker.DirectoriesScanned);
        Interlocked.Add(ref _stats._filesScanned, treeWalker.FilesScanned);
    }

    private async Task ProcessFileAsync(FileEntry file, string hostname, string shareName, CancellationToken cancellationToken)
    {
        // Apply file classifiers
        foreach (var rule in _ruleLoader.FileClassifiers)
        {
            var classifier = new FileClassifier(rule, SnafflerParameters.ContextBytes);
            var result = classifier.ClassifyFile(file.FileName, file.FilePath, file.Extension, file.Size);

            if (result != null)
            {
                switch (rule.MatchAction)
                {
                    case MatchAction.Discard:
                        WriteVerbose($"  DISCARD by rule: {rule.RuleName}");
                        return;

                    case MatchAction.Snaffle:
                        await ReportMatchAsync(file, rule, result, hostname, shareName, cancellationToken)
                            .ConfigureAwait(false);
                        return;

                    case MatchAction.Relay:
                        WriteVerbose($"  RELAY by rule: {rule.RuleName}");
                        await ProcessRelayAsync(file, rule, hostname, shareName, cancellationToken)
                            .ConfigureAwait(false);
                        break;

                    case MatchAction.CheckForKeys:
                        if (!SnafflerParameters.NoContent.IsSet)
                        {
                            await CheckForKeysAsync(file, hostname, shareName, rule, cancellationToken)
                                .ConfigureAwait(false);
                        }
                        break;
                }
            }
        }

        // If no file rule matched with a terminal action, check content rules
        if (!SnafflerParameters.NoContent.IsSet && file.Size <= SnafflerParameters.MaxSizeToGrep)
        {
            await ScanAllContentRulesAsync(file, hostname, shareName, _ruleLoader.ContentsClassifiers, cancellationToken)
                .ConfigureAwait(false);
        }
    }

    private async Task ProcessRelayAsync(FileEntry file, ClassifierRule rule, string hostname, string shareName, CancellationToken cancellationToken)
    {
        if (rule.RelayTargets == null)
            return;

        // Collect content rules from relay targets to batch them into a single file read
        var contentRules = new List<ClassifierRule>();

        foreach (var targetName in rule.RelayTargets)
        {
            var targetRule = _ruleLoader.GetRuleByName(targetName);
            if (targetRule == null)
                continue;

            if (targetRule.EnumerationScope == EnumerationScope.ContentsEnumeration)
            {
                if (!SnafflerParameters.NoContent.IsSet)
                {
                    contentRules.Add(targetRule);
                }
            }
            else if (targetRule.EnumerationScope == EnumerationScope.FileEnumeration)
            {
                var innerClassifier = new FileClassifier(targetRule, SnafflerParameters.ContextBytes);
                var innerResult = innerClassifier.ClassifyFile(file.FileName, file.FilePath, file.Extension, file.Size);
                if (innerResult != null && targetRule.MatchAction == MatchAction.Snaffle)
                {
                    await ReportMatchAsync(file, targetRule, innerResult, hostname, shareName, cancellationToken)
                        .ConfigureAwait(false);
                    return;
                }
            }
        }

        // Read file once for all content relay targets
        if (contentRules.Count > 0)
        {
            await ScanAllContentRulesAsync(file, hostname, shareName, contentRules, cancellationToken)
                .ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Reads file content once and scans against all provided content rules.
    /// </summary>
    private async Task ScanAllContentRulesAsync(FileEntry file, string hostname, string shareName,
        IReadOnlyList<ClassifierRule> rules, CancellationToken cancellationToken)
    {
        if (file.Size > SnafflerParameters.MaxSizeToGrep || rules.Count == 0)
            return;

        byte[]? content;
        try
        {
            content = await ReadFileContentAsync(file, hostname, shareName, cancellationToken)
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            WriteVerbose($"Error reading {file.FilePath}: {ex.GetType().Name}: {ex.Message}");
            return;
        }

        if (content == null)
        {
            WriteVerbose($"  ContentScan: null content for {file.FilePath} (size={file.Size})");
            return;
        }

        foreach (var rule in rules)
        {
            WriteVerbose($"  ContentScan: {file.FilePath} rule={rule.RuleName} contentLen={content.Length} regexCount={rule.Regexes?.Count ?? 0}");
            var classifier = new ContentClassifier(rule, SnafflerParameters.ContextBytes);
            var result = classifier.ClassifyContent(content, SnafflerParameters.MaxSizeToGrep);

            if (result != null && rule.MatchAction == MatchAction.Snaffle)
            {
                await ReportMatchAsync(file, rule, result, hostname, shareName, cancellationToken)
                    .ConfigureAwait(false);
            }
        }
    }

    private async Task CheckForKeysAsync(FileEntry file, string hostname, string shareName, ClassifierRule rule, CancellationToken cancellationToken)
    {
        try
        {
            var content = await ReadFileContentAsync(file, hostname, shareName, cancellationToken)
                .ConfigureAwait(false);
            if (content == null)
                return;

            // Pass filename for filename-based password guessing on PFX files
            var result = ContentClassifier.CheckForPrivateKey(content, file.FileName);
            if (result != null)
            {
                await ReportMatchAsync(file, rule, result, hostname, shareName, cancellationToken)
                    .ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            WriteVerbose($"Error checking keys in {file.FilePath}: {ex.GetType().Name}: {ex.Message}");
        }
    }

    /// <summary>
    /// Reads file content from an SMB share.
    /// </summary>
    private async Task<byte[]?> ReadFileContentAsync(FileEntry file, string hostname, string shareName, CancellationToken cancellationToken)
    {
        if (file.Size > SnafflerParameters.MaxSizeToGrep || file.Size <= 0)
            return null;

        // Validate and extract path
        if (!PathUtilities.TryParseUncPath(file.FilePath, out var pathHost, out var pathShare, out var relativePath))
        {
            WriteVerbose($"Invalid UNC path: {file.FilePath}");
            return null;
        }

        await using var client = SmbParameters.CreateClient();
        var uncPath = new UncPath(hostname, shareName, relativePath);
        var createInfo = CreateInfoFactory.OpenFileReadOnly();

        try
        {
            await using var fileHandle = (Smb2OpenFile)await client.CreateFileAsync(
                uncPath, createInfo, FileAccess.Read, cancellationToken)
                .ConfigureAwait(false);

            await using var stream = fileHandle.GetStream(false);

            var fileSize = (int)file.Size;
            var buffer = new byte[fileSize];
            int totalRead = 0;
            int bytesRead;
            while (totalRead < fileSize &&
                   (bytesRead = await stream.ReadAsync(buffer.AsMemory(totalRead, fileSize - totalRead), cancellationToken)
                       .ConfigureAwait(false)) > 0)
            {
                totalRead += bytesRead;
            }

            // If we read fewer bytes than expected, return trimmed array
            if (totalRead < fileSize)
            {
                var trimmed = new byte[totalRead];
                Array.Copy(buffer, trimmed, totalRead);
                return trimmed;
            }

            return buffer;
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            WriteVerbose($"Cannot read {file.FilePath}: {ex.GetType().Name}: {ex.Message}");
            return null;
        }
    }

    /// <summary>
    /// Checks if a match should be discarded by PostMatch rules.
    /// </summary>
    private bool ShouldDiscardByPostMatch(FileEntry file)
    {
        foreach (var postRule in _ruleLoader.PostMatchClassifiers)
        {
            if (postRule.MatchAction != MatchAction.Discard)
                continue;

            // Check based on match location
            string target = postRule.MatchLocation switch
            {
                MatchLocation.FileName => file.FileName,
                MatchLocation.FilePath => file.FilePath,
                MatchLocation.FileExtension => file.Extension,
                _ => file.FilePath
            };

            if (string.IsNullOrEmpty(target))
                continue;

            // Apply word list matching
            foreach (var pattern in postRule.WordList)
            {
                bool matches = postRule.WordListType switch
                {
                    MatchListType.Exact => target.Equals(pattern, StringComparison.OrdinalIgnoreCase),
                    MatchListType.Contains => target.Contains(pattern, StringComparison.OrdinalIgnoreCase),
                    MatchListType.EndsWith => target.EndsWith(pattern, StringComparison.OrdinalIgnoreCase),
                    MatchListType.StartsWith => target.StartsWith(pattern, StringComparison.OrdinalIgnoreCase),
                    MatchListType.Regex => postRule.Regexes != null &&
                                          postRule.Regexes.Any(r => r.IsMatch(target)),
                    _ => false
                };

                if (matches)
                {
                    WriteVerbose($"PostMatch discard (rule: {postRule.RuleName}): {file.FilePath}");
                    return true;
                }
            }
        }

        return false;
    }

    private async Task ReportMatchAsync(FileEntry file, ClassifierRule rule, TextResult result, string hostname, string shareName, CancellationToken cancellationToken)
    {
        // Apply PostMatch filtering
        if (ShouldDiscardByPostMatch(file))
            return;

        Interlocked.Increment(ref _stats._filesMatched);

        switch (rule.Triage)
        {
            case Triage.Black: Interlocked.Increment(ref _stats._blackCount); break;
            case Triage.Red: Interlocked.Increment(ref _stats._redCount); break;
            case Triage.Yellow: Interlocked.Increment(ref _stats._yellowCount); break;
            case Triage.Green: Interlocked.Increment(ref _stats._greenCount); break;
        }

        var timestamp = DateTime.UtcNow.ToString("u");
        var hostTag = !string.IsNullOrEmpty(_identityPrefix)
            ? $"[{_identityPrefix}@{hostname}]"
            : $"[{hostname}]";
        var snaffleResult = new SnaffleResult
        {
            Prefix = $"{hostTag} {timestamp} ",
            FilePath = file.FilePath,
            FileName = file.FileName,
            Extension = file.Extension,
            Size = file.Size,
            LastWriteTime = file.LastWriteTime,
            Triage = rule.Triage,
            RuleName = rule.RuleName,
            MatchedPattern = result.MatchedStrings.FirstOrDefault() ?? "",
            MatchContext = result.MatchContext
        };

        WriteRecord(snaffleResult);

        _logWriter?.WriteLine(snaffleResult.ToPlainString());

        // Snaffle (download) file if configured
        if (!string.IsNullOrEmpty(SnafflerParameters.SnafflePath) && file.Size <= SnafflerParameters.MaxSizeToSnaffle)
        {
            await SnaffleFileAsync(file, hostname, shareName, cancellationToken)
                .ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Downloads a file to local storage with path traversal prevention.
    /// </summary>
    private async Task SnaffleFileAsync(FileEntry file, string hostname, string shareName, CancellationToken cancellationToken)
    {
        try
        {
            // Parse and validate path
            if (!PathUtilities.TryParseUncPath(file.FilePath, out _, out _, out var relativePath))
            {
                WriteVerbose($"Cannot snaffle: invalid path {file.FilePath}");
                return;
            }

            // Build safe local path with traversal prevention
            if (!PathUtilities.TryBuildSafeLocalPath(
                SnafflerParameters.SnafflePath!,
                hostname,
                shareName,
                relativePath,
                out var localPath))
            {
                WriteError($"Path traversal blocked for: {file.FilePath}");
                return;
            }

            // Create directory structure
            var localDir = Path.GetDirectoryName(localPath);
            if (!string.IsNullOrEmpty(localDir))
                Directory.CreateDirectory(localDir);

            // Read and save the file
            var content = await ReadFileContentAsync(file, hostname, shareName, cancellationToken)
                .ConfigureAwait(false);
            if (content != null)
            {
                await File.WriteAllBytesAsync(localPath, content, cancellationToken)
                    .ConfigureAwait(false);
                WriteVerbose($"Snaffled: {file.FilePath} -> {localPath}");
            }
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            WriteVerbose($"Failed to snaffle {file.FilePath}: {ex.GetType().Name}: {ex.Message}");
        }
    }

    /// <summary>
    /// Enumerates shares using RPC over named pipes.
    /// </summary>
    private async Task<IList<ShareInfo>> EnumerateSharesRpcAsync(string hostname, CancellationToken cancellationToken)
    {
        await using var client = SmbParameters.CreateClient();

        var serverService = new ServerServiceClient();
        var rpcClient = this.Services.CreateRpcClient();
        rpcClient.DefaultAuthLevel = RpcAuthLevel.None;

        var pipePath = new UncPath(hostname, Smb2Client.IpcName, ServerServiceClient.PipeName);
        await rpcClient.ConnectPipe(serverService, client, pipePath, cancellationToken)
            .ConfigureAwait(false);

        return await serverService.GetShares(@"\\" + hostname, ShareInfoLevel.Level1, ServerServiceClient.DefaultReturnBufferSize, cancellationToken)
            .ConfigureAwait(false);
    }
}
