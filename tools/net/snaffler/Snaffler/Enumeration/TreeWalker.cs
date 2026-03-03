using System.ComponentModel.Design;
using System.Runtime.CompilerServices;
using Titanis.Security;
using Titanis.Smb2;
using Titanis.Smb2.Pdus;
using Titanis.Snaffler.Cli.Classification;
using Titanis.Snaffler.Cli.Smb;
using Titanis.Winterop;
using Titanis.Winterop.Security;
using FileAttributes = Titanis.Winterop.FileAttributes;

namespace Titanis.Snaffler.Cli.Enumeration;

/// <summary>
/// Represents a file entry discovered during tree walking.
/// </summary>
public sealed class FileEntry
{
    /// <summary>Gets or sets the file name without path.</summary>
    public string FileName { get; set; } = "";

    /// <summary>Gets or sets the full UNC path to the file.</summary>
    public string FilePath { get; set; } = "";

    /// <summary>Gets or sets the file extension including the dot.</summary>
    public string Extension { get; set; } = "";

    /// <summary>Gets or sets the file size in bytes.</summary>
    public long Size { get; set; }

    /// <summary>Gets or sets the file creation time.</summary>
    public DateTime CreationTime { get; set; }

    /// <summary>Gets or sets the last write time.</summary>
    public DateTime LastWriteTime { get; set; }

    /// <summary>Gets or sets the last access time.</summary>
    public DateTime LastAccessTime { get; set; }

    /// <summary>Gets or sets the file attributes.</summary>
    public FileAttributes Attributes { get; set; }

    /// <summary>Gets whether this entry is a directory.</summary>
    public bool IsDirectory => (Attributes & FileAttributes.Directory) != 0;
}

/// <summary>
/// Walks directory trees on SMB shares.
/// Thread-safe for statistics access.
/// </summary>
public sealed class TreeWalker
{
    private readonly IServiceContainer _services;
    private readonly Func<Smb2Client> _clientFactory;
    private readonly RuleLoader _ruleLoader;
    private readonly int _maxDepth;
    private readonly Action<string>? _verboseLog;

    // Thread-safe counters
    private int _directoriesScanned;
    private int _filesScanned;

    /// <summary>Gets the number of directories scanned (thread-safe).</summary>
    public int DirectoriesScanned => Volatile.Read(ref _directoriesScanned);

    /// <summary>Gets the number of files scanned (thread-safe).</summary>
    public int FilesScanned => Volatile.Read(ref _filesScanned);

    /// <summary>
    /// Initializes a new instance of the <see cref="TreeWalker"/> class.
    /// </summary>
    /// <param name="services">Service container for dependency resolution.</param>
    /// <param name="clientFactory">Factory function to create SMB clients.</param>
    /// <param name="ruleLoader">Rule loader containing classification rules.</param>
    /// <param name="maxDepth">Maximum directory depth (-1 for unlimited).</param>
    /// <param name="verboseLog">Optional callback for verbose logging.</param>
    public TreeWalker(
        IServiceContainer services,
        Func<Smb2Client> clientFactory,
        RuleLoader ruleLoader,
        int maxDepth = -1,
        Action<string>? verboseLog = null)
    {
        _services = services ?? throw new ArgumentNullException(nameof(services));
        _clientFactory = clientFactory ?? throw new ArgumentNullException(nameof(clientFactory));
        _ruleLoader = ruleLoader ?? throw new ArgumentNullException(nameof(ruleLoader));
        _maxDepth = maxDepth < 0 ? int.MaxValue : maxDepth;
        _verboseLog = verboseLog;
    }

    /// <summary>
    /// Walks a share and yields file entries.
    /// </summary>
    /// <param name="hostname">The host name.</param>
    /// <param name="shareName">The share name.</param>
    /// <param name="startPath">Optional starting path within the share.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>An async enumerable of file entries.</returns>
    public async IAsyncEnumerable<FileEntry> WalkAsync(
        string hostname,
        string shareName,
        string? startPath,
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        if (string.IsNullOrEmpty(hostname))
            throw new ArgumentException("Hostname cannot be null or empty.", nameof(hostname));
        if (string.IsNullOrEmpty(shareName))
            throw new ArgumentException("Share name cannot be null or empty.", nameof(shareName));

        await using var client = _clientFactory();

        var basePath = new UncPath(hostname, shareName, startPath ?? "");

        await foreach (var entry in WalkDirectoryAsync(client, basePath, hostname, shareName, 0, cancellationToken)
            .ConfigureAwait(false))
        {
            yield return entry;
        }
    }

    private async IAsyncEnumerable<FileEntry> WalkDirectoryAsync(
        Smb2Client client,
        UncPath dirPath,
        string hostname,
        string shareName,
        int depth,
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        if (depth > _maxDepth)
            yield break;

        Interlocked.Increment(ref _directoriesScanned);
        var fullDirPath = dirPath.ToString();

        _verboseLog?.Invoke($"Scanning: {fullDirPath}");

        // Check if directory should be skipped by rules
        if (ShouldSkipDirectory(fullDirPath))
            yield break;

        List<Smb2DirEntry> entries;
        try
        {
            var createInfo = CreateInfoFactory.OpenDirectoryReadOnly();

            await using var dir = (Smb2Directory)await client.CreateFileAsync(
                dirPath,
                createInfo,
                FileAccess.Read,
                cancellationToken).ConfigureAwait(false);

            entries = await dir.QueryDirAsync("*", 0, SecurityInfo.None, Smb2Directory.DefaultQueryBufferSize, cancellationToken)
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            throw; // Don't swallow cancellation
        }
        catch (Exception ex)
        {
            _verboseLog?.Invoke($"Cannot access {fullDirPath}: {ex.GetType().Name}: {ex.Message}");
            yield break;
        }

        // Separate files and directories for processing
        var subdirs = new List<(string name, UncPath path)>();

        foreach (var entry in entries)
        {
            cancellationToken.ThrowIfCancellationRequested();

            // Skip . and ..
            if (entry.FileName is "." or "..")
                continue;

            var itemPath = dirPath.Append(entry.FileName);
            var fullPath = itemPath.ToString();

            if (entry.IsDirectory)
            {
                subdirs.Add((entry.FileName, itemPath));
            }
            else
            {
                Interlocked.Increment(ref _filesScanned);

                yield return new FileEntry
                {
                    FileName = entry.FileName,
                    FilePath = fullPath,
                    Extension = Path.GetExtension(entry.FileName),
                    Size = (long)entry.Size,
                    CreationTime = entry.CreationTime,
                    LastWriteTime = entry.LastWriteTime,
                    LastAccessTime = entry.LastAccessTime,
                    Attributes = (FileAttributes)entry.FileAttributes
                };
            }
        }

        // Recurse into subdirectories
        foreach (var (_, subPath) in subdirs)
        {
            cancellationToken.ThrowIfCancellationRequested();

            await foreach (var entry in WalkDirectoryAsync(client, subPath, hostname, shareName, depth + 1, cancellationToken)
                .ConfigureAwait(false))
            {
                yield return entry;
            }
        }
    }

    /// <summary>
    /// Checks if a directory should be skipped based on classification rules.
    /// </summary>
    private bool ShouldSkipDirectory(string fullDirPath)
    {
        foreach (var rule in _ruleLoader.DirClassifiers)
        {
            var dirClassifier = new DirClassifier(rule);
            var (scanDir, _, _) = dirClassifier.ClassifyDir(fullDirPath);
            if (!scanDir)
            {
                _verboseLog?.Invoke($"Skipping directory (rule: {rule.RuleName}): {fullDirPath}");
                return true;
            }
        }
        return false;
    }
}
