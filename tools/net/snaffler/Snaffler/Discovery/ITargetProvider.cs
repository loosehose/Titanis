namespace Titanis.Snaffler.Cli.Discovery;

/// <summary>
/// Provides target hosts or shares for scanning.
/// </summary>
public interface ITargetProvider
{
    /// <summary>
    /// Gets the targets to scan.
    /// </summary>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>An async enumerable of target specifications.</returns>
    IAsyncEnumerable<TargetSpec> GetTargetsAsync(CancellationToken cancellationToken);
}

/// <summary>
/// Specifies a target to scan.
/// </summary>
public class TargetSpec
{
    /// <summary>
    /// Gets or sets the hostname or IP address.
    /// </summary>
    public string? Hostname { get; set; }

    /// <summary>
    /// Gets or sets a specific share name (optional).
    /// </summary>
    public string? ShareName { get; set; }

    /// <summary>
    /// Gets or sets the full UNC path if specified directly.
    /// </summary>
    public string? UncPath { get; set; }

    /// <summary>
    /// Creates a TargetSpec from a hostname.
    /// </summary>
    public static TargetSpec FromHost(string hostname)
        => new() { Hostname = hostname };

    /// <summary>
    /// Creates a TargetSpec from a UNC path.
    /// </summary>
    public static TargetSpec FromUncPath(string uncPath)
    {
        // Parse \\server\share format
        if (uncPath.StartsWith(@"\\") || uncPath.StartsWith("//"))
        {
            var path = uncPath.TrimStart('\\', '/');
            var parts = path.Split(new[] { '\\', '/' }, 2);

            return new TargetSpec
            {
                Hostname = parts[0],
                ShareName = parts.Length > 1 ? parts[1].Split(new[] { '\\', '/' })[0] : null,
                UncPath = uncPath
            };
        }

        // Just a hostname
        return FromHost(uncPath);
    }

    public override string ToString()
    {
        if (!string.IsNullOrEmpty(UncPath))
            return UncPath;
        if (!string.IsNullOrEmpty(ShareName))
            return $@"\\{Hostname}\{ShareName}";
        return Hostname ?? "<unknown>";
    }
}
