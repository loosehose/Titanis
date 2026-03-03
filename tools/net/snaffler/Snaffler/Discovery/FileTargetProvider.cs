using System.Runtime.CompilerServices;

namespace Titanis.Snaffler.Cli.Discovery;

/// <summary>
/// Provides targets from a file (one host/path per line).
/// </summary>
public sealed class FileTargetProvider : ITargetProvider
{
    private readonly string _filePath;

    /// <summary>
    /// Initializes a new instance of the <see cref="FileTargetProvider"/> class.
    /// </summary>
    /// <param name="filePath">Path to the file containing targets.</param>
    public FileTargetProvider(string filePath)
    {
        _filePath = filePath ?? throw new ArgumentNullException(nameof(filePath));
    }

    /// <inheritdoc/>
    public async IAsyncEnumerable<TargetSpec> GetTargetsAsync(
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        if (!File.Exists(_filePath))
            throw new FileNotFoundException($"Target file not found: {_filePath}");

        await foreach (var line in ReadLinesAsync(_filePath, cancellationToken)
            .ConfigureAwait(false))
        {
            cancellationToken.ThrowIfCancellationRequested();

            var trimmed = line.Trim();

            // Skip empty lines and comments
            if (string.IsNullOrWhiteSpace(trimmed) || trimmed.StartsWith('#') || trimmed.StartsWith("//"))
                continue;

            yield return TargetSpec.FromUncPath(trimmed);
        }
    }

    private static async IAsyncEnumerable<string> ReadLinesAsync(
        string path,
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        using var reader = new StreamReader(path);

        while (!reader.EndOfStream)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var line = await reader.ReadLineAsync(cancellationToken)
                .ConfigureAwait(false);
            if (line != null)
                yield return line;
        }
    }
}
