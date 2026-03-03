using System.Runtime.CompilerServices;

namespace Titanis.Snaffler.Cli.Discovery;

/// <summary>
/// Provides targets from command-line arguments.
/// </summary>
public sealed class ArgumentTargetProvider : ITargetProvider
{
    private readonly IReadOnlyList<string> _targets;

    /// <summary>
    /// Initializes a new instance of the <see cref="ArgumentTargetProvider"/> class.
    /// </summary>
    /// <param name="targets">The target strings to provide.</param>
    public ArgumentTargetProvider(IEnumerable<string>? targets)
    {
        _targets = targets?.ToList() as IReadOnlyList<string> ?? Array.Empty<string>();
    }

    /// <inheritdoc/>
    public async IAsyncEnumerable<TargetSpec> GetTargetsAsync(
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        foreach (var target in _targets)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (string.IsNullOrWhiteSpace(target))
                continue;

            // Handle comma-separated list
            var items = target.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

            foreach (var item in items)
            {
                if (string.IsNullOrWhiteSpace(item))
                    continue;

                yield return TargetSpec.FromUncPath(item);
            }
        }

        // Yield to avoid sync-over-async warning while maintaining IAsyncEnumerable signature
        await Task.CompletedTask.ConfigureAwait(false);
    }
}
