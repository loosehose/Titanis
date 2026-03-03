using System.Runtime.CompilerServices;

namespace Titanis.Snaffler.Cli.Discovery;

/// <summary>
/// Combines multiple target providers.
/// </summary>
public sealed class CompositeTargetProvider : ITargetProvider
{
    private readonly List<ITargetProvider> _providers = new();

    /// <summary>
    /// Adds a provider to the composite.
    /// </summary>
    /// <param name="provider">The provider to add.</param>
    public void Add(ITargetProvider provider)
    {
        ArgumentNullException.ThrowIfNull(provider);
        _providers.Add(provider);
    }

    /// <inheritdoc/>
    public async IAsyncEnumerable<TargetSpec> GetTargetsAsync(
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        foreach (var provider in _providers)
        {
            await foreach (var target in provider.GetTargetsAsync(cancellationToken)
                .ConfigureAwait(false))
            {
                cancellationToken.ThrowIfCancellationRequested();
                yield return target;
            }
        }
    }

    /// <summary>
    /// Gets whether this composite has any providers.
    /// </summary>
    public bool HasProviders => _providers.Count > 0;
}
