using System.ComponentModel;
using Titanis.Cli;

namespace Titanis.Snaffler.Cli;

/// <summary>
/// Snaffler-specific scanning parameters.
/// </summary>
public class SnafflerParameters : ParameterGroupBase
{
    /// <summary>
    /// Gets or sets the maximum number of hosts to scan in parallel.
    /// </summary>
    [Parameter]
    [Description("Maximum number of hosts to scan in parallel (default: 10)")]
    [Category("Parallelism")]
    public int MaxHostWorkers { get; set; } = 10;

    /// <summary>
    /// Gets or sets the maximum number of shares to scan in parallel per host.
    /// </summary>
    [Parameter]
    [Description("Maximum number of shares to scan in parallel per host (default: 10)")]
    [Category("Parallelism")]
    public int MaxShareWorkers { get; set; } = 10;

    /// <summary>
    /// Gets or sets the maximum number of files to process in parallel.
    /// </summary>
    [Parameter]
    [Description("Maximum number of files to process in parallel (default: 40)")]
    [Category("Parallelism")]
    public int MaxFileWorkers { get; set; } = 40;

    /// <summary>
    /// Gets or sets the maximum file size to scan for content.
    /// </summary>
    [Parameter]
    [Description("Maximum file size in bytes to scan for content (default: 1000000)")]
    [Category("Scanning")]
    public long MaxSizeToGrep { get; set; } = 1000000;

    /// <summary>
    /// Gets or sets the number of context bytes around matches.
    /// </summary>
    [Parameter]
    [Description("Number of context bytes to show around matches (default: 200)")]
    [Category("Scanning")]
    public int ContextBytes { get; set; } = 200;

    /// <summary>
    /// Gets or sets the maximum depth to recurse into directories.
    /// </summary>
    [Parameter]
    [Description("Maximum directory depth (-1 = unlimited, default: -1)")]
    [Category("Scanning")]
    public int MaxDepth { get; set; } = -1;

    /// <summary>
    /// Gets or sets the interest level filter (0-3).
    /// </summary>
    [Parameter]
    [Description("Minimum interest level: 0=all, 1=Yellow+, 2=Red+, 3=Black only (default: 0)")]
    [Category("Scanning")]
    public int InterestLevel { get; set; } = 0;

    /// <summary>
    /// Gets or sets whether to skip content scanning.
    /// </summary>
    [Parameter]
    [Description("Only scan file names, skip content scanning")]
    [Category("Scanning")]
    public SwitchParam NoContent { get; set; }

    /// <summary>
    /// Gets or sets the path to custom rules.
    /// </summary>
    [Parameter]
    [Alias("r")]
    [Description("Path to directory containing custom TOML rules")]
    [Category("Rules")]
    public string? RulePath { get; set; }

    /// <summary>
    /// Gets or sets whether to snaffle (download) matching files.
    /// </summary>
    [Parameter]
    [Description("Download matching files to the specified path")]
    [Category("Output")]
    public string? SnafflePath { get; set; }

    /// <summary>
    /// Gets or sets the maximum file size to snaffle.
    /// </summary>
    [Parameter]
    [Description("Maximum file size to download (default: 10000000)")]
    [Category("Output")]
    public long MaxSizeToSnaffle { get; set; } = 10000000;

    /// <summary>
    /// Gets or sets whether to scan SYSVOL (if multiple DCs, only scan once).
    /// </summary>
    [Parameter]
    [Description("Scan SYSVOL share (default: true)")]
    [Category("Scanning")]
    public SwitchParam ScanSysvol { get; set; }

    /// <summary>
    /// Gets or sets whether to scan NETLOGON (if multiple DCs, only scan once).
    /// </summary>
    [Parameter]
    [Description("Scan NETLOGON share (default: true)")]
    [Category("Scanning")]
    public SwitchParam ScanNetlogon { get; set; }

    /// <summary>
    /// Validates the parameters.
    /// </summary>
    public void Validate(ParameterValidationContext context)
    {
        if (MaxHostWorkers < 1)
            context.LogError(nameof(MaxHostWorkers), "MaxHostWorkers must be >= 1");

        if (MaxShareWorkers < 1)
            context.LogError(nameof(MaxShareWorkers), "MaxShareWorkers must be >= 1");

        if (MaxFileWorkers < 1)
            context.LogError(nameof(MaxFileWorkers), "MaxFileWorkers must be >= 1");

        if (MaxSizeToGrep < 0)
            context.LogError(nameof(MaxSizeToGrep), "MaxSizeToGrep must be >= 0");

        if (ContextBytes < 0)
            context.LogError(nameof(ContextBytes), "ContextBytes must be >= 0");

        if (InterestLevel < 0 || InterestLevel > 3)
            context.LogError(nameof(InterestLevel), "InterestLevel must be between 0 and 3");

        if (!string.IsNullOrEmpty(SnafflePath) && !Directory.Exists(SnafflePath))
        {
            try
            {
                Directory.CreateDirectory(SnafflePath);
            }
            catch (Exception ex)
            {
                context.LogError(nameof(SnafflePath), $"Cannot create snaffle directory: {ex.Message}");
            }
        }

        if (!string.IsNullOrEmpty(RulePath) && !Directory.Exists(RulePath))
            context.LogError(nameof(RulePath), $"Rule directory not found: {RulePath}");
    }
}
