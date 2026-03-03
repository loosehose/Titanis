using System.ComponentModel;
using Titanis.Cli;
using Titanis.Snaffler.Cli.Classification;

namespace Titanis.Snaffler.Cli;

/// <summary>
/// Output record for rule listing.
/// </summary>
public class RuleInfo
{
    [DisplayName("Name")]
    public string RuleName { get; set; } = "";

    [DisplayName("Scope")]
    public EnumerationScope Scope { get; set; }

    [DisplayName("Action")]
    public MatchAction Action { get; set; }

    [DisplayName("Location")]
    public MatchLocation Location { get; set; }

    [DisplayName("Type")]
    public MatchListType ListType { get; set; }

    [DisplayName("Triage")]
    public Triage Triage { get; set; }

    [DisplayName("Patterns")]
    public int PatternCount { get; set; }

    [DisplayName("Description")]
    public string Description { get; set; } = "";
}

/// <summary>
/// Lists loaded classification rules.
/// </summary>
[OutputRecordType(typeof(RuleInfo), DefaultFields = new string[] {
    nameof(RuleInfo.RuleName),
    nameof(RuleInfo.Scope),
    nameof(RuleInfo.Action),
    nameof(RuleInfo.Triage),
    nameof(RuleInfo.PatternCount)
})]
[Description("List loaded classification rules")]
[Example("List embedded rules", @"{0}")]
[Example("List custom rules", @"{0} -RulePath ./my-rules/")]
public class ListRulesCommand : Command
{
    [Parameter]
    [Alias("r")]
    [Description("Path to directory containing custom TOML rules")]
    public string? RulePath { get; set; }

    [Parameter]
    [Description("Filter rules by scope (Share, Directory, File, Contents, PostMatch)")]
    public EnumerationScope? Scope { get; set; }

    [Parameter]
    [Description("Filter rules by action (Discard, Snaffle, Relay, etc.)")]
    public MatchAction? Action { get; set; }

    [Parameter]
    [Description("Filter rules by minimum triage level")]
    public Triage? MinTriage { get; set; }

    [Parameter]
    [Description("Show patterns for each rule")]
    public SwitchParam ShowPatterns { get; set; }

    protected override void ValidateParameters(ParameterValidationContext context)
    {
        base.ValidateParameters(context);

        if (!string.IsNullOrEmpty(RulePath) && !Directory.Exists(RulePath))
            context.LogError(nameof(RulePath), $"Rule directory not found: {RulePath}");
    }

    protected override Task<int> RunAsync(CancellationToken cancellationToken)
    {
        var ruleLoader = new RuleLoader();

        try
        {
            if (!string.IsNullOrEmpty(RulePath))
            {
                WriteVerbose($"Loading rules from {RulePath}");
                ruleLoader.LoadRulesFromDirectory(RulePath);
            }
            else
            {
                WriteVerbose("Loading embedded rules");
                ruleLoader.LoadEmbeddedRules();
            }
        }
        catch (Exception ex)
        {
            WriteError($"Failed to load rules: {ex.Message}");
            return Task.FromResult(1);
        }

        var rules = ruleLoader.AllRules.AsEnumerable();

        // Apply filters
        if (Scope.HasValue)
            rules = rules.Where(r => r.EnumerationScope == Scope.Value);

        if (Action.HasValue)
            rules = rules.Where(r => r.MatchAction == Action.Value);

        if (MinTriage.HasValue)
            rules = rules.Where(r => r.Triage <= MinTriage.Value); // Lower enum value = higher severity

        // Sort by scope, then action, then name
        rules = rules
            .OrderBy(r => r.EnumerationScope)
            .ThenBy(r => r.MatchAction)
            .ThenBy(r => r.RuleName);

        foreach (var rule in rules)
        {
            if (cancellationToken.IsCancellationRequested)
                break;

            var info = new RuleInfo
            {
                RuleName = rule.RuleName,
                Scope = rule.EnumerationScope,
                Action = rule.MatchAction,
                Location = rule.MatchLocation,
                ListType = rule.WordListType,
                Triage = rule.Triage,
                PatternCount = rule.WordList.Count,
                Description = rule.Description
            };

            WriteRecord(info);

            if (ShowPatterns.IsSet && rule.WordList.Count > 0)
            {
                foreach (var pattern in rule.WordList.Take(10))
                {
                    WriteVerbose($"  - {pattern}");
                }
                if (rule.WordList.Count > 10)
                {
                    WriteVerbose($"  ... and {rule.WordList.Count - 10} more patterns");
                }
            }
        }

        WriteVerbose($"\nTotal rules: {ruleLoader.AllRules.Count}");
        WriteVerbose($"  Share rules:    {ruleLoader.ShareClassifiers.Count}");
        WriteVerbose($"  Directory rules: {ruleLoader.DirClassifiers.Count}");
        WriteVerbose($"  File rules:     {ruleLoader.FileClassifiers.Count}");
        WriteVerbose($"  Content rules:  {ruleLoader.ContentsClassifiers.Count}");
        WriteVerbose($"  PostMatch rules: {ruleLoader.PostMatchClassifiers.Count}");

        return Task.FromResult(0);
    }
}
