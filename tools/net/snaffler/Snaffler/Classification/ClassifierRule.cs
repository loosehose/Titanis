using System.Text.RegularExpressions;

namespace Titanis.Snaffler.Cli.Classification;

/// <summary>
/// Defines a classification rule for matching files, shares, or content.
/// </summary>
public class ClassifierRule
{
    /// <summary>
    /// Gets or sets the processing stage this rule applies to.
    /// </summary>
    public EnumerationScope EnumerationScope { get; set; } = EnumerationScope.FileEnumeration;

    /// <summary>
    /// Gets or sets the unique name of this rule.
    /// </summary>
    public string RuleName { get; set; } = "Default";

    /// <summary>
    /// Gets or sets the action to take when the rule matches.
    /// </summary>
    public MatchAction MatchAction { get; set; } = MatchAction.Snaffle;

    /// <summary>
    /// Gets or sets the rules to relay to when MatchAction is Relay.
    /// </summary>
    public List<string>? RelayTargets { get; set; }

    /// <summary>
    /// Gets or sets a human-readable description of what this rule does.
    /// </summary>
    public string Description { get; set; } = "A description of what a rule does.";

    /// <summary>
    /// Gets or sets what part of the item to match against.
    /// </summary>
    public MatchLocation MatchLocation { get; set; } = MatchLocation.FileName;

    /// <summary>
    /// Gets or sets the type of matching to perform.
    /// </summary>
    public MatchListType WordListType { get; set; } = MatchListType.Contains;

    /// <summary>
    /// Gets or sets the minimum match length (0 = no minimum).
    /// </summary>
    public int MatchLength { get; set; } = 0;

    /// <summary>
    /// Gets or sets the MD5 hash to match (when MatchLocation is FileMD5).
    /// </summary>
    public string? MatchMD5 { get; set; }

    /// <summary>
    /// Gets or sets the list of patterns to match.
    /// </summary>
    public List<string> WordList { get; set; } = new();

    /// <summary>
    /// Gets or sets the precompiled regex patterns (built from WordList).
    /// </summary>
    public List<Regex>? Regexes { get; set; }

    /// <summary>
    /// Gets or sets the severity/interest level of matches from this rule.
    /// </summary>
    public Triage Triage { get; set; } = Triage.Green;

    /// <summary>
    /// Precompiles regex patterns based on WordListType.
    /// </summary>
    /// <summary>
    /// Maximum time a single regex match is allowed to run before being aborted.
    /// </summary>
    private static readonly TimeSpan RegexMatchTimeout = TimeSpan.FromSeconds(5);

    public void PrepareRegexes()
    {
        Regexes = new List<Regex>();
        var options = RegexOptions.Compiled | RegexOptions.IgnoreCase | RegexOptions.CultureInvariant;

        foreach (var pattern in WordList)
        {
            try
            {
                string regexPattern = WordListType switch
                {
                    MatchListType.Regex => pattern,
                    MatchListType.EndsWith => Regex.Escape(pattern) + "$",
                    MatchListType.StartsWith => "^" + Regex.Escape(pattern),
                    MatchListType.Exact => "^" + Regex.Escape(pattern) + "$",
                    MatchListType.Contains => Regex.Escape(pattern),
                    _ => Regex.Escape(pattern)
                };

                Regexes.Add(new Regex(regexPattern, options, RegexMatchTimeout));
            }
            catch (ArgumentException)
            {
                // Skip invalid regex patterns
            }
        }
    }

    public override string ToString()
        => $"{RuleName} [{EnumerationScope}] -> {MatchAction}";
}

/// <summary>
/// Container for loading rules from TOML.
/// </summary>
public class RuleSet
{
    /// <summary>
    /// Gets or sets the list of classifier rules.
    /// </summary>
    public List<ClassifierRule> ClassifierRules { get; set; } = new();
}
