using System.Reflection;
using Tomlyn;
using Tomlyn.Model;

namespace Titanis.Snaffler.Cli.Classification;

/// <summary>
/// Loads and manages classification rules.
/// </summary>
public class RuleLoader
{
    private readonly List<ClassifierRule> _allRules = new();

    /// <summary>
    /// Gets all loaded rules.
    /// </summary>
    public IReadOnlyList<ClassifierRule> AllRules => _allRules;

    /// <summary>
    /// Gets rules for share enumeration.
    /// </summary>
    public IReadOnlyList<ClassifierRule> ShareClassifiers { get; private set; } = Array.Empty<ClassifierRule>();

    /// <summary>
    /// Gets rules for directory enumeration.
    /// </summary>
    public IReadOnlyList<ClassifierRule> DirClassifiers { get; private set; } = Array.Empty<ClassifierRule>();

    /// <summary>
    /// Gets rules for file enumeration.
    /// </summary>
    public IReadOnlyList<ClassifierRule> FileClassifiers { get; private set; } = Array.Empty<ClassifierRule>();

    /// <summary>
    /// Gets rules for content enumeration.
    /// </summary>
    public IReadOnlyList<ClassifierRule> ContentsClassifiers { get; private set; } = Array.Empty<ClassifierRule>();

    /// <summary>
    /// Gets rules for post-match filtering.
    /// </summary>
    public IReadOnlyList<ClassifierRule> PostMatchClassifiers { get; private set; } = Array.Empty<ClassifierRule>();

    /// <summary>
    /// Gets a rule by name.
    /// </summary>
    public ClassifierRule? GetRuleByName(string name)
        => _allRules.FirstOrDefault(r => string.Equals(r.RuleName, name, StringComparison.OrdinalIgnoreCase));

    /// <summary>
    /// Loads rules from embedded resources.
    /// </summary>
    public void LoadEmbeddedRules()
    {
        var assembly = Assembly.GetExecutingAssembly();
        var resourceNames = assembly.GetManifestResourceNames()
            .Where(n => n.EndsWith(".toml", StringComparison.OrdinalIgnoreCase));

        foreach (var resourceName in resourceNames)
        {
            using var stream = assembly.GetManifestResourceStream(resourceName);
            if (stream != null)
            {
                using var reader = new StreamReader(stream);
                var content = reader.ReadToEnd();
                LoadTomlContent(content, resourceName);
            }
        }

        PrepareRules();
    }

    /// <summary>
    /// Loads rules from a directory.
    /// </summary>
    /// <param name="path">Path to directory containing TOML files.</param>
    public void LoadRulesFromDirectory(string path)
    {
        if (!Directory.Exists(path))
            throw new DirectoryNotFoundException($"Rule directory not found: {path}");

        var files = Directory.GetFiles(path, "*.toml", SearchOption.AllDirectories);
        foreach (var file in files)
        {
            var content = File.ReadAllText(file);
            LoadTomlContent(content, file);
        }

        PrepareRules();
    }

    /// <summary>
    /// Loads rules from a single TOML file.
    /// </summary>
    /// <param name="path">Path to TOML file.</param>
    public void LoadRulesFromFile(string path)
    {
        if (!File.Exists(path))
            throw new FileNotFoundException($"Rule file not found: {path}");

        var content = File.ReadAllText(path);
        LoadTomlContent(content, path);
        PrepareRules();
    }

    private void LoadTomlContent(string content, string source)
    {
        try
        {
            var model = Toml.ToModel(content);

            if (model.TryGetValue("ClassifierRules", out var rulesObj) && rulesObj is TomlTableArray rulesArray)
            {
                foreach (var ruleTable in rulesArray)
                {
                    var rule = ParseRule(ruleTable);
                    if (rule != null)
                        _allRules.Add(rule);
                }
            }
        }
        catch (Exception ex)
        {
            // Log warning but continue loading other rules
            Console.Error.WriteLine($"Warning: Failed to parse rules from {source}: {ex.Message}");
        }
    }

    private ClassifierRule? ParseRule(TomlTable table)
    {
        var rule = new ClassifierRule();

        if (table.TryGetValue("RuleName", out var name))
            rule.RuleName = name?.ToString() ?? "Unknown";

        if (table.TryGetValue("Description", out var desc))
            rule.Description = desc?.ToString() ?? "";

        if (table.TryGetValue("EnumerationScope", out var scope))
            rule.EnumerationScope = ParseEnum<EnumerationScope>(scope?.ToString());

        if (table.TryGetValue("MatchAction", out var action))
            rule.MatchAction = ParseEnum<MatchAction>(action?.ToString());

        if (table.TryGetValue("MatchLocation", out var location))
            rule.MatchLocation = ParseEnum<MatchLocation>(location?.ToString());

        if (table.TryGetValue("WordListType", out var listType))
            rule.WordListType = ParseEnum<MatchListType>(listType?.ToString());

        if (table.TryGetValue("Triage", out var triage))
            rule.Triage = ParseEnum<Triage>(triage?.ToString());

        if (table.TryGetValue("MatchLength", out var matchLen) && matchLen is long len)
            rule.MatchLength = (int)len;

        if (table.TryGetValue("MatchMD5", out var md5))
            rule.MatchMD5 = md5?.ToString();

        if (table.TryGetValue("WordList", out var wordList) && wordList is TomlArray wordArray)
        {
            rule.WordList = wordArray.Select(w => w?.ToString() ?? "").Where(w => !string.IsNullOrEmpty(w)).ToList();
        }

        if (table.TryGetValue("RelayTargets", out var relayTargets) && relayTargets is TomlArray relayArray)
        {
            rule.RelayTargets = relayArray.Select(r => r?.ToString() ?? "").Where(r => !string.IsNullOrEmpty(r)).ToList();
        }

        return rule;
    }

    private static T ParseEnum<T>(string? value) where T : struct
    {
        if (string.IsNullOrEmpty(value))
            return default;

        if (Enum.TryParse<T>(value, ignoreCase: true, out var result))
            return result;

        return default;
    }

    private void PrepareRules()
    {
        // Precompile regex patterns
        foreach (var rule in _allRules)
        {
            rule.PrepareRegexes();
        }

        // Sort rules by enumeration scope
        // Discard rules should be processed first, then other actions
        ShareClassifiers = _allRules
            .Where(r => r.EnumerationScope == EnumerationScope.ShareEnumeration)
            .OrderBy(r => r.MatchAction)
            .ToList();

        DirClassifiers = _allRules
            .Where(r => r.EnumerationScope == EnumerationScope.DirectoryEnumeration)
            .OrderBy(r => r.MatchAction)
            .ToList();

        FileClassifiers = _allRules
            .Where(r => r.EnumerationScope == EnumerationScope.FileEnumeration)
            .OrderBy(r => r.MatchAction)
            .ToList();

        ContentsClassifiers = _allRules
            .Where(r => r.EnumerationScope == EnumerationScope.ContentsEnumeration)
            .OrderBy(r => r.MatchAction)
            .ToList();

        PostMatchClassifiers = _allRules
            .Where(r => r.EnumerationScope == EnumerationScope.PostMatch)
            .ToList();
    }

    /// <summary>
    /// Filters rules by interest level.
    /// </summary>
    /// <param name="minLevel">Minimum interest level (0-3).</param>
    public void FilterByInterestLevel(int minLevel)
    {
        // Keep all Discard rules, filter others by triage level
        // Level mapping: 0 = all, 1 = Yellow+, 2 = Red+, 3 = Black only
        _allRules.RemoveAll(rule =>
        {
            if (rule.MatchAction == MatchAction.Discard)
                return false; // Always keep discard rules

            return minLevel switch
            {
                0 => false, // Keep all
                1 => rule.Triage == Triage.Green || rule.Triage == Triage.Gray,
                2 => rule.Triage != Triage.Red && rule.Triage != Triage.Black,
                3 => rule.Triage != Triage.Black,
                _ => false
            };
        });

        PrepareRules();
    }
}
