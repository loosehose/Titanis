using System.Text;
using System.Text.RegularExpressions;

namespace Titanis.Snaffler.Cli.Classification;

/// <summary>
/// Result of a text match operation.
/// </summary>
public class TextResult
{
    /// <summary>
    /// Gets or sets the patterns that matched.
    /// </summary>
    public List<string> MatchedStrings { get; set; } = new();

    /// <summary>
    /// Gets or sets the context around the match.
    /// </summary>
    public string? MatchContext { get; set; }
}

/// <summary>
/// Performs text matching using classifier rules.
/// </summary>
public class TextClassifier
{
    private readonly ClassifierRule _rule;
    private readonly int _contextBytes;

    public TextClassifier(ClassifierRule rule, int contextBytes = 200)
    {
        _rule = rule;
        _contextBytes = contextBytes;
    }

    /// <summary>
    /// Attempts to match the input string against the rule's patterns.
    /// </summary>
    /// <param name="input">The string to match.</param>
    /// <returns>A TextResult if matched, or null if no match.</returns>
    public TextResult? TextMatch(string? input)
    {
        if (string.IsNullOrEmpty(input) || _rule.Regexes == null)
            return null;

        foreach (var regex in _rule.Regexes)
        {
            try
            {
                var match = regex.Match(input);
                if (match.Success)
                {
                    return new TextResult
                    {
                        MatchedStrings = new List<string> { regex.ToString() },
                        MatchContext = GetContext(input, match)
                    };
                }
            }
            catch (RegexMatchTimeoutException)
            {
                // Skip patterns that time out
            }
        }

        return null;
    }

    /// <summary>
    /// Extracts context around a match.
    /// </summary>
    private string GetContext(string original, Match match)
    {
        int start = Math.Max(0, match.Index - _contextBytes);
        int end = Math.Min(original.Length, match.Index + match.Length + _contextBytes);
        int length = end - start;

        var context = original.Substring(start, length);

        // Escape control characters
        var sb = new StringBuilder();
        foreach (char c in context)
        {
            if (char.IsControl(c) && c != '\n' && c != '\r' && c != '\t')
                sb.Append(' ');
            else
                sb.Append(c);
        }

        return sb.ToString();
    }
}
