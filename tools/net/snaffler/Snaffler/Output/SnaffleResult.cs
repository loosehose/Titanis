using System.ComponentModel;
using System.Text.RegularExpressions;
using Titanis.Cli;
using Titanis.Snaffler.Cli.Classification;

namespace Titanis.Snaffler.Cli.Output;

/// <summary>
/// Result of a successful snaffler match.
/// </summary>
public class SnaffleResult
{
    /// <summary>
    /// Gets or sets the full UNC path to the file.
    /// </summary>
    [DisplayName("Path")]
    public string FilePath { get; set; } = "";

    /// <summary>
    /// Gets or sets just the file name.
    /// </summary>
    [DisplayName("Name")]
    public string FileName { get; set; } = "";

    /// <summary>
    /// Gets or sets the file extension.
    /// </summary>
    [DisplayName("Ext")]
    public string Extension { get; set; } = "";

    /// <summary>
    /// Gets or sets the file size in bytes.
    /// </summary>
    [DisplayName("Size")]
    [FileSize]
    public long Size { get; set; }

    /// <summary>
    /// Gets or sets the last write time.
    /// </summary>
    [DisplayName("Modified")]
    public DateTime LastWriteTime { get; set; }

    /// <summary>
    /// Gets or sets the severity/interest level.
    /// </summary>
    [DisplayName("Triage")]
    public Triage Triage { get; set; }

    /// <summary>
    /// Gets or sets the name of the rule that matched.
    /// </summary>
    [DisplayName("Rule")]
    public string RuleName { get; set; } = "";

    /// <summary>
    /// Gets or sets the matched pattern.
    /// </summary>
    [DisplayName("Match")]
    public string MatchedPattern { get; set; } = "";

    /// <summary>
    /// Gets or sets context around the match.
    /// </summary>
    [DisplayName("Context")]
    public string? MatchContext { get; set; }

    /// <summary>
    /// Gets or sets whether the file is readable.
    /// </summary>
    [Browsable(false)]
    public bool CanRead { get; set; }

    /// <summary>
    /// Gets or sets whether the file is writable.
    /// </summary>
    [Browsable(false)]
    public bool CanWrite { get; set; }

    // ANSI escape sequences matching original Snaffler color scheme
    private const string Reset = "\x1b[0m";
    private const string DarkGreen = "\x1b[32m";
    private const string DarkYellow = "\x1b[33m";
    private const string DarkRed = "\x1b[31m";
    private const string BlackOnWhite = "\x1b[30;47m";
    private const string Cyan = "\x1b[36m";
    private const string DarkMagenta = "\x1b[35m";
    private const string DarkGray = "\x1b[90m";
    private const string White = "\x1b[37m";
    private const string Green = "\x1b[32m";

    /// <summary>
    /// Gets or sets the log prefix: [DOMAIN\user@host] timestamp [File]
    /// Set by ScanCommand before writing.
    /// </summary>
    [Browsable(false)]
    public string Prefix { get; set; } = "";

    private string GetTriageColor() => Triage switch
    {
        Triage.Green => DarkGreen,
        Triage.Yellow => DarkYellow,
        Triage.Red => DarkRed,
        Triage.Black => BlackOnWhite,
        _ => ""
    };

    /// <summary>
    /// Formats result in original Snaffler single-line format with ANSI colors:
    /// [DOMAIN\user@host] timestamp [File] {Triage}&lt;Rule|RW|Pattern|Size|Modified&gt;(Context) Path
    /// </summary>
    public override string ToString()
    {
        var r = CanRead ? "R" : "";
        var w = CanWrite ? "W" : "";
        // Collapse newlines in context to keep output on a single line
        var context = MatchContext != null
            ? Regex.Replace(MatchContext, @"\r\n?|\n", "\\n")
            : "";

        var triageColor = GetTriageColor();
        return $"{DarkGray}{Prefix}{Reset}" +
               $"{Green}[File]{Reset} " +
               $"{triageColor}{{{Triage}}}{Reset}" +
               $"{Cyan}<{RuleName}|{r}{w}|{MatchedPattern}|{Size}|{LastWriteTime:u}>{Reset}" +
               $"{DarkMagenta}({context}){Reset} {FilePath}";
    }

    /// <summary>
    /// Formats result without ANSI color codes, for log file output.
    /// </summary>
    public string ToPlainString()
    {
        var r = CanRead ? "R" : "";
        var w = CanWrite ? "W" : "";
        var context = MatchContext != null
            ? Regex.Replace(MatchContext, @"\r\n?|\n", "\\n")
            : "";
        return $"{Prefix}[File] {{{Triage}}}<{RuleName}|{r}{w}|{MatchedPattern}|{Size}|{LastWriteTime:u}>({context}) {FilePath}";
    }
}

/// <summary>
/// Result of share enumeration.
/// </summary>
public class ShareResult
{
    /// <summary>
    /// Gets or sets the UNC path to the share.
    /// </summary>
    [DisplayName("Share")]
    public string SharePath { get; set; } = "";

    /// <summary>
    /// Gets or sets the share comment/description.
    /// </summary>
    [DisplayName("Comment")]
    public string? ShareComment { get; set; }

    /// <summary>
    /// Gets or sets whether the share is listable.
    /// </summary>
    [DisplayName("Listable")]
    public bool Listable { get; set; }

    /// <summary>
    /// Gets or sets whether the share root is readable.
    /// </summary>
    [DisplayName("Readable")]
    public bool RootReadable { get; set; }

    /// <summary>
    /// Gets or sets whether the share root is writable.
    /// </summary>
    [DisplayName("Writable")]
    public bool RootWritable { get; set; }

    /// <summary>
    /// Gets or sets the severity if this share matched a rule.
    /// </summary>
    [DisplayName("Triage")]
    public Triage Triage { get; set; } = Triage.Gray;
}

/// <summary>
/// Summary statistics for a scan.
/// Thread-safe for concurrent updates.
/// </summary>
public sealed class ScanStatistics
{
    // Internal fields for Interlocked operations
    internal int _sharesScanned;
    internal int _directoriesScanned;
    internal int _filesScanned;
    internal int _filesMatched;
    internal int _errors;
    internal int _blackCount;
    internal int _redCount;
    internal int _yellowCount;
    internal int _greenCount;

    /// <summary>Number of shares scanned.</summary>
    public int SharesScanned => Volatile.Read(ref _sharesScanned);

    /// <summary>Number of directories scanned.</summary>
    public int DirectoriesScanned => Volatile.Read(ref _directoriesScanned);

    /// <summary>Number of files scanned.</summary>
    public int FilesScanned => Volatile.Read(ref _filesScanned);

    /// <summary>Number of files matched by rules.</summary>
    public int FilesMatched => Volatile.Read(ref _filesMatched);

    /// <summary>Number of errors encountered.</summary>
    public int Errors => Volatile.Read(ref _errors);

    /// <summary>Total scan duration.</summary>
    public TimeSpan Duration { get; set; }

    /// <summary>Number of black (critical) matches.</summary>
    public int BlackCount => Volatile.Read(ref _blackCount);

    /// <summary>Number of red (high) matches.</summary>
    public int RedCount => Volatile.Read(ref _redCount);

    /// <summary>Number of yellow (medium) matches.</summary>
    public int YellowCount => Volatile.Read(ref _yellowCount);

    /// <summary>Number of green (low) matches.</summary>
    public int GreenCount => Volatile.Read(ref _greenCount);
}
