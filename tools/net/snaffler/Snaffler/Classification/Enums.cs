namespace Titanis.Snaffler.Cli.Classification;

/// <summary>
/// Processing pipeline stages for classification rules.
/// </summary>
public enum EnumerationScope
{
    /// <summary>Rules applied during share enumeration (NetShareEnum results).</summary>
    ShareEnumeration,

    /// <summary>Rules applied when deciding whether to walk a directory.</summary>
    DirectoryEnumeration,

    /// <summary>Rules applied to individual file metadata (name, extension, size).</summary>
    FileEnumeration,

    /// <summary>Rules applied to file contents.</summary>
    ContentsEnumeration,

    /// <summary>Rules applied after initial match for filtering.</summary>
    PostMatch
}

/// <summary>
/// What part of the file/share/directory to examine for matching.
/// </summary>
public enum MatchLocation
{
    /// <summary>Match against the share name.</summary>
    ShareName,

    /// <summary>Match against the full file path.</summary>
    FilePath,

    /// <summary>Match against just the file name.</summary>
    FileName,

    /// <summary>Match against the file extension.</summary>
    FileExtension,

    /// <summary>Match against file content as a string.</summary>
    FileContentAsString,

    /// <summary>Match against file content as bytes.</summary>
    FileContentAsBytes,

    /// <summary>Match against file size.</summary>
    FileLength,

    /// <summary>Match against file MD5 hash.</summary>
    FileMD5
}

/// <summary>
/// Type of pattern matching to use.
/// </summary>
public enum MatchListType
{
    /// <summary>Exact literal match (^pattern$).</summary>
    Exact,

    /// <summary>Substring contains match.</summary>
    Contains,

    /// <summary>Full regex pattern.</summary>
    Regex,

    /// <summary>Suffix match (pattern$).</summary>
    EndsWith,

    /// <summary>Prefix match (^pattern).</summary>
    StartsWith
}

/// <summary>
/// Action to take when a rule matches.
/// </summary>
public enum MatchAction
{
    /// <summary>Skip this item entirely.</summary>
    Discard,

    /// <summary>Continue processing with the next scope.</summary>
    SendToNextScope,

    /// <summary>Report and/or download the item.</summary>
    Snaffle,

    /// <summary>Pass to other specific rules (uses RelayTargets).</summary>
    Relay,

    /// <summary>Analyze as X509 certificate.</summary>
    CheckForKeys,

    /// <summary>Parse archives (not implemented).</summary>
    EnterArchive
}

/// <summary>
/// Severity/interest level of a match.
/// </summary>
public enum Triage
{
    /// <summary>Highest interest - critical credentials.</summary>
    Black,

    /// <summary>High interest - likely credentials.</summary>
    Red,

    /// <summary>Medium interest - possibly interesting.</summary>
    Yellow,

    /// <summary>Low interest - might be worth reviewing.</summary>
    Green,

    /// <summary>Neutral/unknown.</summary>
    Gray
}
