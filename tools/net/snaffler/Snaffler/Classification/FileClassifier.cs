namespace Titanis.Snaffler.Cli.Classification;

/// <summary>
/// Classifies files based on their metadata (name, extension, path, size).
/// </summary>
public class FileClassifier
{
    private readonly ClassifierRule _rule;
    private readonly int _contextBytes;

    public FileClassifier(ClassifierRule rule, int contextBytes = 200)
    {
        _rule = rule;
        _contextBytes = contextBytes;
    }

    /// <summary>
    /// Attempts to classify a file based on its metadata.
    /// </summary>
    /// <param name="fileName">The file name.</param>
    /// <param name="filePath">The full file path.</param>
    /// <param name="extension">The file extension.</param>
    /// <param name="fileSize">The file size in bytes.</param>
    /// <returns>A TextResult if matched, or null if no match.</returns>
    public TextResult? ClassifyFile(string fileName, string filePath, string extension, long fileSize)
    {
        string? stringToMatch = null;

        switch (_rule.MatchLocation)
        {
            case MatchLocation.FileExtension:
                stringToMatch = extension;
                break;

            case MatchLocation.FileName:
                stringToMatch = fileName;
                break;

            case MatchLocation.FilePath:
                stringToMatch = filePath;
                break;

            case MatchLocation.FileLength:
                // For file length, check if size is within MatchLength
                if (_rule.MatchLength > 0 && fileSize > _rule.MatchLength)
                    return null;
                // If we get here, size is acceptable
                return new TextResult
                {
                    MatchedStrings = new List<string> { $"Size: {fileSize}" },
                    MatchContext = $"File size {fileSize} bytes"
                };

            default:
                return null;
        }

        if (string.IsNullOrEmpty(stringToMatch))
            return null;

        var textClassifier = new TextClassifier(_rule, _contextBytes);
        return textClassifier.TextMatch(stringToMatch);
    }
}

/// <summary>
/// Classifies directories based on their path.
/// </summary>
public class DirClassifier
{
    private readonly ClassifierRule _rule;

    public DirClassifier(ClassifierRule rule)
    {
        _rule = rule;
    }

    /// <summary>
    /// Determines whether to scan a directory.
    /// </summary>
    /// <param name="dirPath">The directory path.</param>
    /// <returns>True if the directory should be scanned, false to skip.</returns>
    public (bool ScanDir, Triage Triage, TextResult? Result) ClassifyDir(string dirPath)
    {
        var textClassifier = new TextClassifier(_rule);
        var result = textClassifier.TextMatch(dirPath);

        if (result != null)
        {
            switch (_rule.MatchAction)
            {
                case MatchAction.Discard:
                    return (false, _rule.Triage, result);

                case MatchAction.Snaffle:
                    return (true, _rule.Triage, result);
            }
        }

        return (true, Triage.Gray, null);
    }
}

/// <summary>
/// Classifies shares based on their name.
/// </summary>
public class ShareClassifier
{
    private readonly ClassifierRule _rule;

    public ShareClassifier(ClassifierRule rule)
    {
        _rule = rule;
    }

    /// <summary>
    /// Classifies a share.
    /// </summary>
    /// <param name="shareName">The share name or path.</param>
    /// <returns>A tuple indicating whether to skip, and any match result.</returns>
    public (bool Skip, Triage Triage, TextResult? Result) ClassifyShare(string shareName)
    {
        var textClassifier = new TextClassifier(_rule);
        var result = textClassifier.TextMatch(shareName);

        if (result != null)
        {
            switch (_rule.MatchAction)
            {
                case MatchAction.Discard:
                    return (true, _rule.Triage, result);

                case MatchAction.Snaffle:
                    return (false, _rule.Triage, result);
            }
        }

        return (false, Triage.Gray, null);
    }
}
