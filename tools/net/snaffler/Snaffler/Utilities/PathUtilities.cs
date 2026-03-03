using System.Diagnostics.CodeAnalysis;

namespace Titanis.Snaffler.Cli.Utilities;

/// <summary>
/// Utilities for path parsing, validation, and sanitization.
/// </summary>
internal static class PathUtilities
{
    /// <summary>
    /// Parses a UNC file path into its components.
    /// </summary>
    /// <param name="filePath">The full UNC path (e.g., \\server\share\path\file.txt)</param>
    /// <param name="hostname">The extracted hostname.</param>
    /// <param name="shareName">The extracted share name.</param>
    /// <param name="relativePath">The path relative to the share root.</param>
    /// <returns>True if parsing succeeded; false otherwise.</returns>
    public static bool TryParseUncPath(
        string? filePath,
        [NotNullWhen(true)] out string? hostname,
        [NotNullWhen(true)] out string? shareName,
        [NotNullWhen(true)] out string? relativePath)
    {
        hostname = shareName = relativePath = null;

        if (string.IsNullOrEmpty(filePath))
            return false;

        if (!filePath.StartsWith(@"\\", StringComparison.Ordinal))
            return false;

        var parts = filePath.Substring(2).Split('\\', 3);
        if (parts.Length < 2)
            return false;

        hostname = parts[0];
        shareName = parts[1];
        relativePath = parts.Length > 2 ? parts[2] : string.Empty;

        // Validate no path traversal in hostname or share
        if (ContainsTraversal(hostname) || ContainsTraversal(shareName))
            return false;

        return !string.IsNullOrEmpty(hostname) && !string.IsNullOrEmpty(shareName);
    }

    /// <summary>
    /// Checks if a path component contains traversal sequences.
    /// </summary>
    public static bool ContainsTraversal(string component)
    {
        return component.Contains("..") ||
               component.Contains('\0');
    }

    /// <summary>
    /// Sanitizes a path component to prevent directory traversal.
    /// </summary>
    public static string SanitizePathComponent(string component)
    {
        if (string.IsNullOrEmpty(component))
            return "_empty_";

        // Remove any characters that could enable traversal
        return component
            .Replace("..", "_")
            .Replace("/", "_")
            .Replace("\0", "_");
    }

    /// <summary>
    /// Sanitizes a relative path to prevent directory traversal.
    /// </summary>
    public static string SanitizeRelativePath(string path)
    {
        if (string.IsNullOrEmpty(path))
            return string.Empty;

        // Normalize separators
        var normalized = path.Replace("/", "\\");

        // Remove traversal sequences
        var parts = normalized.Split('\\')
            .Where(p => !string.IsNullOrEmpty(p) && p != ".." && p != ".")
            .Select(SanitizePathComponent)
            .ToArray();

        return string.Join("\\", parts);
    }

    /// <summary>
    /// Validates that a destination path is within the allowed base path.
    /// Prevents path traversal attacks when writing files.
    /// </summary>
    /// <param name="basePath">The allowed base directory.</param>
    /// <param name="destinationPath">The proposed destination path.</param>
    /// <returns>True if the destination is within the base path; false otherwise.</returns>
    public static bool IsPathWithinBase(string basePath, string destinationPath)
    {
        var fullBase = Path.GetFullPath(basePath).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        var fullDest = Path.GetFullPath(destinationPath);

        return fullDest.StartsWith(fullBase + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase) ||
               fullDest.Equals(fullBase, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Builds a safe local path for downloading a file, preventing traversal.
    /// </summary>
    /// <param name="basePath">The base download directory.</param>
    /// <param name="hostname">The server hostname.</param>
    /// <param name="shareName">The share name.</param>
    /// <param name="relativePath">The path within the share.</param>
    /// <param name="localPath">The resulting safe local path.</param>
    /// <returns>True if a safe path could be constructed; false otherwise.</returns>
    public static bool TryBuildSafeLocalPath(
        string basePath,
        string hostname,
        string shareName,
        string relativePath,
        [NotNullWhen(true)] out string? localPath)
    {
        localPath = null;

        var safeHostname = SanitizePathComponent(hostname);
        var safeShareName = SanitizePathComponent(shareName);
        var safeRelativePath = SanitizeRelativePath(relativePath);

        var fullBasePath = Path.GetFullPath(basePath);
        var proposedPath = Path.Combine(fullBasePath, safeHostname, safeShareName, safeRelativePath);
        var fullProposedPath = Path.GetFullPath(proposedPath);

        // Final validation that we're still under base
        if (!IsPathWithinBase(fullBasePath, fullProposedPath))
            return false;

        localPath = fullProposedPath;
        return true;
    }
}
