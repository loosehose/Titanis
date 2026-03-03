using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Titanis.Snaffler.Cli.Classification;

/// <summary>
/// Classifies files based on their content.
/// </summary>
public class ContentClassifier
{
    private readonly ClassifierRule _rule;
    private readonly int _contextBytes;

    public ContentClassifier(ClassifierRule rule, int contextBytes = 200)
    {
        _rule = rule;
        _contextBytes = contextBytes;
    }

    /// <summary>
    /// Classifies file content.
    /// </summary>
    /// <param name="content">The file content as bytes.</param>
    /// <param name="maxSize">Maximum size to process.</param>
    /// <returns>A TextResult if matched, or null if no match.</returns>
    public TextResult? ClassifyContent(byte[] content, long maxSize)
    {
        if (content.Length > maxSize)
            return null;

        switch (_rule.MatchLocation)
        {
            case MatchLocation.FileContentAsString:
                return ClassifyAsString(content);

            case MatchLocation.FileContentAsBytes:
                return ClassifyAsBytes(content);

            case MatchLocation.FileMD5:
                return ClassifyByMd5(content);

            case MatchLocation.FileLength:
                if (_rule.MatchLength > 0 && content.Length <= _rule.MatchLength)
                {
                    return new TextResult
                    {
                        MatchedStrings = new List<string> { $"Size: {content.Length}" },
                        MatchContext = $"File size {content.Length} bytes"
                    };
                }
                return null;

            default:
                return null;
        }
    }

    private TextResult? ClassifyAsString(byte[] content)
    {
        string text = DecodeText(content);
        var textClassifier = new TextClassifier(_rule, _contextBytes);
        return textClassifier.TextMatch(text);
    }

    /// <summary>
    /// Decodes byte content to string, detecting BOM for UTF-32/UTF-16/UTF-8 and falling back to UTF-8.
    /// </summary>
    internal static string DecodeText(byte[] content)
    {
        if (content.Length == 0)
            return string.Empty;

        // Check for BOM — order matters: UTF-32 LE starts with FF FE 00 00, must check before UTF-16 LE (FF FE)
        if (content.Length >= 4)
        {
            // UTF-32 LE BOM: FF FE 00 00
            if (content[0] == 0xFF && content[1] == 0xFE && content[2] == 0x00 && content[3] == 0x00)
                return Encoding.UTF32.GetString(content);

            // UTF-32 BE BOM: 00 00 FE FF
            if (content[0] == 0x00 && content[1] == 0x00 && content[2] == 0xFE && content[3] == 0xFF)
                return Encoding.GetEncoding("utf-32BE").GetString(content);
        }

        if (content.Length >= 2)
        {
            // UTF-16 LE BOM: FF FE (already excluded UTF-32 LE above)
            if (content[0] == 0xFF && content[1] == 0xFE)
                return Encoding.Unicode.GetString(content);

            // UTF-16 BE BOM: FE FF
            if (content[0] == 0xFE && content[1] == 0xFF)
                return Encoding.BigEndianUnicode.GetString(content);
        }

        if (content.Length >= 3)
        {
            // UTF-8 BOM: EF BB BF
            if (content[0] == 0xEF && content[1] == 0xBB && content[2] == 0xBF)
                return Encoding.UTF8.GetString(content);
        }

        // No BOM — heuristic: if high byte of each 16-bit unit is frequently null, likely UTF-16 LE
        const int SampleSize = 64;
        if (content.Length >= 4)
        {
            int checkLen = Math.Min(content.Length, SampleSize);
            int oddPositions = checkLen / 2;    // number of odd-index bytes sampled
            int nullCount = 0;
            for (int i = 1; i < checkLen; i += 2)
            {
                if (content[i] == 0) nullCount++;
            }
            // If >30% of odd-position bytes are null, treat as UTF-16 LE
            if (oddPositions > 0 && nullCount > oddPositions * 3 / 10)
                return Encoding.Unicode.GetString(content);
        }

        // UTF-8 — GetString never throws, replaces invalid sequences with U+FFFD
        return Encoding.UTF8.GetString(content);
    }

    private TextResult? ClassifyAsBytes(byte[] content)
    {
        // For byte matching, convert patterns to byte sequences
        // This is typically used for binary signatures
        foreach (var pattern in _rule.WordList)
        {
            try
            {
                // Try to parse as hex string
                var patternBytes = HexStringToBytes(pattern);
                if (patternBytes != null && ContainsBytes(content, patternBytes))
                {
                    return new TextResult
                    {
                        MatchedStrings = new List<string> { pattern },
                        MatchContext = $"Binary pattern match: {pattern}"
                    };
                }
            }
            catch
            {
                // If not hex, try as ASCII
                var patternBytes = Encoding.ASCII.GetBytes(pattern);
                if (ContainsBytes(content, patternBytes))
                {
                    return new TextResult
                    {
                        MatchedStrings = new List<string> { pattern },
                        MatchContext = $"Binary pattern match: {pattern}"
                    };
                }
            }
        }

        return null;
    }

    private TextResult? ClassifyByMd5(byte[] content)
    {
        if (string.IsNullOrEmpty(_rule.MatchMD5))
            return null;

        using var md5 = MD5.Create();
        var hash = md5.ComputeHash(content);
        var hashString = BitConverter.ToString(hash).Replace("-", "").ToUpperInvariant();

        if (string.Equals(hashString, _rule.MatchMD5.ToUpperInvariant(), StringComparison.OrdinalIgnoreCase))
        {
            return new TextResult
            {
                MatchedStrings = new List<string> { hashString },
                MatchContext = $"MD5 match: {hashString}"
            };
        }

        return null;
    }

    private static byte[]? HexStringToBytes(string hex)
    {
        hex = hex.Replace(" ", "").Replace("-", "");
        if (hex.Length % 2 != 0)
            return null;

        var bytes = new byte[hex.Length / 2];
        for (int i = 0; i < bytes.Length; i++)
        {
            bytes[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
        }
        return bytes;
    }

    private static bool ContainsBytes(byte[] haystack, byte[] needle)
    {
        for (int i = 0; i <= haystack.Length - needle.Length; i++)
        {
            bool found = true;
            for (int j = 0; j < needle.Length; j++)
            {
                if (haystack[i + j] != needle[j])
                {
                    found = false;
                    break;
                }
            }
            if (found)
                return true;
        }
        return false;
    }

    /// <summary>
    /// Common passwords to try when loading password-protected PFX/PKCS12 files.
    /// </summary>
    private static readonly string[] CommonPfxPasswords = new[]
    {
        "",                         // Empty password
        "password",
        "mimikatz",
        "1234",
        "abcd",
        "secret",
        "changeme",
        "changeit",
        "SolarWinds.R0cks",         // SolarWinds default
        "P@ssw0rd",
        "Password1",
        "Password123",
        "admin",
        "test",
        "123456",
        "qwerty",
        "letmein"
    };

    /// <summary>
    /// Checks if content appears to be a certificate with private key.
    /// </summary>
    /// <param name="content">The file content.</param>
    /// <param name="fileName">Optional filename to include in password guessing.</param>
    /// <returns>A TextResult if a private key is found, null otherwise.</returns>
    public static TextResult? CheckForPrivateKey(byte[] content, string? fileName = null)
    {
        try
        {
            // Try PEM format first
            var text = DecodeText(content);

            // Check for PEM private key markers
            var privateKeyMarkers = new[]
            {
                "-----BEGIN RSA PRIVATE KEY-----",
                "-----BEGIN PRIVATE KEY-----",
                "-----BEGIN EC PRIVATE KEY-----",
                "-----BEGIN DSA PRIVATE KEY-----",
                "-----BEGIN OPENSSH PRIVATE KEY-----",
                "-----BEGIN ENCRYPTED PRIVATE KEY-----"
            };

            foreach (var marker in privateKeyMarkers)
            {
                if (text.Contains(marker, StringComparison.OrdinalIgnoreCase))
                {
                    return new TextResult
                    {
                        MatchedStrings = new List<string> { marker },
                        MatchContext = $"Contains private key: {marker}"
                    };
                }
            }

            // Try to parse as PKCS12/PFX
            if (content.Length > 4 && content[0] == 0x30)
            {
                var result = TryLoadPfxWithPasswords(content, fileName);
                if (result != null)
                    return result;
            }
        }
        catch
        {
            // Ignore parsing errors
        }

        return null;
    }

    /// <summary>
    /// Attempts to load a PFX/PKCS12 file with common passwords.
    /// </summary>
    private static TextResult? TryLoadPfxWithPasswords(byte[] content, string? fileName)
    {
        // Build password list including filename-based passwords
        var passwords = new List<string>(CommonPfxPasswords);

        // Add filename-based passwords (original Snaffler behavior)
        if (!string.IsNullOrEmpty(fileName))
        {
            var baseName = Path.GetFileNameWithoutExtension(fileName);
            if (!string.IsNullOrEmpty(baseName))
            {
                passwords.Add(baseName);
                passwords.Add(baseName.ToLowerInvariant());
                passwords.Add(baseName.ToUpperInvariant());
            }
        }

        foreach (var password in passwords)
        {
            try
            {
                using var cert = new X509Certificate2(
                    content,
                    password,
                    X509KeyStorageFlags.Exportable | X509KeyStorageFlags.MachineKeySet);

                if (cert.HasPrivateKey)
                {
                    var crackedNote = string.IsNullOrEmpty(password)
                        ? "(no password)"
                        : $"(password: {password})";

                    return new TextResult
                    {
                        MatchedStrings = new List<string> { "X509 Certificate with Private Key" },
                        MatchContext = $"Certificate for {cert.Subject} contains private key {crackedNote}"
                    };
                }
                else
                {
                    // Certificate loaded but no private key
                    return null;
                }
            }
            catch (CryptographicException)
            {
                // Wrong password, try next
            }
            catch
            {
                // Not a valid certificate
                break;
            }
        }

        return null;
    }
}
