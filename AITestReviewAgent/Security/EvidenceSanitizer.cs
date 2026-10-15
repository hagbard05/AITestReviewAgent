using System.Text;
using System.Text.RegularExpressions;

namespace AITestReviewAgent.Security;

public static partial class EvidenceSanitizer
{
    [GeneratedRegex(@"(?i)(authorization\s*[:=]\s*(?:bearer|basic)\s+)[^\s,;]+")]
    private static partial Regex AuthorizationHeader();

    [GeneratedRegex(@"(?i)((?:api[_-]?key|access[_-]?token|password|client[_-]?secret|personal[_-]?access[_-]?token|pat|token|secret|credential|connection[_-]?string|sig|signature|sharedaccesssignature)\s*[:=]\s*)(?:""[^""]*""|'[^']*'|[^\s,;]+)")]
    private static partial Regex SecretAssignment();

    [GeneratedRegex(@"(?i)(""(?:api[_-]?key|access[_-]?token|password|client[_-]?secret|personal[_-]?access[_-]?token|pat|token|secret|credential|connection[_-]?string|sig|signature|sharedaccesssignature)""\s*:\s*)(""(?:(?:\\.)|[^""\\])*""|[^,}\s]+)")]
    private static partial Regex JsonSecretField();

    [GeneratedRegex(@"(?i)\b(?:azd|vso)[a-z0-9]{30,}\b")]
    private static partial Regex AzurePat();

    [GeneratedRegex(@"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b")]
    private static partial Regex OpenAiKey();

    [GeneratedRegex(@"(?i)\b(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,})\b")]
    private static partial Regex GitHubKey();

    [GeneratedRegex(@"(?i)(https?://)[^/@\s]+:[^/@\s]+@")]
    private static partial Regex UrlCredentials();

    public static string Sanitize(string value)
    {
        var sanitized = value.Replace("\0", string.Empty, StringComparison.Ordinal);
        sanitized = JsonSecretField().Replace(sanitized, "$1\"[REDACTED]\"");
        sanitized = AuthorizationHeader().Replace(sanitized, "$1[REDACTED]");
        sanitized = SecretAssignment().Replace(sanitized, "$1[REDACTED]");
        sanitized = AzurePat().Replace(sanitized, "[REDACTED_AZURE_PAT]");
        sanitized = OpenAiKey().Replace(sanitized, "[REDACTED_API_KEY]");
        sanitized = GitHubKey().Replace(sanitized, "[REDACTED_GIT_CREDENTIAL]");
        return UrlCredentials().Replace(sanitized, "$1[REDACTED]@");
    }

    public static string SanitizeModelOutput(string value)
    {
        var sanitized = Sanitize(value);
        var safe = new StringBuilder(sanitized.Length);
        foreach (var character in sanitized)
        {
            safe.Append(char.IsControl(character) && character is not '\r' and not '\n' and not '\t'
                ? '\uFFFD'
                : character);
        }

        return safe.ToString();
    }

    public static string Limit(string value, int maxCharacters, out bool truncated)
    {
        var sanitized = Sanitize(value);
        truncated = sanitized.Length > maxCharacters;
        return truncated ? sanitized[..maxCharacters] : sanitized;
    }
}
