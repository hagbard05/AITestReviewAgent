using System.Security.Cryptography;
using System.Text;
using AITestReviewAgent.Domain;
using AITestReviewAgent.Security;

namespace AITestReviewAgent.Evidence;

public sealed class EvidenceNormalizer(int maxItemCharacters)
{
    public EvidenceItem ForBuild(PipelineRun build)
    {
        var content = EvidenceSanitizer.Limit(
            $"Build ID: {build.Id}\nName: {build.Name}\nStatus: {build.Status}\nResult: {build.Result}\n"
        + $"Finished: {build.FinishTime?.ToString("O") ?? "not reported"}\nCommit: {build.SourceVersion}\n"
        + $"Repository: {build.Repository?.Name ?? "unavailable"} ({build.Repository?.Id ?? "unavailable"})",
            maxItemCharacters,
            out var truncated);
        return new EvidenceItem(
            "build",
            EvidenceType.Build,
            "Azure DevOps build",
            truncated ? EvidenceCollectionStatus.Truncated : EvidenceCollectionStatus.Available,
            content,
            Url: EvidenceSanitizer.Sanitize(build.Url),
            Timestamp: build.FinishTime,
            Revision: build.SourceVersion);
    }

    public EvidenceItem ForTestResult(TestCaseResult result, string testRunName)
    {
        var content = EvidenceSanitizer.Limit(
            $"Test: {result.TestCaseTitle}\nAutomated test: {result.AutomatedTestName}\n"
              + $"Storage: {result.AutomatedTestStorage}\nOutcome: {result.Outcome}\n"
              + $"Test run: {testRunName}\nError:\n{result.ErrorMessage}\nStack trace:\n{result.StackTrace}\n"
              + $"Azure DevOps failing-since metadata: {FormatPriorFailure(result.PriorFailure)}",
            maxItemCharacters,
            out var truncated);
        return new EvidenceItem(
            $"test-result-{result.RunId}-{result.Id}",
            EvidenceType.TestResult,
            "Azure DevOps test result",
            truncated ? EvidenceCollectionStatus.Truncated : EvidenceCollectionStatus.Available,
            content,
            Url: EvidenceSanitizer.Sanitize(result.Url),
            Timestamp: result.StartedDate);
    }

    public EvidenceItem ForAttachment(
        TestAttachment attachment,
        string? content,
        string? error = null)
    {
        if (content is null)
        {
            var safeError = error is null ? null : EvidenceSanitizer.Sanitize(error);
            return new EvidenceItem(
                $"attachment-{attachment.Id}",
                EvidenceType.Attachment,
                "Azure DevOps test attachment",
                safeError is null ? EvidenceCollectionStatus.Unavailable : EvidenceCollectionStatus.Missing,
                safeError ?? "Attachment content is binary or not supported for text extraction.",
                EvidenceSanitizer.Sanitize(attachment.Name),
                EvidenceSanitizer.Sanitize(attachment.Url ?? string.Empty),
                Timestamp: attachment.Timestamp,
                Error: safeError);
        }

        var limited = EvidenceSanitizer.Limit(content, maxItemCharacters, out var truncated);
        return new EvidenceItem(
            $"attachment-{attachment.Id}",
            EvidenceType.Attachment,
            "Azure DevOps test attachment",
            truncated ? EvidenceCollectionStatus.Truncated : EvidenceCollectionStatus.Available,
            limited,
            EvidenceSanitizer.Sanitize(attachment.Name),
            EvidenceSanitizer.Sanitize(attachment.Url ?? string.Empty),
            Timestamp: attachment.Timestamp);
    }

    public EvidenceItem ForSource(
        string path,
        string content,
        string commitId,
        string? url,
        out string numberedContent,
        DateTimeOffset? timestamp = null)
    {
        var id = $"source-{Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(path)))[..12].ToLowerInvariant()}";
        var lines = content.Replace("\r\n", "\n", StringComparison.Ordinal).Split('\n');
        numberedContent = string.Join('\n', lines.Select((line, index) => $"{index + 1}: {line}"));
        var limited = EvidenceSanitizer.Limit(numberedContent, maxItemCharacters, out var truncated);
        return new EvidenceItem(
            id,
            EvidenceType.SourceCode,
            "Azure Repos file at build commit",
            truncated ? EvidenceCollectionStatus.Truncated : EvidenceCollectionStatus.Available,
            limited,
            Path: EvidenceSanitizer.Sanitize(path),
            Url: url is null ? null : EvidenceSanitizer.Sanitize(url),
            Timestamp: timestamp,
            Revision: commitId);
    }

    public EvidenceItem ForCommit(
        string commitId,
        string repositoryId,
        string repositoryName,
        DateTimeOffset? timestamp = null) => new(
        "repository-commit",
        EvidenceType.RepositoryCommit,
        "Azure Repos commit",
        EvidenceCollectionStatus.Available,
        Limit($"Verified commit: {commitId}\nRepository ID: {repositoryId}\nRepository: {repositoryName}"),
        Timestamp: timestamp,
        Revision: commitId);

    public EvidenceItem Unavailable(string id, EvidenceType type, string source, string message, string? url = null) =>
        new(
            id,
            type,
            EvidenceSanitizer.Sanitize(source),
            EvidenceCollectionStatus.Missing,
            EvidenceSanitizer.Sanitize(message),
            Url: url is null ? null : EvidenceSanitizer.Sanitize(url),
            Error: EvidenceSanitizer.Sanitize(message));

    private string Limit(string content) => EvidenceSanitizer.Limit(content, maxItemCharacters, out _);

    private static string FormatPriorFailure(PriorFailureInfo? priorFailure) =>
        priorFailure is null
            ? "not available"
            : $"build {priorFailure.BuildId} ({priorFailure.BuildNumber}), first reported {priorFailure.FirstFailedAt?.ToString("O") ?? "date unavailable"}";
}
