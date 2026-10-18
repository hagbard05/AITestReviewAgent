namespace AITestReviewAgent.Domain;

public interface IAzureDevOpsClient
{
    Task<IReadOnlyList<PipelineRun>> GetRecentFailedBuildsAsync(int top, CancellationToken cancellationToken);

    Task<PipelineRun> GetBuildAsync(int buildId, CancellationToken cancellationToken);

    Task<IReadOnlyList<TestRun>> GetTestRunsAsync(PipelineRun build, CancellationToken cancellationToken);

    Task<IReadOnlyList<TestCaseResult>> GetTestResultsAsync(TestRun testRun, int maxResults, CancellationToken cancellationToken);

    Task<IReadOnlyList<TestAttachment>> GetTestAttachmentsAsync(int runId, int resultId, CancellationToken cancellationToken);

    Task<byte[]?> GetTestAttachmentContentAsync(int runId, int resultId, string attachmentId, int maxBytes, CancellationToken cancellationToken);

    Task<RepositoryCommit?> GetVerifiedCommitAsync(
        string repositoryId,
        string commitId,
        CancellationToken cancellationToken);

    Task<IReadOnlyList<RepositoryItem>> GetRepositoryItemsAsync(
        string repositoryId,
        string commitId,
        CancellationToken cancellationToken);

    Task<string?> GetRepositoryFileAsync(
        string repositoryId,
        string path,
        string commitId,
        int maxBytes,
        CancellationToken cancellationToken);
}

public interface ISourceRepositoryClient
{
    string ProviderName { get; }

    bool Supports(string repositoryType);

    Task<RepositoryCommit?> GetVerifiedCommitAsync(
        RepositoryInfo repository,
        string commitId,
        CancellationToken cancellationToken);

    Task<IReadOnlyList<RepositoryItem>> GetRepositoryItemsAsync(
        RepositoryInfo repository,
        RepositoryCommit commit,
        CancellationToken cancellationToken);

    Task<string?> GetRepositoryFileAsync(
        RepositoryInfo repository,
        string path,
        string commitId,
        int maxBytes,
        CancellationToken cancellationToken);

    string CreatePinnedSourceUrl(RepositoryInfo repository, string path, string commitId);
}

public interface ILLMProvider
{
    bool SupportsImages { get; }

    Task<ProviderResponse> CompleteAsync(LlmRequest request, CancellationToken cancellationToken);
}

public interface IAIInvestigator
{
    bool SupportsImages { get; }

    Task<InvestigationResult> InvestigateAsync(
        InvestigationRequest request,
        InvestigationContext context,
        CancellationToken cancellationToken);
}
