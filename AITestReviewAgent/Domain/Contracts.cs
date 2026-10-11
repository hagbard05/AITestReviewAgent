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

public interface ILLMProvider
{
    Task<ProviderResponse> CompleteAsync(LlmRequest request, CancellationToken cancellationToken);
}

public interface IAIInvestigator
{
    Task<InvestigationResult> InvestigateAsync(
        InvestigationRequest request,
        InvestigationContext context,
        CancellationToken cancellationToken);
}
