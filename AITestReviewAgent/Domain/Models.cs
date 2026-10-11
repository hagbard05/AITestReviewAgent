namespace AITestReviewAgent.Domain;

public enum FailureClassification
{
    ApplicationDefect,
    TestDefect,
    FlakyTest,
    EnvironmentFailure,
    DependencyFailure,
    Inconclusive
}

public enum InvestigationStatus
{
    Completed,
    Preliminary,
    Failed
}

public enum EvidenceType
{
    Build,
    TestResult,
    Attachment,
    RepositoryCommit,
    SourceCode,
    RepositoryMetadata
}

public enum EvidenceCollectionStatus
{
    Available,
    Missing,
    Unavailable,
    Truncated
}

public enum ClaimKind
{
    Observation,
    Hypothesis,
    Recommendation
}

public sealed record InvestigationRequest(int BuildId, int TestResultId, int? TestRunId = null);

public sealed record RepositoryInfo(string Id, string Name, string Type, string Url);

public sealed record PipelineRun(
    int Id,
    string Name,
    string Status,
    string Result,
    DateTimeOffset? FinishTime,
    string SourceVersion,
    RepositoryInfo? Repository,
    string Url);

public sealed record TestRun(int Id, string Name, string State, int? TotalTests, string Url);

public sealed record PriorFailureInfo(int BuildId, string BuildNumber, DateTimeOffset? FirstFailedAt);

public sealed record TestCaseResult(
    int Id,
    int RunId,
    string TestCaseTitle,
    string AutomatedTestName,
    string AutomatedTestStorage,
    string Outcome,
    string ErrorMessage,
    string StackTrace,
    DateTimeOffset? StartedDate,
    string Url,
    PriorFailureInfo? PriorFailure = null);

public sealed record EvidenceItem(
    string Id,
    EvidenceType Type,
    string Source,
    EvidenceCollectionStatus Status,
    string Content,
    string? Path = null,
    string? Url = null,
    DateTimeOffset? Timestamp = null,
    string? Revision = null,
    string? Error = null);

public sealed record EvidenceReference(
    string EvidenceId,
    string? Path,
    int? LineStart,
    int? LineEnd,
    string? Url,
    string? Revision = null,
    DateTimeOffset? Timestamp = null);

public sealed record ReasoningClaim(string Text, ClaimKind Kind, IReadOnlyList<string> EvidenceIds);

public sealed record AlternativeHypothesis(string Explanation, IReadOnlyList<string> EvidenceIds);

public sealed record ReconstructedStep(
    string Description,
    ClaimKind Kind,
    IReadOnlyList<EvidenceReference> SourceReferences);

public sealed record TestReconstruction(
    IReadOnlyList<ReconstructedStep> SetupAndTeardown,
    IReadOnlyList<ReconstructedStep> Actions,
    IReadOnlyList<ReconstructedStep> HelpersAndFixtures,
    IReadOnlyList<ReconstructedStep> InputsAndConfiguration,
    IReadOnlyList<ReconstructedStep> ExpectedResultsAndAssertions,
    ReasoningClaim? FirstKnownDivergence,
    IReadOnlyList<string> AdditionalEvidenceNeeded);

public sealed record ReproductionPlan(
    string SuspectedFailurePoint,
    IReadOnlyList<string> Preconditions,
    IReadOnlyList<string> Steps,
    IReadOnlyList<string> ExpectedObservations,
    IReadOnlyList<string> ActualObservations,
    IReadOnlyList<string> SafetyConsiderations,
    bool ExecutionPerformed);

public sealed record SourceFileSnapshot(
    string Path,
    string Content,
    string EvidenceId,
    string Revision,
    string? Url);

public sealed record TestSourceSnapshot(
    bool RevisionVerified,
    bool TestSourceVerified,
    bool RelevantSourcesVerified,
    string CommitId,
    string? RepositoryId,
    string? TestSourcePath,
    IReadOnlyList<SourceFileSnapshot> Files,
    IReadOnlyList<string> MissingDependencies,
    IReadOnlyList<string> Limitations);

public sealed record InvestigationResult(
    InvestigationStatus Status,
    int BuildId,
    int TestRunId,
    int TestResultId,
    FailureClassification Classification,
    string Summary,
    IReadOnlyList<ReasoningClaim> Reasoning,
    int ConfidencePercent,
    IReadOnlyList<EvidenceReference> EvidenceReferences,
    IReadOnlyList<ReasoningClaim> ContradictoryEvidence,
    IReadOnlyList<AlternativeHypothesis> Alternatives,
    IReadOnlyList<string> MissingEvidence,
    string RecommendedNextAction,
    string? SuggestedRemediation,
    IReadOnlyList<string> Limitations,
    IReadOnlyList<string> Errors,
    TestReconstruction Reconstruction,
    ReproductionPlan ReproductionPlan,
    string? Model,
    long? InputTokens,
    long? OutputTokens);

public sealed record InvestigationContext(
    PipelineRun Build,
    TestRun TestRun,
    TestCaseResult TestResult,
    TestSourceSnapshot Source,
    IReadOnlyList<EvidenceItem> Evidence,
    IReadOnlyList<string> CollectionErrors);

public sealed record RepositoryItem(
    string Path,
    bool IsFolder,
    bool IsBinary,
    string? Url,
    bool IsTreeTruncationMarker = false);

public sealed record TestAttachment(
    string Id,
    string Name,
    string? Url,
    long? Size,
    DateTimeOffset? Timestamp = null);

public sealed record RepositoryCommit(string CommitId, DateTimeOffset? Timestamp);

public sealed record ProviderResponse(string Content, string Model, long? InputTokens, long? OutputTokens);

public sealed record LlmRequest(string SystemPrompt, string UserPrompt, string Model, int MaxOutputTokens);
