using AITestReviewAgent.Domain;
using AITestReviewAgent.Security;

namespace AITestReviewAgent.Investigation;

public static class PreliminaryReport
{
    public static InvestigationResult Create(
        InvestigationRequest request,
        InvestigationContext context,
        string summary,
        string recommendedNextAction,
        IEnumerable<string>? additionalMissingEvidence = null,
        IEnumerable<string>? additionalErrors = null)
    {
        var missing = context.Source.MissingDependencies
            .Concat(context.Source.Limitations)
            .Concat(context.CollectionErrors)
            .Concat(context.Evidence
                .Where(item => item.Status != EvidenceCollectionStatus.Available)
                .Select(item => $"{item.Type} evidence '{item.Path ?? item.Id}' is {item.Status}."))
            .Concat(additionalMissingEvidence ?? [])
            .Select(EvidenceSanitizer.Sanitize)
            .Distinct(StringComparer.Ordinal)
            .ToArray();
        var errors = context.CollectionErrors
            .Concat(context.Source.MissingDependencies)
            .Concat(additionalErrors ?? [])
            .Select(EvidenceSanitizer.Sanitize)
            .ToArray();
        var references = context.Evidence
            .Where(item => item.Type is EvidenceType.SourceCode or EvidenceType.RepositoryCommit or EvidenceType.RepositoryMetadata)
            .Select(item => new EvidenceReference(
                item.Id,
                item.Path,
                null,
                null,
                item.Url is null ? null : EvidenceSanitizer.Sanitize(item.Url),
                item.Revision,
                item.Timestamp))
            .ToArray();

        return new InvestigationResult(
            InvestigationStatus.Preliminary,
            request.BuildId,
            context.TestRun.Id,
            request.TestResultId,
            FailureClassification.Inconclusive,
            EvidenceSanitizer.Sanitize(summary),
            Array.Empty<ReasoningClaim>(),
            0,
            references,
            Array.Empty<ReasoningClaim>(),
            Array.Empty<AlternativeHypothesis>(),
            missing,
            EvidenceSanitizer.Sanitize(recommendedNextAction),
            null,
            context.Source.Limitations.Select(EvidenceSanitizer.Sanitize).ToArray(),
            errors,
            new TestReconstruction(
                Array.Empty<ReconstructedStep>(),
                Array.Empty<ReconstructedStep>(),
                Array.Empty<ReconstructedStep>(),
                Array.Empty<ReconstructedStep>(),
                Array.Empty<ReconstructedStep>(),
                null,
                ["Source analysis could not be completed with the available verified files."]),
            new ReproductionPlan(
                "Unknown until all required source files are available to the investigator.",
                ["Verified test source and required referenced files."],
                ["Restore source access or increase the configured evidence limits, then investigate again."],
                ["The test's expected state and first observed divergence."],
                ["Not executed; no controlled reproduction runner is implemented."],
                ["No test code or commands were executed."],
                false),
            null,
            null,
            null);
    }
}
