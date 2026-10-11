using System.Text;
using AITestReviewAgent.AzureDevOps;
using AITestReviewAgent.Configuration;
using AITestReviewAgent.Domain;
using AITestReviewAgent.Evidence;
using AITestReviewAgent.Security;

namespace AITestReviewAgent.Investigation;

public sealed class InvestigationOrchestrator(
    IAzureDevOpsClient azureDevOps,
    TestSourceCollector sourceCollector,
    IAIInvestigator investigator,
    AzureDevOpsOptions azureOptions)
{
    private const int MaxAttachmentCount = 20;
    private const int MaxAttachmentBytes = 200_000;
    private static readonly HashSet<string> TextAttachmentExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".txt", ".log", ".trx", ".xml", ".json", ".csv", ".md", ".out", ".err"
    };

    public async Task<InvestigationResult> InvestigateAsync(
        InvestigationRequest request,
        CancellationToken cancellationToken)
    {
        if (request.BuildId <= 0 || request.TestResultId <= 0)
        {
            throw new InvestigationWorkflowException("Build ID and failed test result ID must be positive integers.");
        }

        if (request.TestRunId is <= 0)
        {
            throw new InvestigationWorkflowException("Test run ID must be a positive integer when provided.");
        }

        var build = await azureDevOps.GetBuildAsync(request.BuildId, cancellationToken);
        var testRuns = await azureDevOps.GetTestRunsAsync(build, cancellationToken);
        var runsToSearch = request.TestRunId is null
            ? testRuns
            : testRuns.Where(run => run.Id == request.TestRunId.Value).ToArray();
        if (request.TestRunId is not null && runsToSearch.Count == 0)
        {
            throw new InvestigationWorkflowException(
                $"Test run {request.TestRunId} was not found in build {request.BuildId}.");
        }

        var resultSearchWasLimited = false;
        var matches = new List<(TestRun Run, TestCaseResult Result)>();
        foreach (var testRun in runsToSearch)
        {
            var results = await azureDevOps.GetTestResultsAsync(
                testRun, azureOptions.MaxTestResults, cancellationToken);
            resultSearchWasLimited |= results.Count == azureOptions.MaxTestResults;
            matches.AddRange(results
                .Where(result => result.Id == request.TestResultId)
                .Select(result => (testRun, result)));
        }

        if (matches.Count == 0)
        {
            var limitDetail = resultSearchWasLimited
                ? $" Search reached the configured limit of {azureOptions.MaxTestResults} results per test run."
                : string.Empty;
            throw new InvestigationWorkflowException(
                $"Test result {request.TestResultId} was not found in build {request.BuildId}.{limitDetail}");
        }

        if (matches.Count > 1)
        {
            throw new InvestigationWorkflowException(
                $"Test result ID {request.TestResultId} is ambiguous across test runs; specify --test-run-id.");
        }

        var (selectedRun, selectedResult) = matches[0];
        if (!string.Equals(selectedResult.Outcome, "Failed", StringComparison.OrdinalIgnoreCase))
        {
            throw new InvestigationWorkflowException(
                $"Test result {request.TestResultId} has outcome '{selectedResult.Outcome}', not Failed.");
        }

        var normalizer = new EvidenceNormalizer(30_000);
        var evidence = new List<EvidenceItem>
        {
            normalizer.ForBuild(build),
            normalizer.ForTestResult(selectedResult, selectedRun.Name)
        };
        var collectionErrors = new List<string>();
        await CollectAttachmentsAsync(selectedResult, evidence, collectionErrors, normalizer, cancellationToken);
        var (source, sourceEvidence) = await sourceCollector.CollectAsync(build, selectedResult, cancellationToken);
        evidence.AddRange(sourceEvidence);
        var context = new InvestigationContext(
            build, selectedRun, selectedResult, source, evidence, collectionErrors);

        if (!source.RevisionVerified || !source.TestSourceVerified || !source.RelevantSourcesVerified)
        {
            return PreliminaryResult(request, context);
        }

        return await investigator.InvestigateAsync(request, context, cancellationToken);
    }

    private async Task CollectAttachmentsAsync(
        TestCaseResult test,
        ICollection<EvidenceItem> evidence,
        ICollection<string> errors,
        EvidenceNormalizer normalizer,
        CancellationToken cancellationToken)
    {
        IReadOnlyList<TestAttachment> attachments;
        try
        {
            attachments = await azureDevOps.GetTestAttachmentsAsync(test.RunId, test.Id, cancellationToken);
        }
        catch (AzureDevOpsException exception)
        {
            var message = $"Could not list test attachments: {exception.Message}";
            errors.Add(message);
            evidence.Add(normalizer.Unavailable("attachments", EvidenceType.Attachment, "Azure DevOps test attachments", message));
            return;
        }

        if (attachments.Count == 0)
        {
            evidence.Add(normalizer.Unavailable(
                "attachments-none",
                EvidenceType.Attachment,
                "Azure DevOps test attachments",
                "No attachments were published for this test result."));
            return;
        }

        if (attachments.Count > MaxAttachmentCount)
        {
            errors.Add($"Attachment retrieval was limited to the first {MaxAttachmentCount} of {attachments.Count} items.");
        }

        foreach (var attachment in attachments.Take(MaxAttachmentCount))
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!TextAttachmentExtensions.Contains(Path.GetExtension(attachment.Name)))
            {
                evidence.Add(normalizer.ForAttachment(attachment, null));
                continue;
            }

            try
            {
                var bytes = await azureDevOps.GetTestAttachmentContentAsync(
                    test.RunId, test.Id, attachment.Id, MaxAttachmentBytes, cancellationToken);
                if (bytes is null)
                {
                    var message = EvidenceSanitizer.Sanitize($"Attachment '{attachment.Name}' is no longer available.");
                    errors.Add(message);
                    evidence.Add(normalizer.ForAttachment(attachment, null, message));
                    continue;
                }

                var wasTruncated = bytes.Length > MaxAttachmentBytes;
                var text = Encoding.UTF8.GetString(bytes, 0, Math.Min(bytes.Length, MaxAttachmentBytes));
                var item = normalizer.ForAttachment(attachment, text);
                evidence.Add(wasTruncated
                    ? item with
                    {
                        Status = EvidenceCollectionStatus.Truncated,
                        Content = item.Content + "\n[Attachment content truncated by size limit.]"
                    }
                    : item);
            }
            catch (AzureDevOpsException exception)
            {
                var message = EvidenceSanitizer.Sanitize(
                    $"Could not retrieve attachment '{attachment.Name}': {exception.Message}");
                errors.Add(message);
                evidence.Add(normalizer.ForAttachment(attachment, null, message));
            }
        }
    }

    private static InvestigationResult PreliminaryResult(
        InvestigationRequest request,
        InvestigationContext context) =>
        PreliminaryReport.Create(
            request,
            context,
            "A definitive diagnosis was withheld because the failed test source and its relevant dependencies could not be fully verified at the build's exact commit.",
            "Restore access to the build's exact Azure Repos commit and required source files, then investigate again.");
}
