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
    private const int MaxPageSourceBytes = 500_000;
    private const int MaxPageSourceCharacters = 15_000;
    private const int MaxImageAttachmentBytes = 4_000_000;
    private const int MaxTotalImageBytes = 8_000_000;
    private const int MaxImageCount = 4;
    private static readonly IReadOnlyDictionary<string, string> ImageMediaTypes = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
    {
        [".png"] = "image/png",
        [".jpg"] = "image/jpeg",
        [".jpeg"] = "image/jpeg",
        [".webp"] = "image/webp",
        [".gif"] = "image/gif"
    };
    private static readonly HashSet<string> TextAttachmentExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".txt", ".log", ".trx", ".xml", ".json", ".csv", ".md", ".out", ".err",
        ".html", ".htm", ".mhtml", ".mht"
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
        var images = await CollectAttachmentsAsync(
            selectedResult,
            evidence,
            collectionErrors,
            normalizer,
            investigator.SupportsImages,
            cancellationToken);
        var (source, sourceEvidence) = await sourceCollector.CollectAsync(build, selectedResult, cancellationToken);
        evidence.AddRange(sourceEvidence);
        var context = new InvestigationContext(
            build, selectedRun, selectedResult, source, evidence, collectionErrors, images);

        if (!source.RevisionVerified || !source.TestSourceVerified || !source.RelevantSourcesVerified)
        {
            return PreliminaryResult(request, context);
        }

        return await investigator.InvestigateAsync(request, context, cancellationToken);
    }

    private async Task<IReadOnlyList<ImageInput>> CollectAttachmentsAsync(
        TestCaseResult test,
        ICollection<EvidenceItem> evidence,
        ICollection<string> errors,
        EvidenceNormalizer normalizer,
        bool supportsImages,
        CancellationToken cancellationToken)
    {
        var images = new List<ImageInput>();
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
            return images;
        }

        if (attachments.Count == 0)
        {
            evidence.Add(normalizer.Unavailable(
                "attachments-none",
                EvidenceType.Attachment,
                "Azure DevOps test attachments",
                "No attachments were published for this test result."));
            return images;
        }

        if (attachments.Count > MaxAttachmentCount)
        {
            errors.Add($"Attachment retrieval was limited to the first {MaxAttachmentCount} of {attachments.Count} items.");
        }

        foreach (var attachment in attachments.Take(MaxAttachmentCount))
        {
            cancellationToken.ThrowIfCancellationRequested();
            var extension = Path.GetExtension(attachment.Name);
            if (ImageMediaTypes.TryGetValue(extension, out var mediaType))
            {
                if (!supportsImages)
                {
                    evidence.Add(normalizer.ForAttachment(attachment, null));
                    continue;
                }

                if (images.Count >= MaxImageCount)
                {
                    var message = $"Image attachment '{attachment.Name}' was not sent because the limit of {MaxImageCount} images was reached.";
                    errors.Add(message);
                    evidence.Add(normalizer.ForAttachment(attachment, null, message));
                    continue;
                }

                if (attachment.Size is > MaxImageAttachmentBytes)
                {
                    var message = $"Image attachment '{attachment.Name}' exceeds the {MaxImageAttachmentBytes}-byte per-image limit.";
                    errors.Add(message);
                    evidence.Add(normalizer.ForAttachment(attachment, null, message));
                    continue;
                }

                if (attachment.Size is long knownSize && knownSize > MaxTotalImageBytes - images.Sum(image => image.Content.Length))
                {
                    var message = $"Image attachment '{attachment.Name}' exceeds the {MaxTotalImageBytes}-byte total image limit.";
                    errors.Add(message);
                    evidence.Add(normalizer.ForAttachment(attachment, null, message));
                    continue;
                }

                try
                {
                    var bytes = await azureDevOps.GetTestAttachmentContentAsync(
                        test.RunId, test.Id, attachment.Id, MaxImageAttachmentBytes, cancellationToken);
                    if (bytes is null)
                    {
                        var message = $"Image attachment '{attachment.Name}' is no longer available.";
                        errors.Add(message);
                        evidence.Add(normalizer.ForAttachment(attachment, null, message));
                        continue;
                    }

                    if (bytes.Length > MaxImageAttachmentBytes
                        || bytes.Length > MaxTotalImageBytes - images.Sum(image => image.Content.Length))
                    {
                        var message = $"Image attachment '{attachment.Name}' exceeds the configured image size limit.";
                        errors.Add(message);
                        evidence.Add(normalizer.ForAttachment(attachment, null, message));
                        continue;
                    }

                    if (!HasExpectedImageSignature(bytes, mediaType))
                    {
                        var message = $"Image attachment '{attachment.Name}' does not match its declared {mediaType} format.";
                        errors.Add(message);
                        evidence.Add(normalizer.ForAttachment(attachment, null, message));
                        continue;
                    }

                    images.Add(new ImageInput($"attachment-{attachment.Id}", attachment.Name, mediaType, bytes));
                    evidence.Add(normalizer.ForAttachment(attachment, null) with
                    {
                        Status = EvidenceCollectionStatus.Available,
                        Content = $"Image attachment bytes were included for model visual analysis ({mediaType}).",
                        SizeBytes = bytes.Length
                    });
                }
                catch (AzureDevOpsException exception)
                {
                    var message = EvidenceSanitizer.Sanitize(
                        $"Could not retrieve image attachment '{attachment.Name}': {exception.Message}");
                    errors.Add(message);
                    evidence.Add(normalizer.ForAttachment(attachment, null, message));
                }

                continue;
            }

            if (!TextAttachmentExtensions.Contains(Path.GetExtension(attachment.Name)))
            {
                evidence.Add(normalizer.ForAttachment(attachment, null));
                continue;
            }

            var isPageSource = IsPageSource(attachment.Name);
            var maxBytes = isPageSource ? MaxPageSourceBytes : MaxAttachmentBytes;
            try
            {
                var bytes = await azureDevOps.GetTestAttachmentContentAsync(
                    test.RunId, test.Id, attachment.Id, maxBytes, cancellationToken);
                if (bytes is null)
                {
                    var message = EvidenceSanitizer.Sanitize($"Attachment '{attachment.Name}' is no longer available.");
                    errors.Add(message);
                    evidence.Add(normalizer.ForAttachment(attachment, null, message));
                    continue;
                }

                var wasTruncated = bytes.Length > maxBytes
                    || attachment.Size is long declaredSize && declaredSize > maxBytes;
                var pageSource = IsPageSource(attachment.Name);
                var isMhtml = IsMhtml(attachment.Name);
                var pageSourceTruncated = false;
                string text;
                if (pageSource)
                {
                    text = isMhtml
                        ? PageSourceNormalizer.NormalizeMhtml(
                            bytes.AsSpan(0, Math.Min(bytes.Length, maxBytes)).ToArray(),
                            MaxPageSourceCharacters,
                            out pageSourceTruncated)
                        : PageSourceNormalizer.Normalize(
                            Encoding.UTF8.GetString(bytes, 0, Math.Min(bytes.Length, maxBytes)),
                            MaxPageSourceCharacters,
                            out pageSourceTruncated);
                    var item = normalizer.ForAttachment(attachment, text) with
                    {
                        Source = "Azure DevOps page source attachment"
                    };
                    evidence.Add(wasTruncated || pageSourceTruncated
                        ? item with
                        {
                            Status = EvidenceCollectionStatus.Truncated
                        }
                        : item);
                }
                else
                {
                    text = Encoding.UTF8.GetString(bytes, 0, Math.Min(bytes.Length, maxBytes));
                    var item = normalizer.ForAttachment(attachment, text);
                    evidence.Add(wasTruncated
                        ? item with
                        {
                            Status = EvidenceCollectionStatus.Truncated,
                            Content = item.Content + "\n[Attachment content truncated by size limit.]"
                        }
                        : item);
                }
            }
            catch (System.Text.RegularExpressions.RegexMatchTimeoutException)
            {
                var message = $"Page source attachment '{attachment.Name}' could not be normalized within the processing limit.";
                errors.Add(message);
                evidence.Add(normalizer.ForAttachment(attachment, null, message));
            }
            catch (InvalidDataException exception)
            {
                var message = EvidenceSanitizer.Sanitize(
                    $"Page source attachment '{attachment.Name}' could not be parsed: {exception.Message}");
                errors.Add(message);
                evidence.Add(normalizer.ForAttachment(attachment, null, message));
            }
            catch (AzureDevOpsException exception)
            {
                var message = EvidenceSanitizer.Sanitize(
                    $"Could not retrieve attachment '{attachment.Name}': {exception.Message}");
                errors.Add(message);
                evidence.Add(normalizer.ForAttachment(attachment, null, message));
            }
        }

        return images;
    }

    private static bool IsPageSource(string name) =>
        Path.GetExtension(name).Equals(".html", StringComparison.OrdinalIgnoreCase)
        || Path.GetExtension(name).Equals(".htm", StringComparison.OrdinalIgnoreCase)
        || IsMhtml(name);

    private static bool IsMhtml(string name) =>
        Path.GetExtension(name).Equals(".mhtml", StringComparison.OrdinalIgnoreCase)
        || Path.GetExtension(name).Equals(".mht", StringComparison.OrdinalIgnoreCase);

    private static bool HasExpectedImageSignature(byte[] bytes, string mediaType) => mediaType switch
    {
        "image/png" => bytes.AsSpan().StartsWith(new byte[] { 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A }),
        "image/jpeg" => bytes.Length >= 3 && bytes[0] == 0xFF && bytes[1] == 0xD8 && bytes[2] == 0xFF,
        "image/gif" => bytes.AsSpan().StartsWith("GIF87a"u8) || bytes.AsSpan().StartsWith("GIF89a"u8),
        "image/webp" => bytes.Length >= 12
            && bytes.AsSpan(0, 4).SequenceEqual("RIFF"u8)
            && bytes.AsSpan(8, 4).SequenceEqual("WEBP"u8),
        _ => false
    };

    private static InvestigationResult PreliminaryResult(
        InvestigationRequest request,
        InvestigationContext context) =>
        PreliminaryReport.Create(
            request,
            context,
            "A definitive diagnosis was withheld because the failed test source and its relevant dependencies could not be fully verified at the build's exact commit.",
            "Restore access to the build's exact source-provider commit and required source files, then investigate again.");
}
