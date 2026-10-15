using System.Text.Json;
using System.Text.RegularExpressions;
using AITestReviewAgent.Configuration;
using AITestReviewAgent.Domain;
using AITestReviewAgent.Investigation;
using AITestReviewAgent.Security;
using Microsoft.Extensions.Logging;

namespace AITestReviewAgent.AI;

public sealed class AIInvestigator(
    ILLMProvider provider,
    AiOptions options,
    ILogger<AIInvestigator>? logger = null) : IAIInvestigator
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true
    };
    private static readonly Regex UnsupportedOperationClaims = new(
        @"\b(?:I|we|the investigator|the system)\s+(?:have\s+)?(?:already\s+)?reproduced\b"
        + @"|\b(?:the\s+)?(?:test|failure|issue)\s+(?:has been|was)\s+reproduced\b"
        + @"|\b(?:I|we|the investigator|the system)\s+(?:have\s+)?(?:run|executed|performed)\s+(?:the\s+)?(?:reproduction|repro)\b"
        + @"|\b(?:the\s+)?test\s+(?:was|has been)\s+(?:re-run|rerun)\b"
        + @"|\b(?:reproduction|repro)\s+(?:was|has been)\s+(?:attempted|performed|executed|successful|completed)\b"
        + @"|\b(?:root cause|cause)\s+(?:(?:is|has been|was)\s+)?(?:confirmed|proven|verified)\b"
        + @"|\b(?:confirmed|proven|verified)\s+(?:root cause|cause)\b"
        + @"|\b(?:I|we|the system|the investigator)\s+(?:have\s+)?(?:confirmed|proved|verified)\s+(?:the\s+)?(?:root cause|cause)\b"
        + @"|\b(?:multiple|several|both|all)\s+(?:independent\s+)?(?:AI\s+)?models?\s+(?:agree|agreed|concur|concurred)\b"
        + @"|\bmodel consensus\b",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant,
        TimeSpan.FromMilliseconds(250));

    public async Task<InvestigationResult> InvestigateAsync(
        InvestigationRequest request,
        InvestigationContext context,
        CancellationToken cancellationToken)
    {
        if (!context.Source.RevisionVerified
            || !context.Source.TestSourceVerified
            || !context.Source.RelevantSourcesVerified)
        {
            return PreliminaryReport.Create(
                request,
                context,
                "A definitive diagnosis was withheld because the failed test source or a relevant dependency was not fully verified.",
                "Restore access to the build's exact source revision and all required test dependencies, then investigate again.");
        }

        var sourceEvidence = context.Evidence.Where(item => item.Type == EvidenceType.SourceCode).ToArray();
        var sourceCharacters = sourceEvidence.Sum(item =>
            (long)EvidenceSanitizer.Sanitize(item.Content).Length);
        if (sourceEvidence.Length == 0
            || sourceEvidence.Any(item => item.Status != EvidenceCollectionStatus.Available)
            || sourceCharacters > options.MaxEvidenceCharacters)
        {
            var omittedSource = sourceEvidence
                .Where(item => item.Status != EvidenceCollectionStatus.Available)
                .Select(item => item.Path ?? item.Id)
                .ToArray();
            return PreliminaryReport.Create(
                request,
                context,
                "A definitive diagnosis was withheld because the complete test source and relevant source files exceed the configured AI evidence limit.",
                "Increase AI:MaxEvidenceCharacters or reduce the bounded source package, then investigate again.",
                omittedSource.Length == 0
                    ? [$"Retrieved source requires {sourceCharacters} characters; configured AI evidence limit is {options.MaxEvidenceCharacters}."]
                    : omittedSource.Select(path => $"Source file '{path}' was truncated or unavailable."));
        }

        var prompt = InvestigationPrompt.BuildUserPrompt(context, options.MaxEvidenceCharacters);
        var response = await provider.CompleteAsync(
            new LlmRequest(InvestigationPrompt.SystemPrompt, prompt, options.Model, options.MaxOutputTokens),
            cancellationToken);
        var sanitizedResponse = EvidenceSanitizer.SanitizeModelOutput(response.Content);
        logger?.LogInformation(
            "Complete sanitized model response from {Model}:\n{ModelResponse}",
            EvidenceSanitizer.SanitizeModelOutput(response.Model),
            sanitizedResponse);
        if (UnsupportedOperationClaims.IsMatch(response.Content))
        {
            throw new InvestigationOutputException(
                "The AI response claimed an unperformed reproduction, confirmed root cause, or multi-model agreement; the claim was rejected.");
        }

        var output = Parse(response.Content);
        return ValidateAndBuild(request, context, output, response, sanitizedResponse);
    }

    public static InvestigationOutput Parse(string content)
    {
        var json = content.Trim();
        if (json.StartsWith("```", StringComparison.Ordinal))
        {
            var firstLineEnd = json.IndexOf('\n');
            var finalFence = json.LastIndexOf("```", StringComparison.Ordinal);
            if (firstLineEnd >= 0 && finalFence > firstLineEnd)
            {
                json = json[(firstLineEnd + 1)..finalFence].Trim();
            }
        }

        try
        {
            return JsonSerializer.Deserialize<InvestigationOutput>(json, JsonOptions)
                ?? throw new InvestigationOutputException("The AI returned an empty investigation object.");
        }
        catch (JsonException)
        {
            throw new InvestigationOutputException("The AI returned malformed or incomplete investigation JSON.");
        }
    }

    private static InvestigationResult ValidateAndBuild(
        InvestigationRequest request,
        InvestigationContext context,
        InvestigationOutput output,
        ProviderResponse response,
        string sanitizedResponse)
    {
        if (!Enum.TryParse<FailureClassification>(output.Classification, true, out var classification)
            || !Enum.IsDefined(classification))
        {
            throw new InvestigationOutputException($"The AI returned an unknown failure classification '{output.Classification}'.");
        }

        if (output.ConfidencePercent is < 0 or > 100)
        {
            throw new InvestigationOutputException("The AI confidence must be an integer from 0 to 100.");
        }

        RequireText(output.Summary, "summary");
        RequireText(output.RecommendedNextAction, "recommendedNextAction");
        if (output.Reasoning is null || output.Reasoning.Count == 0)
        {
            throw new InvestigationOutputException("The AI response must include at least one reasoning claim.");
        }

        var evidence = context.Evidence.ToDictionary(item => item.Id, StringComparer.Ordinal);
        ValidateClaims(output.Reasoning, evidence);
        ValidateClaims(output.ContradictoryEvidence ?? [], evidence);
        foreach (var alternative in output.Alternatives ?? [])
        {
            if (alternative is null)
            {
                throw new InvestigationOutputException("The AI returned a null alternative.");
            }

            RequireText(alternative.Explanation, "alternatives.explanation");
            if (alternative.EvidenceIds is null)
            {
                throw new InvestigationOutputException("Each alternative must include an evidenceIds array.");
            }

            ValidateIds(alternative.EvidenceIds, evidence);
        }

        var references = output.EvidenceReferences ?? [];
        foreach (var reference in references)
        {
            if (reference is null)
            {
                throw new InvestigationOutputException("The AI returned a null evidence reference.");
            }

            ValidateReference(reference, evidence, context.Source);
        }

        var firstDivergence = output.Reconstruction?.FirstKnownDivergence;
        if (firstDivergence is not null)
        {
            RequireText(firstDivergence.Text, "reconstruction.firstKnownDivergence.text");
            if (firstDivergence.EvidenceIds is null)
            {
                throw new InvestigationOutputException("The first known divergence must include an evidenceIds array.");
            }

            ValidateIds(firstDivergence.EvidenceIds, evidence);
        }

        var unsupported = new List<string>();
        var reasoning = output.Reasoning.Select(claim =>
        {
            var kind = ParseClaimKind(claim.Kind);
            if (claim.EvidenceIds!.Count > 0)
            {
                return new ReasoningClaim(EvidenceSanitizer.Sanitize(claim.Text!), kind, claim.EvidenceIds);
            }

            unsupported.Add(claim.Text!);
            return new ReasoningClaim(
                $"{EvidenceSanitizer.Sanitize(claim.Text!)} [Unsupported assertion: no evidence reference was provided.]",
                kind,
                claim.EvidenceIds);
        }).ToArray();
        var contradictory = (output.ContradictoryEvidence ?? []).Select(claim =>
        {
            var text = EvidenceSanitizer.Sanitize(claim.Text!);
            if (claim.EvidenceIds!.Count > 0)
            {
                return new ReasoningClaim(text, ParseClaimKind(claim.Kind), claim.EvidenceIds);
            }

            unsupported.Add(text);
            return new ReasoningClaim(
                $"{text} [Unsupported assertion: no evidence reference was provided.]",
                ParseClaimKind(claim.Kind),
                claim.EvidenceIds);
        }).ToArray();
        var alternatives = (output.Alternatives ?? []).Select(item =>
        {
            var explanation = EvidenceSanitizer.Sanitize(item.Explanation!);
            if (item.EvidenceIds!.Count > 0)
            {
                return new AlternativeHypothesis(explanation, item.EvidenceIds);
            }

            unsupported.Add(explanation);
            return new AlternativeHypothesis(
                $"{explanation} [Unsupported alternative: no evidence reference was provided.]",
                item.EvidenceIds);
        }).ToArray();
        var summary = EvidenceSanitizer.Sanitize(output.Summary!);
        if (references.Count == 0)
        {
            summary += " [Unsupported assertion: no evidence reference was provided.]";
            unsupported.Add(summary);
        }

        var reconstruction = output.Reconstruction
            ?? throw new InvestigationOutputException("The AI response did not reconstruct the test from source.");
        var setup = ConvertSteps(reconstruction.SetupAndTeardown, evidence, context.Source);
        var actions = ConvertSteps(reconstruction.Actions, evidence, context.Source);
        var helpers = ConvertSteps(reconstruction.HelpersAndFixtures, evidence, context.Source);
        var inputs = ConvertSteps(reconstruction.InputsAndConfiguration, evidence, context.Source);
        var assertions = ConvertSteps(reconstruction.ExpectedResultsAndAssertions, evidence, context.Source);
        if (setup.Count + actions.Count + helpers.Count + inputs.Count + assertions.Count == 0)
        {
            throw new InvestigationOutputException("The AI response did not include any source-referenced test execution steps.");
        }

        ReasoningClaim? divergence = null;
        if (firstDivergence is not null)
        {
            divergence = new ReasoningClaim(
                EvidenceSanitizer.Sanitize(firstDivergence.Text!),
                ParseClaimKind(firstDivergence.Kind),
                firstDivergence.EvidenceIds!);
            if (divergence.EvidenceIds.Count == 0)
            {
                unsupported.Add(divergence.Text);
                divergence = divergence with
                {
                    Text = $"{divergence.Text} [Unsupported assertion: no evidence reference was provided.]"
                };
            }
        }

        var plan = output.ReproductionPlan
            ?? throw new InvestigationOutputException("The AI response did not include a reproduction plan.");
        RequireText(plan.SuspectedFailurePoint, "reproductionPlan.suspectedFailurePoint");
        if (plan.Steps is null || plan.Steps.Count == 0)
        {
            throw new InvestigationOutputException("The reproduction plan must include at least one step.");
        }

        if (plan.ExpectedObservations is null || plan.ExpectedObservations.Count == 0)
        {
            throw new InvestigationOutputException("The reproduction plan must specify expected observations.");
        }

        if (plan.SafetyConsiderations is null || plan.SafetyConsiderations.Count == 0)
        {
            throw new InvestigationOutputException("The reproduction plan must include safety considerations.");
        }

        var limitations = SanitizeStrings(output.Limitations, "limitations").ToList();
        limitations.Add("Confidence is a model estimate, not a statistically calibrated probability.");
        limitations.Add("No controlled reproduction runner is implemented; the plan was not executed.");
        limitations.Add("Only Azure DevOps failing-since metadata is used; historical test executions are not queried.");
        limitations.AddRange(context.Source.Limitations.Select(EvidenceSanitizer.Sanitize));
        if (unsupported.Count > 0)
        {
            limitations.Add($"{unsupported.Count} reasoning claim(s) were returned without evidence citations and are marked unsupported.");
        }

        var automaticMissing = context.Evidence
            .Where(item => item.Status != EvidenceCollectionStatus.Available)
            .Select(item => EvidenceSanitizer.Sanitize(
                $"{item.Type} evidence '{item.Path ?? item.Id}' is {item.Status}: {item.Error ?? "Content was not fully collected."}"))
            .Concat(context.CollectionErrors.Select(EvidenceSanitizer.Sanitize))
            .Concat(context.Source.MissingDependencies.Select(EvidenceSanitizer.Sanitize))
            .Concat(context.Source.Limitations.Select(EvidenceSanitizer.Sanitize));
        automaticMissing = automaticMissing.Append(
            "Historical test execution results were not collected; flakiness cannot be established from test history.");
        var deterministicContradictions = new List<ReasoningClaim>();
        if (string.Equals(context.Build.Result, "succeeded", StringComparison.OrdinalIgnoreCase)
            && string.Equals(context.TestResult.Outcome, "Failed", StringComparison.OrdinalIgnoreCase))
        {
            deterministicContradictions.Add(new ReasoningClaim(
                "Build metadata reports success while the selected test result reports failure; the metadata is inconsistent.",
                ClaimKind.Observation,
                ["build", $"test-result-{context.TestResult.RunId}-{context.TestResult.Id}"]));
        }

        return new InvestigationResult(
            InvestigationStatus.Completed,
            request.BuildId,
            context.TestRun.Id,
            request.TestResultId,
            classification,
            summary,
            reasoning,
            output.ConfidencePercent,
            references.Select(reference => ToDomainReference(reference, evidence)).ToArray(),
            contradictory.Concat(deterministicContradictions).ToArray(),
            alternatives,
            SanitizeStrings(output.MissingEvidence, "missingEvidence")
                .Concat(automaticMissing)
                .Distinct(StringComparer.Ordinal)
                .ToArray(),
            EvidenceSanitizer.Sanitize(output.RecommendedNextAction!),
            output.SuggestedRemediation is null ? null : EvidenceSanitizer.Sanitize(output.SuggestedRemediation),
            limitations,
            context.CollectionErrors.Select(EvidenceSanitizer.Sanitize).ToArray(),
            new TestReconstruction(
                setup,
                actions,
                helpers,
                inputs,
                assertions,
                divergence,
                SanitizeStrings(reconstruction.AdditionalEvidenceNeeded, "reconstruction.additionalEvidenceNeeded")),
            new ReproductionPlan(
                EvidenceSanitizer.Sanitize(plan.SuspectedFailurePoint!),
                SanitizeStrings(plan.Preconditions, "reproductionPlan.preconditions"),
                SanitizeStrings(plan.Steps, "reproductionPlan.steps"),
                SanitizeStrings(plan.ExpectedObservations, "reproductionPlan.expectedObservations"),
                ["Not executed in this iteration; no controlled reproduction runner is implemented."],
                SanitizeStrings(plan.SafetyConsiderations, "reproductionPlan.safetyConsiderations"),
                ExecutionPerformed: false),
            EvidenceSanitizer.Sanitize(response.Model),
            response.InputTokens,
            response.OutputTokens,
            sanitizedResponse);
    }

    private static IReadOnlyList<ReconstructedStep> ConvertSteps(
        IReadOnlyList<ReconstructedStepOutput>? steps,
        IReadOnlyDictionary<string, EvidenceItem> evidence,
        TestSourceSnapshot source)
    {
        var result = new List<ReconstructedStep>();
        foreach (var step in steps ?? [])
        {
            if (step is null)
            {
                throw new InvestigationOutputException("The AI returned a null reconstructed test step.");
            }

            RequireText(step.Description, "reconstruction step description");
            if (step.SourceReferences is null || step.SourceReferences.Count == 0)
            {
                throw new InvestigationOutputException("Each reconstructed source step must cite a source file and line range.");
            }

            foreach (var reference in step.SourceReferences)
            {
                if (reference is null)
                {
                    throw new InvestigationOutputException("The AI returned a null source reference.");
                }

                ValidateReference(reference, evidence, source, requireSource: true);
            }

            result.Add(new ReconstructedStep(
                EvidenceSanitizer.Sanitize(step.Description!),
                ParseClaimKind(step.Kind),
                step.SourceReferences.Select(reference => ToDomainReference(reference, evidence)).ToArray()));
        }

        return result;
    }

    private static void ValidateClaims(
        IReadOnlyList<ClaimOutput> claims,
        IReadOnlyDictionary<string, EvidenceItem> evidence)
    {
        foreach (var claim in claims)
        {
            if (claim is null)
            {
                throw new InvestigationOutputException("The AI returned a null reasoning claim.");
            }

            RequireText(claim.Text, "claim.text");
            if (claim.EvidenceIds is null)
            {
                throw new InvestigationOutputException("Each claim must include an evidenceIds array.");
            }

            ValidateIds(claim.EvidenceIds, evidence);
            _ = ParseClaimKind(claim.Kind);
        }
    }

    private static void ValidateIds(
        IReadOnlyList<string>? ids,
        IReadOnlyDictionary<string, EvidenceItem> evidence)
    {
        foreach (var id in ids ?? [])
        {
            if (string.IsNullOrWhiteSpace(id) || !evidence.ContainsKey(id))
            {
                throw new InvestigationOutputException($"The AI cited unknown evidence ID '{id}'.");
            }
        }
    }

    private static void ValidateReference(
        ReferenceOutput reference,
        IReadOnlyDictionary<string, EvidenceItem> evidence,
        TestSourceSnapshot source,
        bool requireSource = false)
    {
        if (string.IsNullOrWhiteSpace(reference.EvidenceId)
            || !evidence.TryGetValue(reference.EvidenceId, out var item))
        {
            throw new InvestigationOutputException($"The AI cited unknown evidence ID '{reference.EvidenceId}'.");
        }

        if (requireSource && item.Type != EvidenceType.SourceCode)
        {
            throw new InvestigationOutputException("A test reconstruction reference must identify retrieved source code.");
        }

        if (item.Type == EvidenceType.SourceCode)
        {
            if (!string.Equals(item.Path, reference.Path, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvestigationOutputException($"Source reference path does not match evidence '{reference.EvidenceId}'.");
            }

            var file = source.Files.FirstOrDefault(file =>
                string.Equals(file.EvidenceId, reference.EvidenceId, StringComparison.Ordinal));
            if (file is null || reference.LineStart is null || reference.LineEnd is null
                || reference.LineStart < 1 || reference.LineEnd < reference.LineStart)
            {
                throw new InvestigationOutputException("A source reference must include a valid one-based line range.");
            }

            var lineCount = file.Content.Count(character => character == '\n') + 1;
            if (reference.LineEnd > lineCount)
            {
                throw new InvestigationOutputException($"Source line reference exceeds the retrieved file '{file.Path}'.");
            }
        }
    }

    private static ClaimKind ParseClaimKind(string? value)
    {
        if (string.Equals(value, "Inference", StringComparison.OrdinalIgnoreCase))
        {
            return ClaimKind.Hypothesis;
        }

        if (!Enum.TryParse<ClaimKind>(value, true, out var kind) || !Enum.IsDefined(kind))
        {
            throw new InvestigationOutputException($"The AI returned an unknown claim kind '{value}'.");
        }

        return kind;
    }

    private static EvidenceReference ToDomainReference(
        ReferenceOutput output,
        IReadOnlyDictionary<string, EvidenceItem> evidence)
    {
        var item = evidence[output.EvidenceId!];
        return new EvidenceReference(
            item.Id,
            item.Path,
            output.LineStart,
            output.LineEnd,
            item.Url is null ? null : EvidenceSanitizer.Sanitize(item.Url),
            item.Revision,
            item.Timestamp);
    }

    private static string RequireText(string? value, string field)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new InvestigationOutputException($"The AI response is missing required field '{field}'.");
        }

        return value;
    }

    private static IReadOnlyList<string> SanitizeStrings(IEnumerable<string?>? values, string field)
    {
        var result = new List<string>();
        foreach (var value in values ?? [])
        {
            result.Add(EvidenceSanitizer.Sanitize(RequireText(value, field)));
        }

        return result;
    }
}

public sealed class InvestigationOutput
{
    public string? Classification { get; set; }
    public string? Summary { get; set; }
    public List<ClaimOutput>? Reasoning { get; set; }
    public int ConfidencePercent { get; set; }
    public List<ReferenceOutput>? EvidenceReferences { get; set; }
    public List<ClaimOutput>? ContradictoryEvidence { get; set; }
    public List<AlternativeOutput>? Alternatives { get; set; }
    public List<string>? MissingEvidence { get; set; }
    public string? RecommendedNextAction { get; set; }
    public string? SuggestedRemediation { get; set; }
    public List<string>? Limitations { get; set; }
    public ReconstructionOutput? Reconstruction { get; set; }
    public ReproductionPlanOutput? ReproductionPlan { get; set; }
}

public sealed class ClaimOutput
{
    public string? Text { get; set; }
    public string? Kind { get; set; }
    public List<string>? EvidenceIds { get; set; }
}

public sealed class ReferenceOutput
{
    public string? EvidenceId { get; set; }
    public string? Path { get; set; }
    public int? LineStart { get; set; }
    public int? LineEnd { get; set; }
    public string? Url { get; set; }
}

public sealed class AlternativeOutput
{
    public string? Explanation { get; set; }
    public List<string>? EvidenceIds { get; set; }
}

public sealed class ReconstructedStepOutput
{
    public string? Description { get; set; }
    public string? Kind { get; set; }
    public List<ReferenceOutput>? SourceReferences { get; set; }
}

public sealed class ReconstructionOutput
{
    public List<ReconstructedStepOutput>? SetupAndTeardown { get; set; }
    public List<ReconstructedStepOutput>? Actions { get; set; }
    public List<ReconstructedStepOutput>? HelpersAndFixtures { get; set; }
    public List<ReconstructedStepOutput>? InputsAndConfiguration { get; set; }
    public List<ReconstructedStepOutput>? ExpectedResultsAndAssertions { get; set; }
    public ClaimOutput? FirstKnownDivergence { get; set; }
    public List<string>? AdditionalEvidenceNeeded { get; set; }
}

public sealed class ReproductionPlanOutput
{
    public string? SuspectedFailurePoint { get; set; }
    public List<string>? Preconditions { get; set; }
    public List<string>? Steps { get; set; }
    public List<string>? ExpectedObservations { get; set; }
    public List<string>? ActualObservations { get; set; }
    public List<string>? SafetyConsiderations { get; set; }
}
