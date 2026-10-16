using System.Text.Json;
using System.Text.Json.Serialization;
using AITestReviewAgent.AI;
using AITestReviewAgent.AzureDevOps;
using AITestReviewAgent.Configuration;
using AITestReviewAgent.Domain;
using AITestReviewAgent.Evidence;
using AITestReviewAgent.Investigation;
using AITestReviewAgent.Reports;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace AITestReviewAgent;

public class Program
{
    private static readonly JsonSerializerOptions ReportJsonOptions = new()
    {
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() }
    };

    public static async Task<int> Main(string[] args)
    {
        if (args.Length == 0 || args[0] is "help" or "--help" or "-h")
        {
            PrintUsage();
            return 0;
        }

        using var cancellationSource = new CancellationTokenSource();
        ConsoleCancelEventHandler cancelHandler = (_, eventArgs) =>
        {
            eventArgs.Cancel = true;
            cancellationSource.Cancel();
        };
        Console.CancelKeyPress += cancelHandler;

        try
        {
            using var host = CreateHost();
            var configuration = host.Services.GetRequiredService<Microsoft.Extensions.Configuration.IConfiguration>();
            var azureOptions = AzureDevOpsOptions.From(configuration);
            var aiOptions = AiOptions.From(configuration);
            var azure = host.Services.GetRequiredService<IAzureDevOpsClient>();
            var logger = host.Services.GetRequiredService<ILogger<Program>>();
            var command = args[0].ToLowerInvariant();

            switch (command)
            {
                case "runs":
                    azureOptions.Validate(requireCredentials: true);
                    await ListRunsAsync(azure, azureOptions, cancellationSource.Token);
                    return 0;

                case "tests":
                    azureOptions.Validate(requireCredentials: true);
                    await ListTestsAsync(
                        azure,
                        ParsePositiveInt(args, "--build-id"),
                        azureOptions,
                        cancellationSource.Token);
                    return 0;

                case "investigate":
                    azureOptions.Validate(requireCredentials: true);
                    aiOptions.Validate(requireCredentials: true);
                    var buildId = ParsePositiveInt(args, "--build-id");
                    var testResultId = ParsePositiveInt(args, "--test-result-id");
                    var testRunId = ParseOptionalPositiveInt(args, "--test-run-id");
                    var outputPath = ParseOptionalValue(args, "--output");
                    if (outputPath is not null && File.Exists(outputPath))
                    {
                        throw new InvestigationWorkflowException(
                            $"Report file '{outputPath}' already exists; choose a different output path.");
                    }

                    Console.WriteLine(
                        $"This sends sanitized failure evidence and test source to {aiOptions.Provider}/{aiOptions.Model}.");
                    Console.Write("Authorize this model request?: (y) ");
                    if (!string.Equals(Console.ReadKey().KeyChar.ToString().ToLower(), "y", StringComparison.Ordinal))
                    {
                        Console.WriteLine("Model request not authorised Investigation not submitted.");
                        return 0;
                    }

                    logger.LogInformation(
                        "Starting read-only investigation for build {BuildId}, test result {TestResultId}",
                        buildId,
                        testResultId);
                    Console.WriteLine("Collecting build, test, attachment, and exact-commit source evidence...");
                    var result = await host.Services.GetRequiredService<InvestigationOrchestrator>()
                        .InvestigateAsync(new InvestigationRequest(buildId, testResultId, testRunId), cancellationSource.Token);
                    if (outputPath is not null)
                    {
                        var report = JsonSerializer.Serialize(result, ReportJsonOptions);
                        var fullPath = await InvestigationReportWriter.WriteNewAsync(
                            outputPath, report, cancellationSource.Token);
                        Console.WriteLine($"Report saved: {fullPath}");
                    }

                    PrintResult(result);
                    return result.Status == InvestigationStatus.Failed ? 2 : 0;

                default:
                    Console.Error.WriteLine($"Unknown command '{args[0]}'.");
                    PrintUsage();
                    return 2;
            }
        }
        catch (OperationCanceledException) when (cancellationSource.IsCancellationRequested)
        {
            Console.Error.WriteLine("Operation cancelled.");
            return 130;
        }
        catch (Exception exception) when (exception is
            ConfigurationException
            or AzureDevOpsException
            or LlmProviderException
            or InvestigationOutputException
            or InvestigationWorkflowException
            or IOException
            or UnauthorizedAccessException)
        {
            Console.Error.WriteLine($"Error: {exception.Message}");
            return 2;
        }
        finally
        {
            Console.CancelKeyPress -= cancelHandler;
        }
    }

    private static IHost CreateHost()
    {
        var builder = Host.CreateApplicationBuilder();
        builder.Configuration
            .AddJsonFile(Path.Combine(AppContext.BaseDirectory, "appsettings.json"), optional: true, reloadOnChange: false)
            .AddUserSecrets(typeof(Program).Assembly, optional: true)
            .AddEnvironmentVariables();
        builder.Logging.SetMinimumLevel(LogLevel.Information);

        var azureOptions = AzureDevOpsOptions.From(builder.Configuration);
        var aiOptions = AiOptions.From(builder.Configuration);
        builder.Services.AddSingleton(azureOptions);
        builder.Services.AddSingleton(aiOptions);
        builder.Services.AddHttpClient<IAzureDevOpsClient, AzureDevOpsClient>();
        if (aiOptions.Provider.Equals("gemini", StringComparison.OrdinalIgnoreCase))
        {
            builder.Services.AddHttpClient<ILLMProvider, GoogleGeminiProvider>();
        }
        else
        {
            builder.Services.AddHttpClient<ILLMProvider, OpenAiCompatibleProvider>();
        }
        builder.Services.AddSingleton(new EvidenceNormalizer(30_000));
        builder.Services.AddTransient<TestSourceCollector>();
        builder.Services.AddTransient<IAIInvestigator, AIInvestigator>();
        builder.Services.AddTransient<InvestigationOrchestrator>();
        return builder.Build();
    }

    private static async Task ListRunsAsync(
        IAzureDevOpsClient azure,
        AzureDevOpsOptions options,
        CancellationToken cancellationToken)
    {
        var builds = await azure.GetRecentFailedBuildsAsync(options.MaxBuilds, cancellationToken);
        if (builds.Count == 0)
        {
            Console.WriteLine("No failed pipeline runs were returned.");
            return;
        }

        foreach (var build in builds)
        {
            Console.WriteLine(
                $"{build.Id}\t{build.Name}\t{build.FinishTime?.ToString("u") ?? "unknown"}\t{build.SourceVersion}\t{build.Url}");
        }
    }

    private static async Task ListTestsAsync(
        IAzureDevOpsClient azure,
        int buildId,
        AzureDevOpsOptions options,
        CancellationToken cancellationToken)
    {
        var build = await azure.GetBuildAsync(buildId, cancellationToken);
        var runs = await azure.GetTestRunsAsync(build, cancellationToken);
        var failures = 0;
        foreach (var run in runs)
        {
            var results = await azure.GetTestResultsAsync(run, options.MaxTestResults, cancellationToken);
            foreach (var result in results.Where(result =>
                         string.Equals(result.Outcome, "Failed", StringComparison.OrdinalIgnoreCase)))
            {
                Console.WriteLine($"{result.Id}\tRun {run.Id}\t{result.TestCaseTitle}\t{result.AutomatedTestName}");
                failures++;
            }
        }

        if (failures == 0)
        {
            Console.WriteLine($"No failed test results were returned for build {buildId}.");
        }
    }

    private static void PrintResult(InvestigationResult result)
    {
        Console.WriteLine();
        Console.WriteLine($"Status: {result.Status}");
        Console.WriteLine($"Classification: {result.Classification}");
        Console.WriteLine($"Confidence estimate: {result.ConfidencePercent}% (not statistically calibrated)");
        Console.WriteLine($"Summary: {result.Summary}");
        Console.WriteLine($"Build/test run/result: {result.BuildId}/{result.TestRunId}/{result.TestResultId}");

        PrintClaims("Reasoning", result.Reasoning);
        PrintClaims("Contradictory evidence", result.ContradictoryEvidence);
        PrintReferences(result.EvidenceReferences);
        PrintHypotheses(result.Alternatives);
        PrintList("Missing evidence", result.MissingEvidence);
        Console.WriteLine($"Recommended next action: {result.RecommendedNextAction}");
        if (!string.IsNullOrWhiteSpace(result.SuggestedRemediation))
        {
            Console.WriteLine($"Suggested remediation: {result.SuggestedRemediation}");
        }

        PrintReconstruction(result.Reconstruction);
        Console.WriteLine($"Reproduction performed: {result.ReproductionPlan.ExecutionPerformed}");
        Console.WriteLine($"Reproduction plan: {result.ReproductionPlan.SuspectedFailurePoint}");
        PrintList("Reproduction steps", result.ReproductionPlan.Steps);
        PrintList("Limitations", result.Limitations);
        PrintList("Collection/processing errors", result.Errors);
        if (result.Model is not null)
        {
            Console.WriteLine(
                $"Model: {result.Model}; token usage: input={result.InputTokens?.ToString() ?? "not reported"}, output={result.OutputTokens?.ToString() ?? "not reported"}");
        }

        if (result.ModelResponse is not null)
        {
            Console.WriteLine();
            Console.WriteLine("Complete model response (secrets redacted):");
            Console.WriteLine(result.ModelResponse);
        }
    }

    private static void PrintClaims(string title, IReadOnlyList<ReasoningClaim> claims)
    {
        Console.WriteLine($"{title}:");
        if (claims.Count == 0)
        {
            Console.WriteLine("  (none)");
            return;
        }

        foreach (var claim in claims)
        {
            Console.WriteLine($"  [{claim.Kind}] {claim.Text} (evidence: {string.Join(", ", claim.EvidenceIds)})");
        }
    }

    private static void PrintReferences(IReadOnlyList<EvidenceReference> references)
    {
        Console.WriteLine("Evidence references:");
        foreach (var reference in references)
        {
            var location = reference.Path is null
                ? reference.Url
                : $"{reference.Path}:{reference.LineStart}-{reference.LineEnd}"
                  + (reference.Revision is null ? string.Empty : $" @ {reference.Revision}")
                  + (reference.Timestamp is null ? string.Empty : $" ({reference.Timestamp:O})")
                  + (reference.Url is null ? string.Empty : $" ({reference.Url})");
            Console.WriteLine($"  {reference.EvidenceId}\t{location}");
        }
    }

    private static void PrintHypotheses(IReadOnlyList<AlternativeHypothesis> alternatives)
    {
        Console.WriteLine("Alternative explanations:");
        foreach (var alternative in alternatives)
        {
            Console.WriteLine($"  {alternative.Explanation} (evidence: {string.Join(", ", alternative.EvidenceIds)})");
        }
    }

    private static void PrintReconstruction(TestReconstruction reconstruction)
    {
        Console.WriteLine("Test source reconstruction:");
        PrintSteps("Setup/teardown", reconstruction.SetupAndTeardown);
        PrintSteps("Actions", reconstruction.Actions);
        PrintSteps("Helpers/fixtures", reconstruction.HelpersAndFixtures);
        PrintSteps("Inputs/configuration", reconstruction.InputsAndConfiguration);
        PrintSteps("Expected results/assertions", reconstruction.ExpectedResultsAndAssertions);
        if (reconstruction.FirstKnownDivergence is not null)
        {
            Console.WriteLine($"  First known divergence: {reconstruction.FirstKnownDivergence.Text}");
        }

        PrintList("Additional evidence needed", reconstruction.AdditionalEvidenceNeeded);
    }

    private static void PrintSteps(string title, IReadOnlyList<ReconstructedStep> steps)
    {
        Console.WriteLine($"  {title}:");
        foreach (var step in steps)
        {
            var references = string.Join(", ", step.SourceReferences.Select(reference =>
                $"{reference.Path}:{reference.LineStart}-{reference.LineEnd}"));
            Console.WriteLine($"    [{step.Kind}] {step.Description} ({references})");
        }
    }

    private static void PrintList(string title, IReadOnlyList<string> values)
    {
        Console.WriteLine($"{title}:");
        foreach (var value in values)
        {
            Console.WriteLine($"  - {value}");
        }
    }

    private static int ParsePositiveInt(string[] args, string name)
    {
        var value = ParseOptionalValue(args, name);
        if (!int.TryParse(value, out var result) || result <= 0)
        {
            throw new InvestigationWorkflowException($"Provide a positive integer value for {name}.");
        }

        return result;
    }

    private static int? ParseOptionalPositiveInt(string[] args, string name)
    {
        var value = ParseOptionalValue(args, name);
        if (value is null)
        {
            return null;
        }

        if (!int.TryParse(value, out var result) || result <= 0)
        {
            throw new InvestigationWorkflowException($"Provide a positive integer value for {name}.");
        }

        return result;
    }

    private static string? ParseOptionalValue(string[] args, string name)
    {
        var index = Array.FindIndex(args, argument =>
            string.Equals(argument, name, StringComparison.OrdinalIgnoreCase));
        if (index < 0)
        {
            return null;
        }

        if (index + 1 >= args.Length || args[index + 1].StartsWith("--", StringComparison.Ordinal))
        {
            throw new InvestigationWorkflowException($"Provide a value after {name}.");
        }

        return args[index + 1];
    }

    private static void PrintUsage()
    {
        Console.WriteLine(
            """
            AI-powered Azure DevOps test failure investigator

            Commands:
              runs
                  List recent failed pipeline runs.
              tests --build-id <id>
                  List failed test results in a run.
              investigate --build-id <id> --test-result-id <id> [--test-run-id <id>] [--output <file>]
                  Investigate one failed test. Diagnosis is withheld unless its test source is
                  retrieved and verified at the build's exact commit.

            Configure AzureDevOps:Organization and AzureDevOps:Project in appsettings.json or
            environment variables. Store AzureDevOps:PersonalAccessToken and AI:ApiKey using
            .NET User Secrets. AI provider/model/endpoint are configured under AI.
            """);
    }
}
