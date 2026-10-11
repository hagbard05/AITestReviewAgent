# AI-Powered Azure DevOps Test Failure Investigator

A read-only .NET 10 command-line MVP for investigating one failed test result from an Azure DevOps pipeline. It retrieves build and test data, verifies the build's exact Git commit, reads the test source and bounded helper/configuration files at that commit, and asks one configured model for an evidence-cited diagnosis and safe reproduction plan.

## Requirements

- .NET 10 SDK.
- Azure DevOps access to the target project and Git repository.
- An API key for an OpenAI Chat Completions-compatible endpoint for live AI investigations. Calls may incur provider charges.

The project was modernized from the empty .NET Framework 4.7.2 shell to an SDK-style `net10.0` solution. No database or CI/CD integration other than Azure DevOps is used.

## Configure

Set `AzureDevOps:Organization` and `AzureDevOps:Project` in `AITestReviewAgent/appsettings.json` or with environment variables. For example, in PowerShell:

```powershell
$env:AzureDevOps__Organization = "https://dev.azure.com/your-organization"
$env:AzureDevOps__Project = "your-project"
```

Store credentials outside the repository using .NET User Secrets:

```powershell
dotnet user-secrets --project .\AITestReviewAgent\AITestReviewAgent.csproj set "AzureDevOps:PersonalAccessToken" "<PAT>"
dotnet user-secrets --project .\AITestReviewAgent\AITestReviewAgent.csproj set "AI:ApiKey" "<API-key>"
```

The initial Azure DevOps authentication method is a PAT. Grant only the read permissions needed to view builds, test runs/results/attachments, and repository contents. Typical PAT scopes are **Build: Read**, **Test Management: Read**, and **Code: Read**; the identity also needs corresponding project/build/test/repository read permissions. No write scope is used. Production Entra ID authentication is not implemented in this iteration.

`AI` settings in `appsettings.json` select the provider (`openai-compatible`), model, complete Chat Completions endpoint, request timeout, output-token limit, evidence-character limit, and temperature. Only `openai-compatible` is implemented. The API key is read from User Secrets or `AI__ApiKey`; never put it in `appsettings.json`.

## Run

From the solution directory:

```powershell
dotnet build .\AITestReviewAgent.slnx
dotnet test .\AITestReviewAgent.slnx
dotnet run --project .\AITestReviewAgent\AITestReviewAgent.csproj -- help
dotnet run --project .\AITestReviewAgent\AITestReviewAgent.csproj -- runs
dotnet run --project .\AITestReviewAgent\AITestReviewAgent.csproj -- tests --build-id 12345
dotnet run --project .\AITestReviewAgent\AITestReviewAgent.csproj -- investigate --build-id 12345 --test-result-id 67890 --test-run-id 24680 --output .\reports\12345-67890.investigation.json
```

The `runs` command lists recent failed builds; `tests` lists failed test result IDs and their test run IDs for a build; `investigate` handles one selected failed result. Pass `--test-run-id` from the `tests` output to scope result lookup to that run; it is optional. Before an AI request, the CLI requires the operator to type `INVESTIGATE`. Existing report paths are not overwritten. Ctrl+C cancels collection or analysis.

If the build's full commit SHA cannot be verified, the repository is unavailable, or the exact test method cannot be located unambiguously, the CLI returns a **preliminary / Inconclusive** report and does not call the model. The report contains source/provenance limitations and recommended next steps. Save reports only to an access-controlled location; they contain diagnostic text and Azure DevOps links, but not raw attachment bodies.

## Architecture

- `Domain/`: provider- and HTTP-independent models and interfaces.
- `AzureDevOps/`: read-only REST client, bounded pagination, authentication, and transient GET/response retry handling.
- `Evidence/` and `Security/`: evidence normalization, secret redaction, truncation, and source provenance.
- `Investigation/`: exact-commit test-source collection, bounded helper/config discovery, and deterministic workflow.
- `AI/`: prompt boundary, one OpenAI-compatible provider, structured response parsing, evidence-reference validation, and report construction.
- `Program.cs`: CLI, configuration, dependency injection, and report presentation.
- `AITestReviewAgent.Tests/`: offline unit, mocked HTTP, and synthetic end-to-end coverage.

The model receives source files with one-based line numbers and stable evidence IDs. Its citations are checked against the collected package; unknown IDs or invalid source paths/line ranges fail the investigation. Unsupported claims are labeled. Logs, test output, source, and attachments are explicitly treated as untrusted data in the system prompt and serialized as data. Common credential formats are redacted, evidence is bounded, and binary attachments are referenced but not sent to the model. The investigator never executes commands or modifies Azure DevOps.

Confidence is a subjective model estimate, not a calibrated probability. The result includes token usage when the provider reports it; token cost is not estimated because pricing varies by model/account. The reproduction plan is never executed: the returned report always records that reproduction was not performed.

## MVP limits

- One failed test result per invocation; there is no batch investigation or prior-run comparison. Azure DevOps `failingSince` metadata is preserved if present, but full historical runs are not queried. Duplicate submission protection is an explicit confirmation before every model request.
- Source retrieval is bounded by `AzureDevOps:MaxSourceFiles` and `MaxSourceCharacters` (defaults 120 and 250,000). Method/fixture dependency discovery is static and bounded; generated, reflective, inaccessible, or external dependencies can remain unresolved and are reported as limitations.
- At most 20 test attachments are considered; supported text attachments are capped at 200 KB each. Images and other binary diagnostics retain their Azure DevOps link but are not interpreted.
- Only the OpenAI-compatible provider is implemented. Its request/response behavior is tested with mocked HTTP; live Azure DevOps and paid provider access were not available for verification.
- Azure DevOps test history, screenshots/OCR, Entra authentication, cost estimation, controlled reproduction, multi-model review, and non-Azure DevOps CI integrations are out of scope.

To add another model provider, implement `ILLMProvider`, register it in `Program.CreateHost`, add a validated provider selection/configuration, and test its HTTP/error/structured-output behavior. Keep provider credentials and request parsing out of the domain and investigator.
