# AI-Powered Azure DevOps Test Failure Investigator

A read-only .NET 10 command-line MVP for investigating one failed test result from an Azure DevOps pipeline. It retrieves build and test data, verifies the build's exact Git commit, reads the test source and bounded helper/configuration files at that commit, and asks one configured model for an evidence-cited diagnosis and safe reproduction plan.

## Requirements

- .NET 10 SDK.
- Azure DevOps access to the target project, plus source repository access (Azure Repos or GitHub).
- An API key for either Google Gemini or an OpenAI Chat Completions-compatible endpoint for live AI investigations. Calls may incur provider charges.

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

The initial Azure DevOps authentication method is a PAT. Grant only the read permissions needed to view builds, test runs/results/attachments, and Azure Repos contents. Typical PAT scopes are **Build: Read**, **Test Management: Read**, and **Code: Read**; the identity also needs corresponding project/build/test/repository read permissions. No write scope is used. Production Entra ID authentication is not implemented in this iteration.

For Azure Pipelines builds using GitHub, the source provider is selected from the build's `repository.type` and validated against `repository.url`. Public GitHub repositories do not require a GitHub token. For private repositories, optionally provide a read-only GitHub token through User Secrets or `GitHub__Token`:

```powershell
dotnet user-secrets --project .\AITestReviewAgent\AITestReviewAgent.csproj set "GitHub:Token" "<read-only-token>"
```

GitHub commits are verified by full SHA, and files are fetched using that verified SHA; the collector never falls back to a branch or latest revision.

`AI` settings select the provider, model, endpoint, request timeout, output-token limit, evidence-character limit, and temperature. Supported providers are `openai-compatible` and `gemini`. The API key is read from User Secrets or `AI__ApiKey`; never put it in `appsettings.json`.

For LM Studio, use `AI:Provider = openai-compatible`, set `AI:Model` to the exact ID shown by `GET /v1/models`, and set `AI:Endpoint` to the full chat endpoint, such as `http://localhost:1234/v1/chat/completions`. Loopback OpenAI-compatible servers do not require `AI:ApiKey`; when provided, the key is sent as a Bearer token. Set `AI:SupportsImages` to `true` only when the selected model supports image input; it defaults to `false` for OpenAI-compatible providers and `true` for Gemini. The checked-in local example uses `qwen3-1.7b@q8_0` with image support disabled.

When image support is enabled for the selected model, supported screenshot attachments (PNG, JPEG, WebP, GIF) are retrieved and sent as Gemini inline image parts or OpenAI-compatible data-URL image parts. `AI:SupportsImages` is a model capability setting; keep it false for text-only models (including the checked-in Qwen example). Image retrieval is bounded to four images, 4 MB per image, and 8 MB total; oversized, unavailable, or invalid-format images are reported as evidence limitations rather than sent. Raw image bytes are held in memory only for the provider request and are not written to investigation reports or application logs. A text-only selected model still receives the screenshot’s Azure DevOps location and metadata, but no pixel data.

HTML page-source attachments (`.html` and `.htm`) are made available as bounded text evidence for any selected model. The collector removes scripts, styles, comments, and markup, then includes the page title, extracted text (browser visibility is not evaluated), links, and selected DOM landmarks (IDs, classes, roles, and accessible labels). Each page source is capped at 500 KB of downloaded input and 15,000 normalized characters, is prioritized after the failed test source in the prompt, and is explicitly treated as untrusted data. The attachment index links the normalized text to its Azure DevOps attachment and evidence ID; no HTML attachment is executed.

To select Gemini, get an API key from Google AI Studio, store it using the User Secrets command above, and set:

```powershell
$env:AI__Provider = "gemini"
$env:AI__Model = "gemini-2.5-flash"
$env:AI__Endpoint = "https://generativelanguage.googleapis.com/v1beta"
```

Gemini uses the native `generateContent` API, sends its key using the `x-goog-api-key` header, requests JSON output, and reports provider token usage where returned. For a persistent setup, set `AI:Provider`, `AI:Model`, and `AI:Endpoint` in local user configuration (do not store the key in `appsettings.json`). The CLI chooses exactly one provider per invocation.

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

The `runs` command lists recent failed builds; `tests` lists failed test result IDs and their test run IDs for a build; `investigate` handles one selected failed result. Pass `--test-run-id` from the `tests` output to scope result lookup to that run; it is optional. Before an AI request, the CLI requires the operator to type `INVESTIGATE`. Report parent directories are created automatically and existing report paths are not overwritten. Ctrl+C cancels collection or analysis.

If the build's full commit SHA cannot be verified, the repository is unavailable, or the exact test method cannot be located unambiguously, the CLI returns a **preliminary / Inconclusive** report and does not call the model. The report contains source/provenance limitations and recommended next steps. Save reports only to an access-controlled location; they contain diagnostic text and Azure DevOps links, but not raw attachment bodies.

## Architecture

- `Domain/`: provider- and HTTP-independent models and interfaces.
- `AzureDevOps/`: read-only REST client, bounded pagination, authentication, and transient GET/response retry handling.
- `SourceControl/`: Azure Repos and GitHub clients selected from Azure Pipelines repository metadata; source retrieval is pinned to the verified build commit.
- `Evidence/` and `Security/`: evidence normalization, secret redaction, truncation, and source provenance.
- `Investigation/`: exact-commit test-source collection, bounded helper/config discovery, and deterministic workflow.
- `AI/`: prompt boundary, OpenAI-compatible and native Google Gemini providers, structured response parsing, evidence-reference validation, and report construction.
- `Program.cs`: CLI, configuration, dependency injection, and report presentation.
- `AITestReviewAgent.Tests/`: offline unit, mocked HTTP, and synthetic end-to-end coverage.

The model receives source files with one-based line numbers and stable evidence IDs. Its citations are checked against the collected package; unknown IDs or invalid source paths/line ranges fail the investigation. Unsupported claims are labeled. Logs, test output, source, page-source text, and attachments are explicitly treated as untrusted data in the system prompt and serialized as data. Common credential formats are redacted and evidence is bounded. Binary attachments such as `screenshot.png` are listed in a separate, budget-independent index containing the evidence/attachment ID, filename, media type, Azure DevOps test-result location, and link. Image pixels are not sent to text-only AI providers; the model is instructed to identify where to open the screenshot and not claim visual inspection. The investigator never executes commands or modifies Azure DevOps.

After a provider responds, the complete model response text is logged and included in the investigation report and CLI output. Common credential patterns are redacted and terminal control characters are replaced before logging/display; the response remains untrusted model output. These logs and reports may contain diagnostic details, so keep them in an access-controlled location and do not enable less-restricted log forwarding.

Confidence is a subjective model estimate, not a calibrated probability. The result includes token usage when the provider reports it; token cost is not estimated because pricing varies by model/account. The reproduction plan is never executed: the returned report always records that reproduction was not performed.

## MVP limits

- One failed test result per invocation; there is no batch investigation or prior-run comparison. Azure DevOps `failingSince` metadata is preserved if present, but full historical runs are not queried. Duplicate submission protection is an explicit confirmation before every model request.
- Source retrieval is bounded by `AzureDevOps:MaxSourceFiles` and `MaxSourceCharacters` (defaults 120 and 250,000). Method/fixture dependency discovery is static and bounded; generated, reflective, inaccessible, or external dependencies can remain unresolved and are reported as limitations.
- At most 20 test attachments are considered; supported text attachments are capped at 200 KB each, except normalized HTML page source, which is capped at 500 KB input and 15,000 output characters. Images and other binary diagnostics retain their Azure DevOps link but are not interpreted.
- OpenAI-compatible and Google Gemini request/response behavior is covered by mocked HTTP tests; live Azure DevOps and paid provider access were not available for verification.
- Azure DevOps test history, screenshots/OCR, Entra authentication, cost estimation, controlled reproduction, multi-model review, and non-Azure DevOps CI integrations are out of scope.

To add another model provider, implement `ILLMProvider`, register it in `Program.CreateHost`, add a validated provider selection/configuration, and test its HTTP/error/structured-output behavior. Keep provider credentials and request parsing out of the domain and investigator.
