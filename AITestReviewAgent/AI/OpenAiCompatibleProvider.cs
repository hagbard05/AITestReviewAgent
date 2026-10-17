using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using AITestReviewAgent.Configuration;
using AITestReviewAgent.Domain;
using AITestReviewAgent.Infrastructure;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace AITestReviewAgent.AI;

public sealed class OpenAiCompatibleProvider : ILLMProvider
{
    private readonly HttpClient _httpClient;
    private readonly AiOptions _options;
    private readonly ILogger<OpenAiCompatibleProvider> _logger;

    public OpenAiCompatibleProvider(
        HttpClient httpClient,
        AiOptions options,
        ILogger<OpenAiCompatibleProvider>? logger = null)
    {
        _httpClient = httpClient;
        _options = options;
        _logger = logger ?? NullLogger<OpenAiCompatibleProvider>.Instance;
        _options.Validate(requireCredentials: true);
        _httpClient.Timeout = TimeSpan.FromSeconds(_options.TimeoutSeconds);
        if (!string.IsNullOrWhiteSpace(_options.ApiKey))
        {
            _httpClient.DefaultRequestHeaders.Authorization =
                new AuthenticationHeaderValue("Bearer", _options.ApiKey);
        }
    }

    public async Task<ProviderResponse> CompleteAsync(LlmRequest request, CancellationToken cancellationToken)
    {
        var body = JsonSerializer.Serialize(new
        {
            model = request.Model,
            messages = new[]
            {
                new { role = "system", content = request.SystemPrompt },
                new { role = "user", content = request.UserPrompt }
            },
            response_format = new { type = "text" },
            max_tokens = request.MaxOutputTokens,
            temperature = _options.Temperature
        });

        HttpResponseMessage response;
        try
        {
            response = await HttpRetry.SendPostAsync(
                _httpClient,
                () => new HttpRequestMessage(HttpMethod.Post, _options.Endpoint)
                {
                    Content = new StringContent(body, Encoding.UTF8, "application/json")
                },
                cancellationToken);
        }
        catch (HttpRequestException)
        {
            throw new LlmProviderException("The configured AI provider could not be reached.");
        }
        catch (TaskCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            throw new LlmProviderException("The AI provider request timed out.");
        }

        using (response)
        {
            if (!response.IsSuccessStatusCode)
            {
                var diagnostics = await ReadSafeErrorDiagnosticsAsync(response, cancellationToken);
                _logger.LogWarning(
                    "AI provider {Provider} endpoint {Endpoint} returned HTTP {StatusCode}. Safe response diagnostics: {Diagnostics}",
                    "OpenAI-compatible",
                    GetSafeEndpoint(_options.Endpoint),
                    (int)response.StatusCode,
                    diagnostics);

                if (IsTransient(response.StatusCode))
                {
                    throw new LlmProviderException(
                        $"The OpenAI-compatible provider returned transient HTTP {(int)response.StatusCode}; retry the investigation later.");
                }

                throw new LlmProviderException(
                    $"The OpenAI-compatible provider rejected the request with HTTP {(int)response.StatusCode}; check the configured endpoint, model ID, and provider error diagnostics.");
            }

            var json = await ReadResponseAsync(response, 1_000_000, cancellationToken);
            try
            {
                using var document = JsonDocument.Parse(json);
                var root = document.RootElement;
                var content = root.GetProperty("choices")[0].GetProperty("message").GetProperty("content").GetString();
                if (string.IsNullOrWhiteSpace(content))
                {
                    throw new LlmProviderException("The AI provider returned no structured response content.");
                }

                var usage = root.TryGetProperty("usage", out var usageElement) ? usageElement : default;
                return new ProviderResponse(
                    content,
                    root.TryGetProperty("model", out var modelElement) ? modelElement.GetString() ?? request.Model : request.Model,
                    ReadTokenCount(usage, "prompt_tokens"),
                    ReadTokenCount(usage, "completion_tokens"));
            }
            catch (JsonException)
            {
                throw new LlmProviderException("The AI provider returned malformed response JSON.");
            }
            catch (KeyNotFoundException)
            {
                throw new LlmProviderException("The AI provider response did not contain the expected chat completion fields.");
            }
            catch (IndexOutOfRangeException)
            {
                throw new LlmProviderException("The AI provider response did not contain a completion choice.");
            }
            catch (InvalidOperationException)
            {
                throw new LlmProviderException("The AI provider returned unexpected chat completion fields.");
            }
        }
    }

    private static async Task<string> ReadResponseAsync(
        HttpResponseMessage response,
        int maxBytes,
        CancellationToken cancellationToken)
    {
        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken);
        using var output = new MemoryStream();
        var buffer = new byte[8192];
        while (output.Length <= maxBytes)
        {
            var count = await stream.ReadAsync(
                buffer.AsMemory(0, Math.Min(buffer.Length, maxBytes + 1 - (int)output.Length)),
                cancellationToken);
            if (count == 0)
            {
                break;
            }

            output.Write(buffer, 0, count);
        }

        if (output.Length > maxBytes)
        {
            throw new LlmProviderException("The AI provider response exceeded the configured safety limit.");
        }

        return Encoding.UTF8.GetString(output.ToArray());
    }

    private static long? ReadTokenCount(JsonElement usage, string name) =>
        usage.ValueKind == JsonValueKind.Object
        && usage.TryGetProperty(name, out var value)
        && value.TryGetInt64(out var count)
            ? count
            : null;

    private static async Task<string> ReadSafeErrorDiagnosticsAsync(
        HttpResponseMessage response,
        CancellationToken cancellationToken)
    {
        const int maxDiagnosticBytes = 16_384;
        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken);
        using var output = new MemoryStream();
        var buffer = new byte[4096];
        while (output.Length <= maxDiagnosticBytes)
        {
            var read = await stream.ReadAsync(
                buffer.AsMemory(0, Math.Min(buffer.Length, maxDiagnosticBytes + 1 - (int)output.Length)),
                cancellationToken);
            if (read == 0)
            {
                break;
            }

            output.Write(buffer, 0, read);
        }

        if (output.Length > maxDiagnosticBytes)
        {
            return "error response exceeded diagnostic size limit; response body omitted";
        }

        try
        {
            using var document = JsonDocument.Parse(output.ToArray());
            var root = document.RootElement;
            var error = root.TryGetProperty("error", out var errorElement)
                ? errorElement
                : root;
            var safeFields = new[] { "code", "type", "param" }
                .Where(name => error.ValueKind == JsonValueKind.Object
                    && error.TryGetProperty(name, out var value)
                    && value.ValueKind == JsonValueKind.String)
                .Select(name => $"{name}={SanitizeDiagnosticValue(error.GetProperty(name).GetString())}")
                .ToArray();
            return safeFields.Length == 0
                ? "error response received; free-text message omitted to protect request evidence"
                : string.Join(", ", safeFields)
                    + "; free-text message omitted to protect request evidence";
        }
        catch (JsonException)
        {
            return "non-JSON error response received; response body omitted to protect request evidence";
        }
    }

    private static string SanitizeDiagnosticValue(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return "(empty)";
        }

        var safeValue = new string(value.Take(100)
            .Select(character => char.IsLetterOrDigit(character) || character is '_' or '-' or '.'
                ? character
                : '_')
            .ToArray());
        return safeValue;
    }

    private static string GetSafeEndpoint(string endpoint)
    {
        if (!Uri.TryCreate(endpoint, UriKind.Absolute, out var uri))
        {
            return "(invalid endpoint)";
        }

        return $"{uri.Scheme}://{uri.Authority}{uri.AbsolutePath}";
    }

    private static bool IsTransient(HttpStatusCode status) =>
        status is HttpStatusCode.RequestTimeout
            or HttpStatusCode.TooManyRequests
            or HttpStatusCode.BadGateway
            or HttpStatusCode.ServiceUnavailable
            or HttpStatusCode.GatewayTimeout
        || (int)status >= 500;
}
