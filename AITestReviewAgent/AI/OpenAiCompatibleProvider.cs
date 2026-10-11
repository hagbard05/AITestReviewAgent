using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using AITestReviewAgent.Configuration;
using AITestReviewAgent.Domain;
using AITestReviewAgent.Infrastructure;

namespace AITestReviewAgent.AI;

public sealed class OpenAiCompatibleProvider : ILLMProvider
{
    private readonly HttpClient _httpClient;
    private readonly AiOptions _options;

    public OpenAiCompatibleProvider(HttpClient httpClient, AiOptions options)
    {
        _httpClient = httpClient;
        _options = options;
        _options.Validate(requireCredentials: true);
        _httpClient.Timeout = TimeSpan.FromSeconds(_options.TimeoutSeconds);
        _httpClient.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", _options.ApiKey);
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
            response_format = new { type = "json_object" },
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
                if (IsTransient(response.StatusCode))
                {
                    throw new LlmProviderException(
                        $"The AI provider returned transient HTTP {(int)response.StatusCode}; retry the investigation later.");
                }

                throw new LlmProviderException(
                    $"The AI provider rejected the request with HTTP {(int)response.StatusCode}; check provider configuration and quota.");
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

    private static bool IsTransient(HttpStatusCode status) =>
        status is HttpStatusCode.RequestTimeout
            or HttpStatusCode.TooManyRequests
            or HttpStatusCode.BadGateway
            or HttpStatusCode.ServiceUnavailable
            or HttpStatusCode.GatewayTimeout
        || (int)status >= 500;
}
