using System.Net;
using System.Text;
using System.Text.Json;
using AITestReviewAgent.Configuration;
using AITestReviewAgent.Domain;
using AITestReviewAgent.Infrastructure;

namespace AITestReviewAgent.AI;

public sealed class GoogleGeminiProvider : ILLMProvider
{
    private const int MaxResponseBytes = 1_000_000;
    private readonly HttpClient _httpClient;
    private readonly AiOptions _options;
    private readonly Uri _endpoint;

    public GoogleGeminiProvider(HttpClient httpClient, AiOptions options)
    {
        _httpClient = httpClient;
        _options = options;
        _options.Validate(requireCredentials: true);
        _endpoint = new Uri(options.Endpoint.TrimEnd('/') + "/", UriKind.Absolute);
        _httpClient.Timeout = TimeSpan.FromSeconds(_options.TimeoutSeconds);
    }

    public bool SupportsImages => _options.SupportsImages;

    public async Task<ProviderResponse> CompleteAsync(
        LlmRequest request,
        CancellationToken cancellationToken)
    {
        var body = JsonSerializer.Serialize(new
        {
            systemInstruction = new
            {
                parts = new[] { new { text = request.SystemPrompt } }
            },
            contents = new[]
            {
                new
                {
                    role = "user",
                    parts = CreateUserParts(request)
                }
            },
            generationConfig = new
            {
                responseMimeType = "application/json",
                maxOutputTokens = request.MaxOutputTokens,
                temperature = _options.Temperature
            }

        });
        var uri = new Uri(
            _endpoint,
            $"models/{Uri.EscapeDataString(request.Model)}:generateContent");

        HttpResponseMessage response;
        try
        {
            response = await HttpRetry.SendPostAsync(
                _httpClient,
                () =>
                {
                    var message = new HttpRequestMessage(HttpMethod.Post, uri)
                    {
                        Content = new StringContent(body, Encoding.UTF8, "application/json")
                    };
                    message.Headers.TryAddWithoutValidation("x-goog-api-key", _options.ApiKey);
                    return message;
                },
                cancellationToken);
        }
        catch (HttpRequestException)
        {
            throw new LlmProviderException("The configured Google Gemini API could not be reached.");
        }
        catch (TaskCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            throw new LlmProviderException("The Google Gemini request timed out.");
        }

        using (response)
        {
            if (!response.IsSuccessStatusCode)
            {
                if (IsTransient(response.StatusCode))
                {
                    throw new LlmProviderException(
                        $"Google Gemini returned transient HTTP {(int)response.StatusCode}; retry the investigation later.");
                }

                throw new LlmProviderException(
                    $"Google Gemini rejected the request with HTTP {(int)response.StatusCode}; check API key, model, and quota.");
            }

            var json = await ReadResponseAsync(response, cancellationToken);
            try
            {
                using var document = JsonDocument.Parse(json);
                var root = document.RootElement;
                var candidates = root.GetProperty("candidates");
                if (candidates.ValueKind != JsonValueKind.Array || candidates.GetArrayLength() == 0)
                {
                    throw new LlmProviderException("Google Gemini returned no response candidate.");
                }

                var candidate = candidates[0];
                var finishReason = candidate.TryGetProperty("finishReason", out var finishReasonElement)
                    ? finishReasonElement.GetString()
                    : null;
                if (!string.IsNullOrEmpty(finishReason)
                    && !string.Equals(finishReason, "STOP", StringComparison.OrdinalIgnoreCase))
                {
                    throw new LlmProviderException(
                        $"Google Gemini did not complete a usable response (finish reason: {finishReason}).");
                }

                var parts = candidate.GetProperty("content").GetProperty("parts");
                var text = string.Join(
                    string.Empty,
                    parts.EnumerateArray()
                        .Where(part => !part.TryGetProperty("thought", out var thought) || thought.ValueKind != JsonValueKind.True)
                        .Where(part => part.TryGetProperty("text", out _))
                        .Select(part => part.GetProperty("text").GetString()));
                if (string.IsNullOrWhiteSpace(text))
                {
                    throw new LlmProviderException("Google Gemini returned no structured response content.");
                }

                var usage = root.TryGetProperty("usageMetadata", out var usageElement)
                    ? usageElement
                    : default;
                var model = root.TryGetProperty("modelVersion", out var modelVersion)
                    ? modelVersion.GetString() ?? request.Model
                    : request.Model;
                return new ProviderResponse(
                    text,
                    model,
                    ReadTokenCount(usage, "promptTokenCount"),
                    ReadTokenCount(usage, "candidatesTokenCount"));
            }
            catch (JsonException)
            {
                throw new LlmProviderException("Google Gemini returned malformed response JSON.");
            }
            catch (KeyNotFoundException)
            {
                throw new LlmProviderException("Google Gemini response did not contain the expected generateContent fields.");
            }
            catch (InvalidOperationException)
            {
                throw new LlmProviderException("Google Gemini returned unexpected generateContent response fields.");
            }
        }
    }

    private static object[] CreateUserParts(LlmRequest request)
    {
        var parts = new List<object> { new { text = request.UserPrompt } };
        foreach (var image in request.Images ?? Array.Empty<ImageInput>())
        {
            parts.Add(new
            {
                inlineData = new
                {
                    mimeType = image.MediaType,
                    data = Convert.ToBase64String(image.Content)
                }
            });
        }

        return parts.ToArray();
    }

    private static async Task<string> ReadResponseAsync(
        HttpResponseMessage response,
        CancellationToken cancellationToken)
    {
        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken);
        using var output = new MemoryStream();
        var buffer = new byte[8192];
        while (output.Length <= MaxResponseBytes)
        {
            var count = await stream.ReadAsync(
                buffer.AsMemory(0, Math.Min(buffer.Length, MaxResponseBytes + 1 - (int)output.Length)),
                cancellationToken);
            if (count == 0)
            {
                break;
            }

            output.Write(buffer, 0, count);
        }

        if (output.Length > MaxResponseBytes)
        {
            throw new LlmProviderException("Google Gemini response exceeded the configured safety limit.");
        }

        return Encoding.UTF8.GetString(output.ToArray());
    }

    private static long? ReadTokenCount(JsonElement usage, string propertyName) =>
        usage.ValueKind == JsonValueKind.Object
        && usage.TryGetProperty(propertyName, out var value)
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
