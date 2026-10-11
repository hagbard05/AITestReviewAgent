using System.Net;

namespace AITestReviewAgent.Infrastructure;

internal static class HttpRetry
{
    public static async Task<HttpResponseMessage> SendGetAsync(
        HttpClient client,
        Func<HttpRequestMessage> createRequest,
        CancellationToken cancellationToken)
        => await SendAsync(client, createRequest, retryNetworkErrors: true, cancellationToken);

    public static async Task<HttpResponseMessage> SendPostAsync(
        HttpClient client,
        Func<HttpRequestMessage> createRequest,
        CancellationToken cancellationToken)
        => await SendAsync(client, createRequest, retryNetworkErrors: false, cancellationToken);

    private static async Task<HttpResponseMessage> SendAsync(
        HttpClient client,
        Func<HttpRequestMessage> createRequest,
        bool retryNetworkErrors,
        CancellationToken cancellationToken)
    {
        const int maxAttempts = 3;

        for (var attempt = 1; ; attempt++)
        {
            try
            {
                using var request = createRequest();
                var response = await client.SendAsync(
                    request,
                    HttpCompletionOption.ResponseHeadersRead,
                    cancellationToken);

                if (!IsTransient(response.StatusCode) || attempt == maxAttempts)
                {
                    return response;
                }

                var delay = GetRetryDelay(response, attempt);
                response.Dispose();
                await Task.Delay(delay, cancellationToken);
            }
            catch (HttpRequestException) when (retryNetworkErrors && attempt < maxAttempts)
            {
                await Task.Delay(TimeSpan.FromMilliseconds(200 * attempt), cancellationToken);
            }
        }
    }

    private static bool IsTransient(HttpStatusCode status) =>
        status is HttpStatusCode.RequestTimeout
            or HttpStatusCode.TooManyRequests
            or HttpStatusCode.BadGateway
            or HttpStatusCode.ServiceUnavailable
            or HttpStatusCode.GatewayTimeout
        || (int)status >= 500;

    private static TimeSpan GetRetryDelay(HttpResponseMessage response, int attempt)
    {
        var retryAfter = response.Headers.RetryAfter;
        var serverDelay = retryAfter?.Delta
            ?? (retryAfter?.Date is { } date ? date - DateTimeOffset.UtcNow : null);
        var delay = serverDelay ?? TimeSpan.FromMilliseconds(200 * attempt);
        return TimeSpan.FromMilliseconds(Math.Clamp(delay.TotalMilliseconds, 0, 5000));
    }
}
