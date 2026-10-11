namespace AITestReviewAgent.AzureDevOps;

public sealed class AzureDevOpsException(string message, int? statusCode = null) : Exception(message)
{
    public int? StatusCode { get; } = statusCode;
}
