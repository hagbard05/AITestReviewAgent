namespace AITestReviewAgent.AI;

public sealed class LlmProviderException(string message) : Exception(message);

public sealed class InvestigationOutputException(string message) : Exception(message);
