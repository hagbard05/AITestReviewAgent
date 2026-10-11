using System.Globalization;
using Microsoft.Extensions.Configuration;

namespace AITestReviewAgent.Configuration;

public sealed record AzureDevOpsOptions(
    string Organization,
    string Project,
    string PersonalAccessToken,
    int MaxBuilds,
    int MaxTestResults,
    int MaxSourceFiles,
    int MaxSourceCharacters)
{
    public static AzureDevOpsOptions From(IConfiguration configuration) => new(
        configuration["AzureDevOps:Organization"] ?? string.Empty,
        configuration["AzureDevOps:Project"] ?? string.Empty,
        configuration["AzureDevOps:PersonalAccessToken"] ?? string.Empty,
        ReadInt(configuration["AzureDevOps:MaxBuilds"], "AzureDevOps:MaxBuilds", 20),
        ReadInt(configuration["AzureDevOps:MaxTestResults"], "AzureDevOps:MaxTestResults", 200),
        ReadInt(configuration["AzureDevOps:MaxSourceFiles"], "AzureDevOps:MaxSourceFiles", 120),
        ReadInt(configuration["AzureDevOps:MaxSourceCharacters"], "AzureDevOps:MaxSourceCharacters", 250_000));

    public void Validate(bool requireCredentials)
    {
        if (!Uri.TryCreate(Organization.TrimEnd('/') + "/", UriKind.Absolute, out var organizationUri)
            || organizationUri.Scheme != Uri.UriSchemeHttps)
        {
            throw new ConfigurationException("AzureDevOps:Organization must be an HTTPS Azure DevOps organization URL.");
        }

        if (string.IsNullOrWhiteSpace(Project))
        {
            throw new ConfigurationException("AzureDevOps:Project is required.");
        }

        if (requireCredentials && string.IsNullOrWhiteSpace(PersonalAccessToken))
        {
            throw new ConfigurationException(
                "Azure DevOps PAT is missing. Store it with 'dotnet user-secrets set \"AzureDevOps:PersonalAccessToken\" \"<PAT>\"'.");
        }

        if (MaxBuilds is < 1 or > 100 || MaxTestResults is < 1 or > 1000
            || MaxSourceFiles is < 1 or > 1000 || MaxSourceCharacters is < 1000 or > 2_000_000)
        {
            throw new ConfigurationException("Azure DevOps result and source limits are outside the supported bounds.");
        }
    }

    private static int ReadInt(string? setting, string key, int fallback)
    {
        if (setting is null)
        {
            return fallback;
        }

        return int.TryParse(setting, NumberStyles.Integer, CultureInfo.InvariantCulture, out var value)
            ? value
            : throw new ConfigurationException($"{key} must be an integer.");
    }
}

public sealed record AiOptions(
    string Provider,
    string Model,
    string Endpoint,
    string ApiKey,
    int TimeoutSeconds,
    int MaxOutputTokens,
    int MaxEvidenceCharacters,
    double Temperature)
{
    public static AiOptions From(IConfiguration configuration) => new(
        configuration["AI:Provider"] ?? "openai-compatible",
        configuration["AI:Model"] ?? string.Empty,
        configuration["AI:Endpoint"] ?? string.Empty,
        configuration["AI:ApiKey"] ?? string.Empty,
        ReadInt(configuration, "AI:TimeoutSeconds", 90),
        ReadInt(configuration, "AI:MaxOutputTokens", 5000),
        ReadInt(configuration, "AI:MaxEvidenceCharacters", 50_000),
        ReadDouble(configuration, "AI:Temperature", 0));

    public void Validate(bool requireCredentials)
    {
        if (!string.Equals(Provider, "openai-compatible", StringComparison.OrdinalIgnoreCase))
        {
            throw new ConfigurationException("AI:Provider must be 'openai-compatible'; no other provider is implemented.");
        }

        if (string.IsNullOrWhiteSpace(Model))
        {
            throw new ConfigurationException("AI:Model is required.");
        }

        if (!Uri.TryCreate(Endpoint, UriKind.Absolute, out var endpoint)
            || (endpoint.Scheme != Uri.UriSchemeHttps
                && !(endpoint.Scheme == Uri.UriSchemeHttp && endpoint.IsLoopback)))
        {
            throw new ConfigurationException("AI:Endpoint must be HTTPS (HTTP is allowed only for localhost tests).");
        }

        if (requireCredentials && string.IsNullOrWhiteSpace(ApiKey))
        {
            throw new ConfigurationException(
                "AI API key is missing. Store it with 'dotnet user-secrets set \"AI:ApiKey\" \"<key>\"'.");
        }

        if (TimeoutSeconds is < 1 or > 600 || MaxOutputTokens is < 100 or > 100_000
            || MaxEvidenceCharacters is < 1000 or > 200_000
            || !double.IsFinite(Temperature) || Temperature is < 0 or > 2)
        {
            throw new ConfigurationException("AI timeout or payload limits are outside the supported bounds.");
        }
    }

    private static int ReadInt(IConfiguration configuration, string key, int fallback) =>
        ReadInt(configuration[key], key, fallback);

    private static int ReadInt(string? setting, string key, int fallback)
    {
        if (setting is null)
        {
            return fallback;
        }

        return int.TryParse(setting, NumberStyles.Integer, CultureInfo.InvariantCulture, out var value)
            ? value
            : throw new ConfigurationException($"{key} must be an integer.");
    }

    private static double ReadDouble(IConfiguration configuration, string key, double fallback)
    {
        var setting = configuration[key];
        if (setting is null)
        {
            return fallback;
        }

        return double.TryParse(setting, NumberStyles.Float, CultureInfo.InvariantCulture, out var value)
            ? value
            : throw new ConfigurationException($"{key} must be a number.");
    }
}

public sealed class ConfigurationException(string message) : Exception(message);
