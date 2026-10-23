using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using AITestReviewAgent.Configuration;
using AITestReviewAgent.Domain;
using AITestReviewAgent.Infrastructure;

namespace AITestReviewAgent.AzureDevOps;

public sealed class AzureDevOpsClient : IAzureDevOpsClient
{
    private const string ApiVersion = "7.1";
    private static readonly JsonSerializerOptions JsonOptions = new() { PropertyNameCaseInsensitive = true };
    private readonly HttpClient _httpClient;
    private readonly AzureDevOpsOptions _options;
    private readonly string _projectPath;

    public AzureDevOpsClient(HttpClient httpClient, AzureDevOpsOptions options)
    {
        _httpClient = httpClient;
        _options = options;
        _options.Validate(requireCredentials: true);
        _httpClient.Timeout = TimeSpan.FromSeconds(45);
        _httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue(
            "Basic",
            Convert.ToBase64String(Encoding.UTF8.GetBytes(":" + _options.PersonalAccessToken)));
        _httpClient.DefaultRequestHeaders.UserAgent.ParseAdd("AITestReviewAgent/1.0");
        _projectPath = $"{_options.Organization.TrimEnd('/')}/{Uri.EscapeDataString(_options.Project)}";
    }

    public async Task<IReadOnlyList<PipelineRun>> GetRecentFailedBuildsAsync(
        int top,
        CancellationToken cancellationToken)
    {
        var uri = ApiUri($"build/builds?queryOrder=finishTimeDescending&resultFilter=failed&$top={Math.Clamp(top, 1, 100)}");
        var builds = await GetCollectionAsync<BuildDto>(uri, cancellationToken);
        return builds.Select(MapBuild).ToArray();
    }

    public async Task<PipelineRun?> GetLatestBuildAsync(CancellationToken cancellationToken)
    {
        var builds = await GetCollectionAsync<BuildDto>(
            ApiUri("build/builds?queryOrder=finishTimeDescending&$top=1"), cancellationToken);
        return builds.Count == 0 ? null : MapBuild(builds[0]);
    }

    public async Task<PipelineRun> GetBuildAsync(int buildId, CancellationToken cancellationToken)
    {
        var dto = await GetObjectAsync<BuildDto>(ApiUri($"build/builds/{buildId}"), cancellationToken);
        return MapBuild(dto);
    }

    public async Task<IReadOnlyList<TestRun>> GetTestRunsAsync(
        PipelineRun build,
        CancellationToken cancellationToken)
    {
        var buildUri = Uri.EscapeDataString($"vstfs:///Build/Build/{build.Id}");
        var runs = await GetPagedCollectionAsync<TestRunDto>(
            skip => ApiUri($"test/runs?buildUri={buildUri}&$top=100&$skip={skip}"),
            maxItems: 1000,
            cancellationToken);
        return runs.Select(MapTestRun).ToArray();
    }

    public async Task<IReadOnlyList<TestCaseResult>> GetTestResultsAsync(
        TestRun testRun,
        int maxResults,
        CancellationToken cancellationToken)
    {
        var results = await GetPagedCollectionAsync<TestResultDto>(
            skip => ApiUri($"test/Runs/{testRun.Id}/results?$top=100&$skip={skip}"),
            Math.Clamp(maxResults, 1, 1000),
            cancellationToken);
        return results.Select(result => MapTestResult(result, testRun.Id)).ToArray();
    }

    public async Task<IReadOnlyList<TestAttachment>> GetTestAttachmentsAsync(
        int runId,
        int resultId,
        CancellationToken cancellationToken)
    {
        var uri = ApiUri($"test/Runs/{runId}/Results/{resultId}/attachments?api-version=7.1");
        var attachments = await GetCollectionAsync<AttachmentDto>(uri, cancellationToken);
        return attachments
            .Select(a => new TestAttachment(
                ConvertAttachmentId(a.Id),
                a.FileName ?? a.Name ?? "attachment",
                a.Url,
                a.Size,
                a.CreatedDate))
            .Where(a => !string.IsNullOrWhiteSpace(a.Id))
            .ToArray();
    }

    public async Task<byte[]?> GetTestAttachmentContentAsync(
        int runId,
        int resultId,
        string attachmentId,
        int maxBytes,
        CancellationToken cancellationToken)
    {
        var uri = ApiUri(
            $"test/Runs/{runId}/Results/{resultId}/attachments/{Uri.EscapeDataString(attachmentId)}?api-version=7.1");
        using var response = await SendGetAsync(uri, cancellationToken);
        if (response.StatusCode == System.Net.HttpStatusCode.NotFound)
        {
            return null;
        }

        EnsureSuccess(response);
        return await ReadBytesBoundedAsync(response, maxBytes + 1, cancellationToken);
    }

    public async Task<RepositoryCommit?> GetVerifiedCommitAsync(
        string repositoryId,
        string commitId,
        CancellationToken cancellationToken)
    {
        var dto = await GetObjectAsync<CommitDto>(
            ApiUri($"git/repositories/{Uri.EscapeDataString(repositoryId)}/commits/{Uri.EscapeDataString(commitId)}"),
            cancellationToken);
        return !string.IsNullOrWhiteSpace(dto.CommitId)
            && string.Equals(dto.CommitId, commitId, StringComparison.OrdinalIgnoreCase)
                ? new RepositoryCommit(dto.CommitId, dto.Committer?.Date)
                : null;
    }

    public async Task<IReadOnlyList<RepositoryItem>> GetRepositoryItemsAsync(
        string repositoryId,
        string commitId,
        CancellationToken cancellationToken)
    {
        var items = await GetCollectionAsync<GitItemDto>(
            ApiUri(
                $"git/repositories/{Uri.EscapeDataString(repositoryId)}/items?scopePath=%2F&recursionLevel=Full&includeContentMetadata=true&{CommitQuery(commitId)}"),
            cancellationToken);
        var maxItems = Math.Min(_options.MaxSourceFiles * 10, 10_000);
        var mapped = items.Take(maxItems).Select(item => new RepositoryItem(
                item.Path ?? string.Empty,
                item.IsFolder,
                item.ContentMetadata?.IsBinary ?? false,
                item.Url))
            .Where(item => !string.IsNullOrWhiteSpace(item.Path))
            .ToList();
        if (items.Count > maxItems)
        {
            mapped.Add(new RepositoryItem("[repository tree truncated by safety limit]", false, true, null, true));
        }

        return mapped;
    }

    public async Task<string?> GetRepositoryFileAsync(
        string repositoryId,
        string path,
        string commitId,
        int maxBytes,
        CancellationToken cancellationToken)
    {
        var queryPath = Uri.EscapeDataString(path);
        var uri = ApiUri(
            $"git/repositories/{Uri.EscapeDataString(repositoryId)}/items?path={queryPath}&includeContent=true&{CommitQuery(commitId)}");
        using var response = await SendGetAsync(uri, cancellationToken);
        if (response.StatusCode == System.Net.HttpStatusCode.NotFound)
        {
            return null;
        }

        EnsureSuccess(response);
        var bytes = await ReadBytesBoundedAsync(response, maxBytes + 1, cancellationToken);
        if (bytes.Length > maxBytes)
        {
            throw new AzureDevOpsException("A repository file exceeded the configured source retrieval size limit.");
        }

        var content = Encoding.UTF8.GetString(bytes);
        if (!string.Equals(
                response.Content.Headers.ContentType?.MediaType,
                "application/json",
                StringComparison.OrdinalIgnoreCase))
        {
            return content;
        }

        try
        {
            using var document = JsonDocument.Parse(content);
            if (document.RootElement.TryGetProperty("content", out var value)
                && value.ValueKind == JsonValueKind.String)
            {
                return value.GetString();
            }
        }
        catch (JsonException)
        {
            throw new AzureDevOpsException("Azure DevOps returned malformed repository file content.");
        }

        throw new AzureDevOpsException("Azure DevOps repository response did not contain file content.");
    }

    private async Task<IReadOnlyList<T>> GetCollectionAsync<T>(Uri uri, CancellationToken cancellationToken)
    {
        var json = await GetTextAsync(uri, 8_000_000, cancellationToken);
        try
        {
            using var document = JsonDocument.Parse(json);
            var array = document.RootElement.ValueKind == JsonValueKind.Array
                ? document.RootElement
                : document.RootElement.TryGetProperty("value", out var value)
                    ? value
                    : throw new AzureDevOpsException("Azure DevOps returned an unexpected collection response.");
            return JsonSerializer.Deserialize<List<T>>(array.GetRawText(), JsonOptions)
                ?? throw new AzureDevOpsException("Azure DevOps returned an empty collection response.");
        }
        catch (JsonException)
        {
            throw new AzureDevOpsException("Azure DevOps returned malformed collection JSON.");
        }
    }

    private async Task<IReadOnlyList<T>> GetPagedCollectionAsync<T>(
        Func<int, Uri> createUri,
        int maxItems,
        CancellationToken cancellationToken,
        int pageSize = 100)
    {
        var results = new List<T>(Math.Min(maxItems, 1000));
        for (var skip = 0; results.Count < maxItems; skip += pageSize)
        {
            var page = await GetCollectionAsync<T>(createUri(skip), cancellationToken);
            results.AddRange(page.Take(maxItems - results.Count));
            if (page.Count < pageSize)
            {
                break;
            }
        }

        return results;
    }

    private async Task<T> GetObjectAsync<T>(Uri uri, CancellationToken cancellationToken)
    {
        var json = await GetTextAsync(uri, 4_000_000, cancellationToken);
        try
        {
            return JsonSerializer.Deserialize<T>(json, JsonOptions)
                ?? throw new AzureDevOpsException("Azure DevOps returned an empty response.");
        }
        catch (JsonException)
        {
            throw new AzureDevOpsException("Azure DevOps returned malformed response JSON.");
        }
    }

    private async Task<string> GetTextAsync(Uri uri, int maxBytes, CancellationToken cancellationToken)
    {
        using var response = await SendGetAsync(uri, cancellationToken);
        EnsureSuccess(response);
        var bytes = await ReadBytesBoundedAsync(response, maxBytes + 1, cancellationToken);
        if (bytes.Length > maxBytes)
        {
            throw new AzureDevOpsException("Azure DevOps response exceeded the configured size limit.");
        }

        return Encoding.UTF8.GetString(bytes);
    }

    private async Task<HttpResponseMessage> SendGetAsync(Uri uri, CancellationToken cancellationToken)
    {
        try
        {
            return await HttpRetry.SendGetAsync(
                _httpClient,
                () => new HttpRequestMessage(HttpMethod.Get, uri),
                cancellationToken);
        }
        catch (HttpRequestException)
        {
            throw new AzureDevOpsException("Azure DevOps could not be reached after transient retries.");
        }
        catch (TaskCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            throw new AzureDevOpsException("The Azure DevOps request timed out.");
        }
    }

    private static async Task<byte[]> ReadBytesBoundedAsync(
        HttpResponseMessage response,
        int maxBytes,
        CancellationToken cancellationToken)
    {
        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken);
        using var output = new MemoryStream(Math.Min(maxBytes, 16_384));
        var buffer = new byte[8192];
        while (output.Length < maxBytes)
        {
            var read = await stream.ReadAsync(
                buffer.AsMemory(0, Math.Min(buffer.Length, maxBytes - (int)output.Length)),
                cancellationToken);
            if (read == 0)
            {
                break;
            }

            output.Write(buffer, 0, read);
        }

        return output.ToArray();
    }

    private Uri ApiUri(string relativePath)
    {
        if (relativePath.Contains("api-version=", StringComparison.Ordinal))
        {
            return new Uri($"{_projectPath}/_apis/{relativePath}");
        }

        return new Uri(
            $"{_projectPath}/_apis/{relativePath}{(relativePath.Contains('?') ? "&" : "?")}api-version={ApiVersion}");
    }

    private static string CommitQuery(string commitId) =>
        $"versionDescriptor.version={Uri.EscapeDataString(commitId)}&versionDescriptor.versionType=commit";

    private static string ConvertAttachmentId(JsonElement id) => id.ValueKind switch
    {
        JsonValueKind.String => id.GetString() ?? string.Empty,
        JsonValueKind.Number => id.GetRawText(),
        _ => string.Empty
    };

    private static void EnsureSuccess(HttpResponseMessage response)
    {
        if (response.IsSuccessStatusCode)
        {
            return;
        }

        var statusCode = (int)response.StatusCode;
        var message = response.StatusCode switch
        {
            System.Net.HttpStatusCode.Unauthorized => "Azure DevOps authentication failed (HTTP 401); check the PAT and its scopes.",
            System.Net.HttpStatusCode.Forbidden => "Azure DevOps access was denied (HTTP 403); check project permissions and PAT scopes.",
            System.Net.HttpStatusCode.NotFound => "The requested Azure DevOps build, test, repository, or attachment was not found.",
            _ => $"Azure DevOps request failed with HTTP {statusCode}."
        };
        throw new AzureDevOpsException(message, statusCode);
    }

    private static PipelineRun MapBuild(BuildDto dto) => new(
        dto.Id,
        dto.Definition?.Name ?? dto.BuildNumber ?? $"Build {dto.Id}",
        dto.Status ?? "unknown",
        dto.Result ?? "unknown",
        dto.FinishTime,
        dto.SourceVersion ?? string.Empty,
        dto.Repository is null
            ? null
            : new RepositoryInfo(
                dto.Repository.Id ?? string.Empty,
                dto.Repository.Name ?? string.Empty,
                dto.Repository.Type ?? string.Empty,
                dto.Repository.Url ?? string.Empty),
        dto.Links?.Web?.Href ?? dto.Url ?? string.Empty);

    private static TestRun MapTestRun(TestRunDto dto) => new(
        dto.Id,
        dto.Name ?? $"Test run {dto.Id}",
        dto.State ?? "unknown",
        dto.TotalTests,
        dto.Url ?? string.Empty);

    private TestCaseResult MapTestResult(TestResultDto dto, int runId) => new(
        dto.Id,
        runId,
        dto.TestCaseTitle ?? string.Empty,
        dto.AutomatedTestName ?? string.Empty,
        dto.AutomatedTestStorage ?? string.Empty,
        dto.Outcome ?? "unknown",
        dto.ErrorMessage ?? string.Empty,
        dto.StackTrace ?? string.Empty,
        dto.StartedDate,
        dto.Url ?? ApiUri($"test/Runs/{runId}/results/{dto.Id}").ToString(),
        dto.FailingSince?.Build is { } failingBuild
            ? new PriorFailureInfo(failingBuild.Id, failingBuild.Number ?? string.Empty, dto.FailingSince.Date)
            : null);

    private sealed class BuildDto
    {
        public int Id { get; set; }
        public string? BuildNumber { get; set; }
        public string? Status { get; set; }
        public string? Result { get; set; }
        public DateTimeOffset? FinishTime { get; set; }
        public string? SourceVersion { get; set; }
        public string? Url { get; set; }
        public DefinitionDto? Definition { get; set; }
        public RepositoryDto? Repository { get; set; }
        [JsonPropertyName("_links")]
        public LinksDto? Links { get; set; }
    }

    private sealed class DefinitionDto { public string? Name { get; set; } }
    private sealed class RepositoryDto { public string? Id { get; set; } public string? Name { get; set; } public string? Type { get; set; } public string? Url { get; set; } }
    private sealed class LinksDto { public LinkDto? Web { get; set; } }
    private sealed class LinkDto { public string? Href { get; set; } }
    private sealed class TestRunDto { public int Id { get; set; } public string? Name { get; set; } public string? State { get; set; } public int? TotalTests { get; set; } public string? Url { get; set; } }
    private sealed class TestResultDto
    {
        public int Id { get; set; }
        public string? TestCaseTitle { get; set; }
        public string? AutomatedTestName { get; set; }
        public string? AutomatedTestStorage { get; set; }
        public string? Outcome { get; set; }
        public string? ErrorMessage { get; set; }
        public string? StackTrace { get; set; }
        public DateTimeOffset? StartedDate { get; set; }
        public string? Url { get; set; }
        public FailingSinceDto? FailingSince { get; set; }
    }
    private sealed class FailingSinceDto
    {
        public DateTimeOffset? Date { get; set; }
        public FailingBuildDto? Build { get; set; }
    }
    private sealed class FailingBuildDto { public int Id { get; set; } public string? Number { get; set; } }
    private sealed class AttachmentDto
    {
        public JsonElement Id { get; set; }
        public string? Name { get; set; }
        public string? FileName { get; set; }
        public string? Url { get; set; }
        public long? Size { get; set; }
        public DateTimeOffset? CreatedDate { get; set; }
    }
    private sealed class CommitDto
    {
        public string? CommitId { get; set; }
        public CommitPersonDto? Committer { get; set; }
    }
    private sealed class CommitPersonDto { public DateTimeOffset? Date { get; set; } }
    private sealed class GitItemDto
    {
        public string? Path { get; set; }
        public bool IsFolder { get; set; }
        public string? Url { get; set; }
        public ContentMetadataDto? ContentMetadata { get; set; }
    }
    private sealed class ContentMetadataDto { public bool IsBinary { get; set; } }
}
