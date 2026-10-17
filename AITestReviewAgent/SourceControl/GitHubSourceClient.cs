using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using AITestReviewAgent.Configuration;
using AITestReviewAgent.Domain;
using AITestReviewAgent.Infrastructure;

namespace AITestReviewAgent.SourceControl;

public sealed class GitHubSourceClient : ISourceRepositoryClient
{
	private const string ApiBaseUrl = "https://api.github.com/";
	private readonly HttpClient _httpClient;
	private readonly GitHubOptions _options;

	public GitHubSourceClient(HttpClient httpClient, GitHubOptions options)
	{
		_httpClient = httpClient;
		_options = options;
		_httpClient.Timeout = TimeSpan.FromSeconds(45);
		_httpClient.DefaultRequestHeaders.UserAgent.ParseAdd("AITestReviewAgent/1.0");
		_httpClient.DefaultRequestHeaders.Accept.Add(
			new MediaTypeWithQualityHeaderValue("application/vnd.github+json"));
		_httpClient.DefaultRequestHeaders.Add("X-GitHub-Api-Version", "2022-11-28");
		if (!string.IsNullOrWhiteSpace(options.Token))
		{
			_httpClient.DefaultRequestHeaders.Authorization =
				new AuthenticationHeaderValue("Bearer", options.Token);
		}
	}

	public string ProviderName => "GitHub";

	public bool Supports(string repositoryType) =>
		repositoryType.Equals("GitHub", StringComparison.OrdinalIgnoreCase);

	public async Task<RepositoryCommit?> GetVerifiedCommitAsync(
		RepositoryInfo repository,
		string commitId,
		CancellationToken cancellationToken)
	{
		var repo = ParseRepository(repository);
		using var response = await SendGetAsync(
			new Uri(ApiBaseUrl + $"repos/{repo.Owner}/{repo.Name}/commits/{Uri.EscapeDataString(commitId)}"),
			cancellationToken);
		if (response.StatusCode == HttpStatusCode.NotFound)
		{
			return null;
		}

		EnsureSuccess(response, "verify commit");
		using var document = await ReadJsonAsync(response, 2_000_000, cancellationToken);
		var root = document.RootElement;
		var returnedSha = GetString(root, "sha");
		if (!string.Equals(returnedSha, commitId, StringComparison.OrdinalIgnoreCase))
		{
			return null;
		}

		DateTimeOffset? timestamp = null;
		if (root.TryGetProperty("commit", out var commit)
			&& commit.TryGetProperty("committer", out var committer)
			&& committer.TryGetProperty("date", out var date)
			&& date.TryGetDateTimeOffset(out var parsedDate))
		{
			timestamp = parsedDate;
		}

		var treeId = root.TryGetProperty("commit", out var commitData)
			&& commitData.TryGetProperty("tree", out var tree)
			? GetString(tree, "sha")
			: null;
		if (treeId is null || treeId.Length != 40 || treeId.Any(character => !Uri.IsHexDigit(character)))
		{
			throw new SourceRepositoryException(
				$"GitHub verified commit '{commitId}' but did not return a valid tree SHA; source files cannot be listed safely.");
		}

		return new RepositoryCommit(returnedSha!, timestamp, treeId);
	}

	public async Task<IReadOnlyList<RepositoryItem>> GetRepositoryItemsAsync(
		RepositoryInfo repository,
		RepositoryCommit commit,
		CancellationToken cancellationToken)
	{
		var repo = ParseRepository(repository);
		var treeId = commit.TreeId;
		if (treeId is null || treeId.Length != 40 || treeId.Any(character => !Uri.IsHexDigit(character)))
		{
			throw new SourceRepositoryException(
				$"GitHub commit '{commit.CommitId}' has no valid verified tree SHA.");
		}

		using var response = await SendGetAsync(
			new Uri(ApiBaseUrl + $"repos/{repo.Owner}/{repo.Name}/git/trees/{Uri.EscapeDataString(treeId)}?recursive=1"),
			cancellationToken);
		EnsureSuccess(response, "list source files");
		using var document = await ReadJsonAsync(response, 8_000_000, cancellationToken);
		var root = document.RootElement;
		if (!string.Equals(GetString(root, "sha"), treeId, StringComparison.OrdinalIgnoreCase))
		{
			throw new SourceRepositoryException(
				$"GitHub returned a repository tree that does not match the verified tree SHA for commit '{commit.CommitId}'.");
		}

		var items = new List<RepositoryItem>();
		if (root.TryGetProperty("tree", out var tree) && tree.ValueKind == JsonValueKind.Array)
		{
			foreach (var item in tree.EnumerateArray())
			{
				var path = GetString(item, "path");
				if (string.IsNullOrWhiteSpace(path))
				{
					continue;
				}

				var isTree = string.Equals(GetString(item, "type"), "tree", StringComparison.Ordinal);
				var isBlob = string.Equals(GetString(item, "type"), "blob", StringComparison.Ordinal);
				var isBinary = !isBlob || (item.TryGetProperty("size", out var size)
					&& size.TryGetInt64(out var byteCount)
					&& byteCount > 2_000_000);
				items.Add(new RepositoryItem(path, isTree, isBinary, CreatePinnedSourceUrl(repository, path, commit.CommitId)));
			}
		}

		if (root.TryGetProperty("truncated", out var truncated) && truncated.ValueKind == JsonValueKind.True)
		{
			items.Add(new RepositoryItem(
				"[GitHub tree truncated by API limit]", false, true, null, IsTreeTruncationMarker: true));
		}

		return items;
	}

	public async Task<string?> GetRepositoryFileAsync(
		RepositoryInfo repository,
		string path,
		string commitId,
		int maxBytes,
		CancellationToken cancellationToken)
	{
		var repo = ParseRepository(repository);
		var encodedPath = string.Join('/', path.Split('/').Select(Uri.EscapeDataString));
		var uri = new Uri(ApiBaseUrl
			+ $"repos/{repo.Owner}/{repo.Name}/contents/{encodedPath}?ref={Uri.EscapeDataString(commitId)}");
		using var response = await SendGetAsync(uri, cancellationToken);
		if (response.StatusCode == HttpStatusCode.NotFound)
		{
			return null;
		}

		EnsureSuccess(response, $"retrieve '{path}' at commit '{commitId}'");
		using var document = await ReadJsonAsync(response, 4_000_000, cancellationToken);
		var root = document.RootElement;
		if (!string.Equals(GetString(root, "encoding"), "base64", StringComparison.OrdinalIgnoreCase)
			|| !root.TryGetProperty("content", out var contentElement)
			|| contentElement.ValueKind != JsonValueKind.String)
		{
			throw new SourceRepositoryException(
				$"GitHub did not return base64 file content for '{path}' at commit '{commitId}'." +
				" The file may exceed the Contents API limit or use an unsupported content encoding.");
		}

		byte[] bytes;
		try
		{
			bytes = Convert.FromBase64String(contentElement.GetString() ?? string.Empty);
		}
		catch (FormatException)
		{
			throw new SourceRepositoryException($"GitHub returned malformed base64 content for '{path}'.");
		}

		if (bytes.Length > maxBytes)
		{
			throw new SourceRepositoryException($"GitHub file '{path}' exceeded the configured source retrieval size limit.");
		}

		return Encoding.UTF8.GetString(bytes);
	}

	public string CreatePinnedSourceUrl(RepositoryInfo repository, string path, string commitId)
	{
		var repo = ParseRepository(repository);
		var encodedPath = string.Join('/', path.Split('/').Select(Uri.EscapeDataString));
		return $"https://github.com/{repo.Owner}/{repo.Name}/blob/{Uri.EscapeDataString(commitId)}/{encodedPath}";
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
			throw new SourceRepositoryException("GitHub could not be reached after transient retries.");
		}
		catch (TaskCanceledException) when (!cancellationToken.IsCancellationRequested)
		{
			throw new SourceRepositoryException("The GitHub source request timed out.");
		}
	}

	private static async Task<JsonDocument> ReadJsonAsync(
		HttpResponseMessage response,
		int maxBytes,
		CancellationToken cancellationToken)
	{
		await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken);
		using var output = new MemoryStream();
		var buffer = new byte[8192];
		while (output.Length <= maxBytes)
		{
			var read = await stream.ReadAsync(
				buffer.AsMemory(0, Math.Min(buffer.Length, maxBytes + 1 - (int)output.Length)),
				cancellationToken);
			if (read == 0)
			{
				break;
			}

			output.Write(buffer, 0, read);
		}

		if (output.Length > maxBytes)
		{
			throw new SourceRepositoryException("GitHub returned a response exceeding the configured size limit.");
		}

		try
		{
			return JsonDocument.Parse(output.ToArray());
		}
		catch (JsonException)
		{
			throw new SourceRepositoryException("GitHub returned malformed JSON for a source repository request.");
		}
	}

	private static void EnsureSuccess(HttpResponseMessage response, string operation)
	{
		if (response.IsSuccessStatusCode)
		{
			return;
		}

		var message = response.StatusCode switch
		{
			HttpStatusCode.Unauthorized => "GitHub authentication failed; check the optional GitHub token and its repository access.",
			HttpStatusCode.Forbidden => "GitHub denied access or rate-limited the request; check token permissions and rate limits.",
			HttpStatusCode.NotFound => "The GitHub repository or requested resource was not found; check repository URL, visibility, and access.",
			_ => $"GitHub returned HTTP {(int)response.StatusCode}."
		};
		throw new SourceRepositoryException($"GitHub could not {operation}: {message}");
	}

	private static (string Owner, string Name) ParseRepository(RepositoryInfo repository)
	{
		if (!repository.Type.Equals("GitHub", StringComparison.OrdinalIgnoreCase)
			|| !Uri.TryCreate(repository.Url, UriKind.Absolute, out var url)
			|| !url.Host.Equals("github.com", StringComparison.OrdinalIgnoreCase)
			|| !string.IsNullOrEmpty(url.UserInfo))
		{
			throw new SourceRepositoryException(
				$"Build metadata identifies repository type '{repository.Type}' but URL '{repository.Url}' is not a supported github.com repository URL.");
		}

		var segments = url.AbsolutePath.Split('/', StringSplitOptions.RemoveEmptyEntries);
		if (segments.Length != 2)
		{
			throw new SourceRepositoryException(
				$"GitHub repository URL '{repository.Url}' must identify exactly an owner and repository.");
		}

		var name = segments[1].EndsWith(".git", StringComparison.OrdinalIgnoreCase)
			? segments[1][..^4]
			: segments[1];
		return (Uri.EscapeDataString(Uri.UnescapeDataString(segments[0])),
			Uri.EscapeDataString(Uri.UnescapeDataString(name)));
	}

	private static string? GetString(JsonElement element, string propertyName) =>
		element.TryGetProperty(propertyName, out var value) && value.ValueKind == JsonValueKind.String
			? value.GetString()
			: null;
}