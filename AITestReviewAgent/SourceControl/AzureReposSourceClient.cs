using AITestReviewAgent.Configuration;
using AITestReviewAgent.Domain;

namespace AITestReviewAgent.SourceControl;

public sealed class AzureReposSourceClient(
	IAzureDevOpsClient azureDevOps,
	AzureDevOpsOptions options) : ISourceRepositoryClient
{
	public string ProviderName => "Azure Repos Git";

	public bool Supports(string repositoryType) =>
		repositoryType.Equals("TfsGit", StringComparison.OrdinalIgnoreCase)
		|| repositoryType.Equals("AzureReposGit", StringComparison.OrdinalIgnoreCase);

	public async Task<RepositoryCommit?> GetVerifiedCommitAsync(
		RepositoryInfo repository,
		string commitId,
		CancellationToken cancellationToken)
	{
		ValidateRepository(repository);
		try
		{
			return await azureDevOps.GetVerifiedCommitAsync(repository.Id, commitId, cancellationToken);
		}
		catch (AzureDevOps.AzureDevOpsException exception)
		{
			throw new SourceRepositoryException(
				$"Azure Repos could not verify commit '{commitId}': {exception.Message}");
		}
	}

	public async Task<IReadOnlyList<RepositoryItem>> GetRepositoryItemsAsync(
		RepositoryInfo repository,
		RepositoryCommit commit,
		CancellationToken cancellationToken)
	{
		ValidateRepository(repository);
		try
		{
			return await azureDevOps.GetRepositoryItemsAsync(repository.Id, commit.CommitId, cancellationToken);
		}
		catch (AzureDevOps.AzureDevOpsException exception)
		{
			throw new SourceRepositoryException(
				$"Azure Repos could not list files at commit '{commit.CommitId}': {exception.Message}");
		}
	}

	public async Task<string?> GetRepositoryFileAsync(
		RepositoryInfo repository,
		string path,
		string commitId,
		int maxBytes,
		CancellationToken cancellationToken)
	{
		ValidateRepository(repository);
		try
		{
			return await azureDevOps.GetRepositoryFileAsync(
				repository.Id, path, commitId, maxBytes, cancellationToken);
		}
		catch (AzureDevOps.AzureDevOpsException exception)
		{
			throw new SourceRepositoryException(
				$"Azure Repos could not retrieve '{path}' at commit '{commitId}': {exception.Message}");
		}
	}

	public string CreatePinnedSourceUrl(RepositoryInfo repository, string path, string commitId)
	{
		ValidateRepository(repository);
		return $"{options.Organization.TrimEnd('/')}/{Uri.EscapeDataString(options.Project)}"
			+ $"/_apis/git/repositories/{Uri.EscapeDataString(repository.Id)}/items"
			+ $"?path={Uri.EscapeDataString(path)}&versionDescriptor.version={Uri.EscapeDataString(commitId)}"
			+ "&versionDescriptor.versionType=commit&api-version=7.1";
	}

	private static void ValidateRepository(RepositoryInfo repository)
	{
		if (!Uri.TryCreate(repository.Url, UriKind.Absolute, out var url)
			|| !(url.Host.Equals("dev.azure.com", StringComparison.OrdinalIgnoreCase)
				|| url.Host.EndsWith(".visualstudio.com", StringComparison.OrdinalIgnoreCase)))
		{
			throw new SourceRepositoryException(
				$"Build metadata identifies repository type '{repository.Type}' but URL '{repository.Url}' is not an Azure Repos URL.");
		}
	}
}