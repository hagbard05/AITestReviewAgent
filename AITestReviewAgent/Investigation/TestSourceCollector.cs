using System.Text.RegularExpressions;
using AITestReviewAgent.Configuration;
using AITestReviewAgent.Domain;
using AITestReviewAgent.Evidence;
using AITestReviewAgent.Security;
using AITestReviewAgent.SourceControl;

namespace AITestReviewAgent.Investigation;

public sealed class TestSourceCollector(
    IEnumerable<ISourceRepositoryClient> sourceClients,
    AzureDevOpsOptions options,
    EvidenceNormalizer normalizer)
{
    private static readonly Regex MethodDeclarationRegex = new(
        @"(?m)^\s*(?:(?:public|private|protected|internal|static|async|virtual|override|sealed|new|partial|extern|unsafe)\s+)*(?:[\w.<>,?\[\]]+\s+)+(?<name>[A-Za-z_]\w*)\s*(?:<[^>]+>)?\s*\(",
        RegexOptions.CultureInvariant,
        TimeSpan.FromMilliseconds(250));
    private static readonly Regex TypeDeclarationRegex = new(
        @"\b(?:class|record|struct|interface)\s+(?<name>[A-Z]\w*)\b",
        RegexOptions.CultureInvariant,
        TimeSpan.FromMilliseconds(250));

    private static readonly HashSet<string> SupportedExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".cs", ".csx", ".vb", ".fs", ".razor", ".feature", ".json", ".config", ".xml",
        ".yaml", ".yml", ".runsettings", ".props", ".targets", ".csproj", ".sln", ".slnx",
        ".editorconfig"
    };

    public async Task<(TestSourceSnapshot Snapshot, IReadOnlyList<EvidenceItem> Evidence)> CollectAsync(
        PipelineRun build,
        TestCaseResult test,
        CancellationToken cancellationToken)
    {
        var repo = build.Repository;
        if (repo is null || !repo.Type.Contains("git", StringComparison.OrdinalIgnoreCase))
        {
            return Missing(build, "The build does not identify an accessible Git repository.");
        }

        var sourceClient = sourceClients.FirstOrDefault(client => client.Supports(repo.Type));
        if (sourceClient is null)
        {
            return Missing(
                build,
                $"No source provider is registered for repository type '{repo.Type}' and URL '{repo.Url}'.",
                repo.Type);
        }

        if (!Regex.IsMatch(build.SourceVersion, @"\A[0-9a-fA-F]{40}([0-9a-fA-F]{24})?\z"))
        {
            return Missing(build, "The build does not provide a full Git commit SHA; exact source revision cannot be verified.");
        }

        RepositoryCommit? commit;
        try
        {
            commit = await sourceClient.GetVerifiedCommitAsync(repo, build.SourceVersion, cancellationToken);
        }
        catch (SourceRepositoryException exception)
        {
            return Missing(build, exception.Message, sourceClient.ProviderName);
        }

        if (commit is null
            || !string.Equals(commit.CommitId, build.SourceVersion, StringComparison.OrdinalIgnoreCase))
        {
            return Missing(
                build,
                $"{sourceClient.ProviderName} did not verify the build's exact source commit '{build.SourceVersion}'.",
                sourceClient.ProviderName);
        }

        var verifiedCommit = commit.CommitId;
        IReadOnlyList<RepositoryItem> tree;
        try
        {
            tree = await sourceClient.GetRepositoryItemsAsync(repo, commit, cancellationToken);
        }
        catch (SourceRepositoryException exception)
        {
            return Missing(
                build,
                $"{sourceClient.ProviderName} could not list repository files at the build commit: {exception.Message}",
                sourceClient.ProviderName);
        }

        var treeTruncated = tree.Any(item => item.IsTreeTruncationMarker);
        var allCandidates = tree
            .Where(item => !item.IsTreeTruncationMarker)
            .Where(item => !item.IsFolder && !item.IsBinary && SupportedExtensions.Contains(Path.GetExtension(item.Path)))
            .Where(item => !HasIgnoredDirectory(item.Path))
            .OrderByDescending(item => IsTestPath(item.Path))
            .ThenBy(item => item.Path, StringComparer.OrdinalIgnoreCase)
            .ToArray();
        var sourceIndexTruncated = allCandidates.Length > options.MaxSourceFiles;
        var candidates = allCandidates
            .Take(options.MaxSourceFiles)
            .ToArray();

        var collected = new List<(RepositoryItem Item, string Content)>();
        var truncatedPaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var remainingCharacters = options.MaxSourceCharacters;
        var missingFiles = new List<(string Path, string Error)>();
        foreach (var item in candidates)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (remainingCharacters <= 0)
            {
                break;
            }

            var byteLimit = Math.Min(2_000_000, Math.Max(256_000, remainingCharacters * 4 + 4096));
            string? content;
            try
            {
                content = await sourceClient.GetRepositoryFileAsync(
                    repo, item.Path, verifiedCommit, byteLimit, cancellationToken);
            }
            catch (SourceRepositoryException exception)
            {
                missingFiles.Add((item.Path, exception.Message));
                continue;
            }

            if (content is null)
            {
                missingFiles.Add((item.Path, $"{sourceClient.ProviderName} did not return the file at the verified commit."));
                continue;
            }

            if (content.Length > remainingCharacters)
            {
                truncatedPaths.Add(item.Path);
                content = content[..remainingCharacters];
            }

            collected.Add((item, content));
            remainingCharacters -= content.Length;
        }

        var methodNames = GetMethodNames(test);
        var matchingFiles = collected
            .Where(file => methodNames.Any(name => HasMethodDeclaration(file.Content, name)))
            .ToArray();
        if (matchingFiles.Length > 1)
        {
            var testPathMatches = matchingFiles.Where(file => IsTestPath(file.Item.Path)).ToArray();
            if (testPathMatches.Length == 1)
            {
                matchingFiles = testPathMatches;
            }
        }

        if (matchingFiles.Length != 1)
        {
            var reason = matchingFiles.Length == 0
                ? "The exact test method was not found in the bounded source snapshot."
                : "The test method matched multiple source files and could not be identified unambiguously.";
            var missing = new[] { reason }.Concat(missingFiles.Select(file =>
                $"Could not retrieve repository file '{file.Path}': {file.Error}")).ToArray();
            return (
                new TestSourceSnapshot(
                    true, false, false, verifiedCommit, repo.Id,
                    CreateProvenance(sourceClient, repo, verifiedCommit), null, Array.Empty<SourceFileSnapshot>(), missing,
                    new[] { $"Source scan was limited to {candidates.Length} files and {options.MaxSourceCharacters} characters." }),
                new[] { normalizer.ForCommit(verifiedCommit, repo.Id, repo.Name, commit.Timestamp, sourceClient.ProviderName) });
        }

        var testFile = matchingFiles[0];
        var relatedFiles = FindReferencedFiles(testFile, collected)
            .Concat(collected.Where(file => IsRelatedConfigurationOrData(file.Item.Path, testFile.Item.Path)))
            .Prepend(testFile)
            .DistinctBy(file => file.Item.Path, StringComparer.OrdinalIgnoreCase)
            .ToArray();
        var sourceFiles = new List<SourceFileSnapshot>();
        var evidence = new List<EvidenceItem>
        {
            normalizer.ForCommit(verifiedCommit, repo.Id, repo.Name, commit.Timestamp, sourceClient.ProviderName)
        };

        foreach (var file in relatedFiles)
        {
            var pinnedUrl = sourceClient.CreatePinnedSourceUrl(repo, file.Item.Path, verifiedCommit);
            var sourceEvidence = normalizer.ForSource(
                file.Item.Path, file.Content, verifiedCommit, pinnedUrl, out _, commit.Timestamp, sourceClient.ProviderName);
            sourceFiles.Add(new SourceFileSnapshot(
                sourceEvidence.Path ?? file.Item.Path,
                file.Content,
                sourceEvidence.Id,
                verifiedCommit,
                sourceEvidence.Url));
            evidence.Add(sourceEvidence);
        }

        var limitations = new List<string>();
        if (treeTruncated)
        {
            limitations.Add("The repository tree exceeded the configured item limit; source files outside the returned portion were not searched.");
        }

        var safeTestSourcePath = EvidenceSanitizer.Sanitize(testFile.Item.Path);
        var testSourceEvidence = evidence.First(item =>
            item.Type == EvidenceType.SourceCode
            && string.Equals(item.Path, safeTestSourcePath, StringComparison.OrdinalIgnoreCase));
        var testSourceComplete = testSourceEvidence.Status == EvidenceCollectionStatus.Available
            && !truncatedPaths.Contains(testFile.Item.Path);
        var sourceLimitStoppedScan = remainingCharacters <= 0 && collected.Count < candidates.Length;
        var relevantSourcesComplete = testSourceComplete
            && !treeTruncated
            && !sourceIndexTruncated
            && !sourceLimitStoppedScan
            && missingFiles.Count == 0
            && relatedFiles.All(file =>
                !truncatedPaths.Contains(file.Item.Path)
                && evidence.Any(item =>
                    item.Type == EvidenceType.SourceCode
                    && string.Equals(item.Path, EvidenceSanitizer.Sanitize(file.Item.Path), StringComparison.OrdinalIgnoreCase)
                    && item.Status == EvidenceCollectionStatus.Available));
        if (!testSourceComplete)
        {
            limitations.Add("The complete test source exceeded a retrieval or evidence size limit and was not fully available to the investigator.");
        }

        if (!relevantSourcesComplete && testSourceComplete)
        {
            limitations.Add("One or more referenced source files were truncated or the bounded repository tree was incomplete.");
        }

        if (sourceIndexTruncated || sourceLimitStoppedScan)
        {
            limitations.Add("Repository source retrieval reached a configured file or character limit; some helpers or configuration may be absent.");
        }

        if (missingFiles.Count > 0)
        {
            limitations.Add($"Could not retrieve {missingFiles.Count} {sourceClient.ProviderName} file(s) at the build commit.");
        }

        limitations.Add("Helper and fixture discovery is static and bounded; generated, reflective, or external dependencies may not be included.");
        var missingDependencies = GetUnresolvedReferencedTypes(testFile.Content, collected)
            .Concat(missingFiles.Select(path =>
                $"Could not retrieve repository file '{path.Path}' at the build commit: {path.Error}"))
            .ToArray();
        return (
            new TestSourceSnapshot(
                true,
                testSourceComplete,
                relevantSourcesComplete,
                verifiedCommit,
                repo.Id,
                CreateProvenance(sourceClient, repo, verifiedCommit),
                testSourceEvidence.Path,
                sourceFiles,
                missingDependencies,
                limitations),
            evidence);
    }

    private (TestSourceSnapshot Snapshot, IReadOnlyList<EvidenceItem> Evidence) Missing(
        PipelineRun build,
        string reason,
        string? providerName = null)
    {
        var repository = build.Repository;
        var provenance = repository is null
            ? null
            : new SourceRepositoryMetadata(
                providerName ?? repository.Type,
                repository.Id,
                repository.Url,
                build.SourceVersion);
        var snapshot = new TestSourceSnapshot(
            false, false, false, build.SourceVersion, repository?.Id, provenance,
            null, Array.Empty<SourceFileSnapshot>(), new[] { reason }, new[] { reason });
        return (snapshot, new[]
        {
            normalizer.Unavailable("source-revision", EvidenceType.RepositoryMetadata,
                $"{providerName ?? repository?.Type ?? "Git"} source", reason)
        });
    }

    private static SourceRepositoryMetadata CreateProvenance(
        ISourceRepositoryClient sourceClient,
        RepositoryInfo repository,
        string revision) => new(sourceClient.ProviderName, repository.Id, repository.Url, revision);

    private static IEnumerable<string> GetMethodNames(TestCaseResult test)
    {
        foreach (var testName in new[] { test.AutomatedTestName, test.TestCaseTitle })
        {
            var name = testName.Split('(')[0].TrimEnd('.');
            var leaf = name.Split('.').LastOrDefault();
            if (!string.IsNullOrWhiteSpace(leaf) && Regex.IsMatch(leaf, @"\A[A-Za-z_]\w*\z"))
            {
                yield return leaf;
            }
        }
    }

    private static bool HasMethodDeclaration(string content, string methodName)
    {
        var declaration = $@"(?m)^\s*(?:(?:public|private|protected|internal|static|async|virtual|override|sealed|new|partial)\s+)*(?:[\w.<>,?\[\]]+\s+)+{Regex.Escape(methodName)}\s*(?:<[^>]+>)?\s*\(";
        return Regex.IsMatch(content, declaration);
    }

    private static IEnumerable<(RepositoryItem Item, string Content)> FindReferencedFiles(
        (RepositoryItem Item, string Content) testFile,
        IReadOnlyList<(RepositoryItem Item, string Content)> files)
    {
        var resolved = new Dictionary<string, (RepositoryItem Item, string Content)>(StringComparer.OrdinalIgnoreCase)
        {
            [testFile.Item.Path] = testFile
        };

        for (var depth = 0; depth < 3; depth++)
        {
            var typeNames = resolved.Values
                .SelectMany(file => GetReferencedTypes(file.Content))
                .ToHashSet(StringComparer.Ordinal);
            var methodNames = resolved.Values
                .SelectMany(file => GetInvokedMethodNames(file.Content))
                .ToHashSet(StringComparer.Ordinal);

            foreach (var file in files)
            {
                if (resolved.ContainsKey(file.Item.Path))
                {
                    continue;
                }

                var declaredTypes = GetDeclarationNames(TypeDeclarationRegex, file.Content);
                var declaredMethods = GetDeclarationNames(MethodDeclarationRegex, file.Content);
                var matchesType = declaredTypes.Any(typeNames.Contains);
                var matchesMethod = declaredMethods.Any(methodNames.Contains);
                if (matchesType || matchesMethod)
                {
                    resolved[file.Item.Path] = file;
                }
            }
        }

        return resolved.Values;
    }

    private static IEnumerable<string> GetReferencedTypes(string content) =>
        Regex.Matches(content, @"\b(?:new|IClassFixture|CollectionDefinition|ClassFixture)\s*<*\s*([A-Z]\w*)")
            .Select(match => match.Groups[1].Value);

    private static IEnumerable<string> GetInvokedMethodNames(string content) =>
        Regex.Matches(content, @"\b([A-Za-z_]\w*)\s*(?:<[^>]+>)?\s*\(")
            .Select(match => match.Groups[1].Value);

    private static IReadOnlyList<string> GetUnresolvedReferencedTypes(
        string content,
        IReadOnlyList<(RepositoryItem Item, string Content)> files)
    {
        var types = GetReferencedTypes(content)
            .Distinct(StringComparer.Ordinal);
        var declaredTypes = files
            .SelectMany(file => GetDeclarationNames(TypeDeclarationRegex, file.Content))
            .ToHashSet(StringComparer.Ordinal);
        return types
            .Where(type => !declaredTypes.Contains(type))
            .Select(type => $"Referenced type '{type}' was not found in the retrieved repository source; it may be external or inaccessible.")
            .ToArray();
    }

    private static IEnumerable<string> GetDeclarationNames(Regex pattern, string content) =>
        pattern.Matches(content).Select(match => match.Groups["name"].Value);

    private static bool IsTestPath(string path) =>
        Regex.IsMatch(path, @"(^|[/\\])(test|tests|spec|specs)([/\\]|$)", RegexOptions.IgnoreCase);

    private static bool IsRelatedConfigurationOrData(string path, string testPath)
    {
        var normalizedPath = path.Replace('\\', '/');
        var normalizedTestPath = testPath.Replace('\\', '/');
        var testSeparator = normalizedTestPath.LastIndexOf('/');
        var testDirectory = testSeparator < 0 ? string.Empty : normalizedTestPath[..testSeparator];
        var pathSeparator = normalizedPath.LastIndexOf('/');
        var parent = pathSeparator < 0 ? string.Empty : normalizedPath[..pathSeparator];
        var fileName = Path.GetFileName(normalizedPath);
        var extension = Path.GetExtension(normalizedPath);
        var underTestDirectory = testDirectory.Length > 0
            && normalizedPath.StartsWith(testDirectory.TrimEnd('/') + "/", StringComparison.OrdinalIgnoreCase);
        var configExtension = extension.Equals(".json", StringComparison.OrdinalIgnoreCase)
            || extension.Equals(".config", StringComparison.OrdinalIgnoreCase)
            || extension.Equals(".xml", StringComparison.OrdinalIgnoreCase)
            || extension.Equals(".yaml", StringComparison.OrdinalIgnoreCase)
            || extension.Equals(".yml", StringComparison.OrdinalIgnoreCase)
            || extension.Equals(".runsettings", StringComparison.OrdinalIgnoreCase)
            || extension.Equals(".csproj", StringComparison.OrdinalIgnoreCase)
            || extension.Equals(".props", StringComparison.OrdinalIgnoreCase)
            || extension.Equals(".targets", StringComparison.OrdinalIgnoreCase);
        var ancestorProjectConfig = configExtension
            && (fileName.StartsWith("Directory.Build.", StringComparison.OrdinalIgnoreCase)
                || fileName.Equals("global.json", StringComparison.OrdinalIgnoreCase)
                || fileName.Contains("appsettings", StringComparison.OrdinalIgnoreCase)
                || fileName.EndsWith(".csproj", StringComparison.OrdinalIgnoreCase)
                || parent.Length == 0
                || normalizedTestPath.StartsWith(parent.TrimEnd('/') + "/", StringComparison.OrdinalIgnoreCase));
        return configExtension && underTestDirectory || ancestorProjectConfig;
    }

    private static bool HasIgnoredDirectory(string path) =>
        Regex.IsMatch(path, @"(^|[/\\])(bin|obj|packages|node_modules|\.git)([/\\]|$)", RegexOptions.IgnoreCase);
}
