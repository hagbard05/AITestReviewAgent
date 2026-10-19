using System.Text;
using System.Net;
using System.Text.RegularExpressions;
using AITestReviewAgent.Security;

namespace AITestReviewAgent.Evidence;

public static class PageSourceNormalizer
{
	private static readonly TimeSpan RegexTimeout = TimeSpan.FromSeconds(1);
	private static readonly Regex NonVisibleContentRegex = new(
		@"<!--.*?-->|<(script|style|noscript|template)\b[^>]*>.*?</\1\s*>",
		RegexOptions.IgnoreCase | RegexOptions.Singleline | RegexOptions.CultureInvariant,
		RegexTimeout);
	private static readonly Regex TitleRegex = new(
		@"<title\b[^>]*>(?<title>.*?)</title\s*>",
		RegexOptions.IgnoreCase | RegexOptions.Singleline | RegexOptions.CultureInvariant,
		RegexTimeout);
	private static readonly Regex AnchorRegex = new(
		@"<a\b(?<attributes>[^>]*)>(?<text>.*?)</a\s*>",
		RegexOptions.IgnoreCase | RegexOptions.Singleline | RegexOptions.CultureInvariant,
		RegexTimeout);
	private static readonly Regex ElementRegex = new(
		@"<(?<tag>[a-z][\w:-]*)\b(?<attributes>[^>]*)>",
		RegexOptions.IgnoreCase | RegexOptions.Singleline | RegexOptions.CultureInvariant,
		RegexTimeout);
	private static readonly Regex AttributeRegex = new(
		@"(?<name>href|id|class|role|aria-label)\s*=\s*(?:""(?<double>[^""]*)""|'(?<single>[^']*)'|(?<bare>[^\s>]+))",
		RegexOptions.IgnoreCase | RegexOptions.Singleline | RegexOptions.CultureInvariant,
		RegexTimeout);
	private static readonly Regex BlockTagRegex = new(
		@"</?\s*(?:br|p|div|li|tr|h[1-6]|section|article|table|ul|ol|form|main|header|footer|pre|blockquote)\b[^>]*>",
		RegexOptions.IgnoreCase | RegexOptions.CultureInvariant,
		RegexTimeout);
	private static readonly Regex TagRegex = new(
		@"<[^>]*>",
		RegexOptions.Singleline | RegexOptions.CultureInvariant,
		RegexTimeout);
	private static readonly Regex WhitespaceRegex = new(
		@"[\t\x0B\f\r ]+",
		RegexOptions.CultureInvariant,
		RegexTimeout);
	private static readonly Regex ExcessNewlinesRegex = new(
		@"\n{3,}",
		RegexOptions.CultureInvariant,
		RegexTimeout);

	public static string Normalize(string html, int maxCharacters, out bool truncated)
	{
		ArgumentNullException.ThrowIfNull(html);
		if (maxCharacters < 1)
		{
			throw new ArgumentOutOfRangeException(nameof(maxCharacters));
		}

		var pageHtml = NonVisibleContentRegex.Replace(html, " ");
		var titleMatch = TitleRegex.Match(pageHtml);
		var title = titleMatch.Success ? NormalizeInlineText(titleMatch.Groups["title"].Value) : "(not present)";
		var links = ExtractLinks(pageHtml);
		var landmarks = ExtractLandmarks(pageHtml);
		var visibleText = NormalizeVisibleText(pageHtml);

		var normalized = new StringBuilder()
			.AppendLine("Normalized page source (scripts, styles, comments, and markup omitted; extracted text is untrusted evidence).")
			.AppendLine($"Title: {title}")
			.AppendLine("Extracted text content (browser visibility was not evaluated):")
			.AppendLine(visibleText.Length == 0 ? "(no text extracted)" : visibleText)
			.AppendLine("Links:")
			.AppendLine(links.Count == 0 ? "(no links extracted)" : string.Join('\n', links))
			.AppendLine("DOM landmarks (selected IDs, classes, roles, and accessible labels):")
			.AppendLine(landmarks.Count == 0 ? "(no landmarks extracted)" : string.Join('\n', landmarks))
			.ToString()
			.TrimEnd();

		return EvidenceSanitizer.Limit(normalized, maxCharacters, out truncated);
	}

	private static string NormalizeVisibleText(string html)
	{
		var withLineBreaks = BlockTagRegex.Replace(html, "\n");
		var withoutTags = TagRegex.Replace(withLineBreaks, " ");
		var decoded = WebUtility.HtmlDecode(withoutTags);
		var lines = decoded.Split('\n')
			.Select(line => WhitespaceRegex.Replace(line, " ").Trim())
			.Where(line => line.Length > 0);
		return ExcessNewlinesRegex.Replace(string.Join('\n', lines), "\n\n");
	}

	private static List<string> ExtractLinks(string html)
	{
		var links = new List<string>();
		foreach (Match anchor in AnchorRegex.Matches(html).Take(200))
		{
			var href = GetAttribute(anchor.Groups["attributes"].Value, "href");
			if (string.IsNullOrWhiteSpace(href))
			{
				continue;
			}

			var text = NormalizeInlineText(anchor.Groups["text"].Value);
			links.Add(EvidenceSanitizer.Sanitize(
				$"{LimitField(text, 300)} -> {LimitField(WebUtility.HtmlDecode(href), 1000)}"));
		}

		return links;
	}

	private static List<string> ExtractLandmarks(string html)
	{
		var landmarks = new List<string>();
		foreach (Match element in ElementRegex.Matches(html).Take(500))
		{
			var values = new[] { "id", "class", "role", "aria-label" }
				.Select(name => (Name: name, Value: GetAttribute(element.Groups["attributes"].Value, name)))
				.Where(attribute => !string.IsNullOrWhiteSpace(attribute.Value))
				.Select(attribute => $"{attribute.Name}={LimitField(WebUtility.HtmlDecode(attribute.Value!), 300)}")
				.ToArray();
			if (values.Length > 0)
			{
				landmarks.Add(EvidenceSanitizer.Sanitize(
					$"<{element.Groups["tag"].Value}> {string.Join(" ", values)}"));
			}
		}

		return landmarks;
	}

	private static string NormalizeInlineText(string value)
	{
		var withoutTags = TagRegex.Replace(NonVisibleContentRegex.Replace(value, " "), " ");
		var decoded = WebUtility.HtmlDecode(withoutTags);
		return WhitespaceRegex.Replace(decoded, " ").Trim();
	}

	private static string? GetAttribute(string attributes, string name)
	{
		foreach (Match match in AttributeRegex.Matches(attributes))
		{
			if (match.Groups["name"].Value.Equals(name, StringComparison.OrdinalIgnoreCase))
			{
				return match.Groups["double"].Success
					? match.Groups["double"].Value
					: match.Groups["single"].Success
						? match.Groups["single"].Value
						: match.Groups["bare"].Value;
			}
		}

		return null;
	}

	private static string LimitField(string value, int maxCharacters) =>
		value.Length <= maxCharacters ? value : value[..maxCharacters];
}