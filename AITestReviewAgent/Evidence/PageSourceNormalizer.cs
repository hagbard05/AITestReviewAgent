using System.Net;
using System.Net.Mime;
using System.Text;
using System.Text.RegularExpressions;
using AITestReviewAgent.Security;

namespace AITestReviewAgent.Evidence;

public static class PageSourceNormalizer
{
	private const int MaxInlineScriptCount = 12;
	private const int MaxInlineScriptCharacters = 5_000;
	private const int MaxScriptCharactersPerBlock = 2_000;
	private const int MaxCssRuleCount = 40;
	private const int MaxCssCharacters = 3_500;
	private static readonly TimeSpan RegexTimeout = TimeSpan.FromSeconds(1);
	private static readonly Regex NonVisibleContentRegex = new(
		@"<!--.*?-->|<(script|style|noscript|template)\b[^>]*>.*?</\1\s*>",
		RegexOptions.IgnoreCase | RegexOptions.Singleline | RegexOptions.CultureInvariant,
		RegexTimeout);
	private static readonly Regex ScriptBlockRegex = new(
		@"<script\b(?<attributes>[^>]*)>(?<code>.*?)</script\s*>",
		RegexOptions.IgnoreCase | RegexOptions.Singleline | RegexOptions.CultureInvariant,
		RegexTimeout);
	private static readonly Regex StyleBlockRegex = new(
		@"<style\b[^>]*>(?<css>.*?)</style\s*>",
		RegexOptions.IgnoreCase | RegexOptions.Singleline | RegexOptions.CultureInvariant,
		RegexTimeout);
	private static readonly Regex CssRuleRegex = new(
		@"(?<selector>[^{}]+)\{(?<declarations>[^{}]*)\}",
		RegexOptions.Singleline | RegexOptions.CultureInvariant,
		RegexTimeout);
	private static readonly Regex ImageElementRegex = new(
		@"<(picture|svg|object)\b[^>]*>.*?</\1\s*>|<(img|embed)\b[^>]*>",
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
		@"(?<name>href|id|class|role|aria-label|src|rel)\s*=\s*(?:""(?<double>[^""]*)""|'(?<single>[^']*)'|(?<bare>[^\s>]+))",
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

		var scripts = ExtractJavaScript(html);
		var styles = ExtractCssRules(html);
		var externalResources = ExtractExternalResources(html);
		var pageHtml = ImageElementRegex.Replace(NonVisibleContentRegex.Replace(html, " "), " ");
		var titleMatch = TitleRegex.Match(pageHtml);
		var title = titleMatch.Success ? NormalizeInlineText(titleMatch.Groups["title"].Value) : "(not present)";
		var links = ExtractLinks(pageHtml);
		var landmarks = ExtractLandmarks(pageHtml);
		var visibleText = NormalizeVisibleText(pageHtml);

		var normalized = new StringBuilder()
			.AppendLine("Normalized page source (markup, comments, and embedded image content omitted; bounded script and CSS excerpts are untrusted source evidence).")
			.AppendLine($"Title: {title}")
			.AppendLine("Extracted text content (browser visibility was not evaluated):")
			.AppendLine(visibleText.Length == 0 ? "(no text extracted)" : visibleText)
			.AppendLine("Links:")
			.AppendLine(links.Count == 0 ? "(no links extracted)" : string.Join('\n', links))
			.AppendLine("Inline JavaScript (untrusted source; not executed):")
			.AppendLine(scripts.Length == 0 ? "(no inline scripts extracted)" : scripts)
			.AppendLine("CSS selector and rule excerpts (bounded; not a complete stylesheet):")
			.AppendLine(styles.Length == 0 ? "(no inline CSS rules extracted)" : styles)
			.AppendLine("External script and stylesheet references (not fetched):")
			.AppendLine(externalResources.Count == 0 ? "(none extracted)" : string.Join('\n', externalResources))
			.AppendLine("DOM landmarks (selected IDs, classes, roles, and accessible labels):")
			.AppendLine(landmarks.Count == 0 ? "(no landmarks extracted)" : string.Join('\n', landmarks))
			.ToString()
			.TrimEnd();

		return EvidenceSanitizer.Limit(normalized, maxCharacters, out truncated);
	}

	private static string ExtractJavaScript(string html)
	{
		var scripts = new StringBuilder();
		var remainingCharacters = MaxInlineScriptCharacters;
		var scriptNumber = 0;
		foreach (Match match in ScriptBlockRegex.Matches(html).Take(MaxInlineScriptCount))
		{
			var code = match.Groups["code"].Value.Trim();
			if (code.Length == 0)
			{
				continue;
			}

			if (remainingCharacters == 0)
			{
				scripts.AppendLine("[Inline JavaScript omitted after the configured character limit.]");
				break;
			}

			var length = Math.Min(code.Length, Math.Min(MaxScriptCharactersPerBlock, remainingCharacters));
			scripts.AppendLine($"Script {++scriptNumber}:");
			scripts.AppendLine(code[..length]);
			remainingCharacters -= length;
			if (length < code.Length)
			{
				scripts.AppendLine("[Script content truncated.]");
				if (remainingCharacters == 0)
				{
					break;
				}
			}
		}

		if (ScriptBlockRegex.Matches(html).Count > MaxInlineScriptCount)
		{
			scripts.AppendLine("[Additional inline scripts omitted after the configured script-count limit.]");
		}

		return EvidenceSanitizer.Sanitize(scripts.ToString().TrimEnd());
	}

	private static string ExtractCssRules(string html)
	{
		var excerpts = new StringBuilder();
		var remainingCharacters = MaxCssCharacters;
		var ruleCount = 0;
		foreach (Match style in StyleBlockRegex.Matches(html))
		{
			foreach (Match rule in CssRuleRegex.Matches(style.Groups["css"].Value))
			{
				var selector = NormalizeCssField(rule.Groups["selector"].Value);
				if (selector.Length == 0 || selector.StartsWith('@'))
				{
					continue;
				}

				if (ruleCount >= MaxCssRuleCount || remainingCharacters == 0)
				{
					excerpts.AppendLine("[Additional CSS rules omitted after the configured limit.]");
					return EvidenceSanitizer.Sanitize(excerpts.ToString().TrimEnd());
				}

				var declarations = NormalizeCssField(rule.Groups["declarations"].Value);
				var excerpt = $"{LimitField(selector, 300)} {{ {LimitField(declarations, 220)} }}";
				if (excerpt.Length > remainingCharacters)
				{
					excerpt = LimitField(excerpt, remainingCharacters);
				}

				excerpts.AppendLine(excerpt);
				remainingCharacters -= excerpt.Length;
				ruleCount++;
			}
		}

		return EvidenceSanitizer.Sanitize(excerpts.ToString().TrimEnd());
	}

	private static List<string> ExtractExternalResources(string html)
	{
		var resources = new List<string>();
		foreach (Match element in ElementRegex.Matches(html))
		{
			var tagName = element.Groups["tag"].Value;
			var attributes = element.Groups["attributes"].Value;
			if (tagName.Equals("script", StringComparison.OrdinalIgnoreCase))
			{
				var source = GetAttribute(attributes, "src");
				if (!string.IsNullOrWhiteSpace(source))
				{
					resources.Add("script src=" + LimitField(WebUtility.HtmlDecode(source), 500));
				}
			}
			else if (tagName.Equals("link", StringComparison.OrdinalIgnoreCase)
				&& (GetAttribute(attributes, "rel") ?? string.Empty)
					.Split(' ', StringSplitOptions.RemoveEmptyEntries)
					.Contains("stylesheet", StringComparer.OrdinalIgnoreCase))
			{
				var href = GetAttribute(attributes, "href");
				if (!string.IsNullOrWhiteSpace(href))
				{
					resources.Add("stylesheet href=" + LimitField(WebUtility.HtmlDecode(href), 500));
				}
			}

			if (resources.Count >= 40)
			{
				resources.Add("[Additional external resources omitted.]");
				break;
			}
		}

		return resources.Select(EvidenceSanitizer.Sanitize).ToList();
	}

	private static string NormalizeCssField(string value) =>
		WhitespaceRegex.Replace(value, " ").Trim();

	public static string NormalizeMhtml(byte[] mhtml, int maxCharacters, out bool truncated)
	{
		ArgumentNullException.ThrowIfNull(mhtml);
		var html = ExtractHtmlPart(Encoding.Latin1.GetString(mhtml), 0);
		return Normalize(html, maxCharacters, out truncated);
	}

	private static string ExtractHtmlPart(string message, int depth)
	{
		if (depth > 5)
		{
			throw new InvalidDataException("MHTML contains too many nested MIME parts.");
		}

		var separator = FindHeaderBodySeparator(message);
		if (separator is null)
		{
			throw new InvalidDataException("MHTML MIME headers are incomplete.");
		}

		var (headerLength, bodyOffset) = separator.Value;
		var headers = ParseHeaders(message[..headerLength]);
		if (!headers.TryGetValue("Content-Type", out var contentTypeHeader))
		{
			throw new InvalidDataException("MHTML MIME part has no Content-Type header.");
		}

		ContentType contentType;
		try
		{
			contentType = new ContentType(contentTypeHeader);
		}
		catch (FormatException exception)
		{
			throw new InvalidDataException("MHTML contains an invalid MIME Content-Type header.", exception);
		}

		var body = message[bodyOffset..];
		if (contentType.MediaType.Equals("text/html", StringComparison.OrdinalIgnoreCase))
		{
			var transferEncoding = headers.GetValueOrDefault("Content-Transfer-Encoding");
			var contentBytes = DecodeTransferEncoding(body, transferEncoding);
			return DecodeText(contentBytes, contentType.CharSet);
		}

		if (!contentType.MediaType.StartsWith("multipart/", StringComparison.OrdinalIgnoreCase))
		{
			throw new InvalidDataException("MHTML contains no HTML page part.");
		}

		var boundary = contentType.Parameters["boundary"];
		if (string.IsNullOrWhiteSpace(boundary))
		{
			throw new InvalidDataException("MHTML multipart Content-Type has no boundary.");
		}

		var marker = "--" + boundary;
		var part = new StringBuilder();
		var insidePart = false;
		foreach (var line in body.Split('\n'))
		{
			var trimmedLine = line.TrimEnd('\r');
			if (IsBoundaryLine(trimmedLine, marker, out var isClosing))
			{
				if (insidePart)
				{
					var partContent = part.ToString();
					try
					{
						return ExtractHtmlPart(partContent, depth + 1);
					}
					catch (InvalidDataException)
					{
						part.Clear();
					}
				}

				if (isClosing)
				{
					break;
				}

				insidePart = true;
				continue;
			}

			if (insidePart)
			{
				part.Append(trimmedLine).Append("\r\n");
			}
		}

		if (insidePart && part.Length > 0)
		{
			try
			{
				return ExtractHtmlPart(part.ToString(), depth + 1);
			}
			catch (InvalidDataException)
			{
				// Report a clear no-HTML-part error below rather than exposing MIME content.
			}
		}

		throw new InvalidDataException("MHTML multipart content contains no text/html page part.");
	}

	private static (int HeaderLength, int BodyOffset)? FindHeaderBodySeparator(string message)
	{
		var crlfSeparator = message.IndexOf("\r\n\r\n", StringComparison.Ordinal);
		if (crlfSeparator >= 0)
		{
			return (crlfSeparator, crlfSeparator + 4);
		}

		var lfSeparator = message.IndexOf("\n\n", StringComparison.Ordinal);
		return lfSeparator >= 0 ? (lfSeparator, lfSeparator + 2) : null;
	}

	private static Dictionary<string, string> ParseHeaders(string headers)
	{
		var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
		string? currentHeader = null;
		foreach (var line in headers.Split('\n'))
		{
			var normalizedLine = line.TrimEnd('\r');
			if (normalizedLine.Length == 0)
			{
				continue;
			}

			if (char.IsWhiteSpace(normalizedLine[0]) && currentHeader is not null)
			{
				result[currentHeader] += " " + normalizedLine.Trim();
				continue;
			}

			var colon = normalizedLine.IndexOf(':');
			if (colon <= 0)
			{
				continue;
			}

			currentHeader = normalizedLine[..colon].Trim();
			result[currentHeader] = normalizedLine[(colon + 1)..].Trim();
		}

		return result;
	}

	private static bool IsBoundaryLine(string line, string marker, out bool isClosing)
	{
		isClosing = false;
		if (!line.StartsWith(marker, StringComparison.Ordinal))
		{
			return false;
		}

		var suffix = line[marker.Length..].Trim();
		if (suffix.Length == 0)
		{
			return true;
		}

		if (suffix == "--")
		{
			isClosing = true;
			return true;
		}

		return false;
	}

	private static byte[] DecodeTransferEncoding(string content, string? transferEncoding)
	{
		var bytes = Encoding.Latin1.GetBytes(content);
		switch (transferEncoding?.Trim().ToLowerInvariant())
		{
			case "base64":
				try
				{
					return Convert.FromBase64String(Encoding.ASCII.GetString(bytes));
				}
				catch (FormatException exception)
				{
					throw new InvalidDataException("MHTML HTML part has invalid base64 encoding.", exception);
				}
			case "quoted-printable":
				return DecodeQuotedPrintable(bytes);
			default:
				return bytes;
		}
	}

	private static byte[] DecodeQuotedPrintable(byte[] input)
	{
		using var output = new MemoryStream(input.Length);
		for (var index = 0; index < input.Length; index++)
		{
			if (input[index] != '=' || index + 1 >= input.Length)
			{
				output.WriteByte(input[index]);
				continue;
			}

			if (input[index + 1] == '\r' && index + 2 < input.Length && input[index + 2] == '\n')
			{
				index += 2;
				continue;
			}

			if (input[index + 1] == '\n')
			{
				index++;
				continue;
			}

			if (index + 2 < input.Length
				&& byte.TryParse(input.AsSpan(index + 1, 2), System.Globalization.NumberStyles.HexNumber, null, out var value))
			{
				output.WriteByte(value);
				index += 2;
				continue;
			}

			output.WriteByte(input[index]);
		}

		return output.ToArray();
	}

	private static string DecodeText(byte[] content, string? charset)
	{
		if (!string.IsNullOrWhiteSpace(charset))
		{
			try
			{
				return Encoding.GetEncoding(charset).GetString(content);
			}
			catch (ArgumentException)
			{
				// Use UTF-8 for unknown charset labels; the page text remains bounded and untrusted.
			}
		}

		return new UTF8Encoding(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: false).GetString(content);
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