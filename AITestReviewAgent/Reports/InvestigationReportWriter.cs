using System.Text;

namespace AITestReviewAgent.Reports;

public static class InvestigationReportWriter
{
	public static async Task<string> WriteNewAsync(
		string path,
		string content,
		CancellationToken cancellationToken)
	{
		var fullPath = Path.GetFullPath(path);
		var directory = Path.GetDirectoryName(fullPath);
		if (!string.IsNullOrEmpty(directory))
		{
			Directory.CreateDirectory(directory);
		}

		await using var stream = new FileStream(
			fullPath,
			FileMode.CreateNew,
			FileAccess.Write,
			FileShare.None,
			bufferSize: 4096,
			useAsync: true);
		await using var writer = new StreamWriter(stream, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
		await writer.WriteAsync(content.AsMemory(), cancellationToken);
		return fullPath;
	}
}