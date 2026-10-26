namespace BrotliScan.Tests;

[TestClass]
public sealed class ReporterTests
{
    [TestMethod]
    [DataRow("project", "project         azure:rg/app")]
    [DataRow("azure function app", "azure function app azure:rg/app")]
    public void TargetKindIsAlwaysSeparatedFromThePath(string kind, string expected)
    {
        var target = new TargetReport(kind, "azure:rg/app", null, Verdict.Review, "couldn't scan", [], []);
        var report = new ScanReport("brotli-scan", "1.0.0", "CVE-2026-111497", DateTimeOffset.UnixEpoch, [], 0, [], [target], []);
        using var output = new StringWriter();

        new Reporter(output, [], color: false, verbose: false).WriteText(report, TimeSpan.Zero);

        StringAssert.Contains(output.ToString(), expected);
    }
}
