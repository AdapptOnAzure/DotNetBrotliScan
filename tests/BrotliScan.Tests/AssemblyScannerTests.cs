using System.Reflection.PortableExecutable;
using Microsoft.CodeAnalysis;

namespace BrotliScan.Tests;

[TestClass]
public sealed class AssemblyScannerTests
{
    private const string Usings = """
        using System;
        using System.IO;
        using System.IO.Compression;
        using System.Net;
        using System.Net.Http;
        using System.Threading.Tasks;
        using Microsoft.AspNetCore.Builder;
        using Microsoft.AspNetCore.Http;
        using Microsoft.AspNetCore.RequestDecompression;
        """;

    [TestMethod]
    [DataRow(OptimizationLevel.Release)]
    [DataRow(OptimizationLevel.Debug)]
    public void FindsRequestDecompression(OptimizationLevel optimization) =>
        AssertSingle("object M(object app) => app.UseRequestDecompression();", FindingKind.InboundRequest, optimization);

    [TestMethod]
    [DataRow(OptimizationLevel.Release)]
    [DataRow(OptimizationLevel.Debug)]
    public void FindsBrProviderRemoval(OptimizationLevel optimization) =>
        AssertSingle("void M(RequestDecompressionOptions o) => o.DecompressionProviders.Remove(\"br\");", FindingKind.Mitigation, optimization);

    [TestMethod]
    [DataRow("DecompressionMethods.All", "DecompressionMethods.All")]
    [DataRow("DecompressionMethods.GZip | DecompressionMethods.Brotli", "DecompressionMethods.GZip | DecompressionMethods.Brotli")]
    public void FindsAutomaticBrotliDecompression(string value, string described)
    {
        var finding = AssertSingle($"HttpClientHandler M() => new HttpClientHandler {{ AutomaticDecompression = {value} }};", FindingKind.OutboundResponse);
        StringAssert.Contains(finding.Detail, described);
    }

    [TestMethod]
    public void SocketsHandlerWithoutBrotliIsSafe() =>
        AssertNone("void M(SocketsHttpHandler h) => h.AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate;");

    [TestMethod]
    public void NonConstantDecompressionNeedsReview() =>
        AssertSingle("void M(HttpClientHandler h, DecompressionMethods m) => h.AutomaticDecompression = m;", FindingKind.Ambiguous);

    [TestMethod]
    [DataRow("new BrotliStream(s, CompressionMode.Decompress)")]
    [DataRow("new BrotliStream(s, CompressionMode.Decompress, leaveOpen: true)")]
    public void FindsBrotliStreamDecompression(string expression) =>
        AssertSingle($"Stream M(Stream s) => {expression};", FindingKind.DirectDecode);

    [TestMethod]
    [DataRow("new BrotliStream(s, CompressionMode.Compress)")]
    [DataRow("new BrotliStream(s, CompressionLevel.Optimal)")]
    [DataRow("new BrotliStream(s, CompressionLevel.Fastest, leaveOpen: true)")]
    public void CompressionIsSafe(string expression) =>
        AssertNone($"Stream M(Stream s) => {expression};");

    [TestMethod]
    public void FindsBrotliDecoder() =>
        AssertSingle("bool M(byte[] a, byte[] b) => BrotliDecoder.TryDecompress(a, b, out _);", FindingKind.DirectDecode);

    [TestMethod]
    public void FindsDecodePathInsideAsyncMethod() =>
        AssertSingle("async System.Threading.Tasks.Task M(HttpClientHandler h) { await System.Threading.Tasks.Task.Yield(); h.AutomaticDecompression = DecompressionMethods.All; }", FindingKind.OutboundResponse);

    [TestMethod]
    [DataRow(OptimizationLevel.Release)]
    [DataRow(OptimizationLevel.Debug)]
    public void RequestBodyDecodingIsInbound(OptimizationLevel optimization) =>
        AssertSingle("Stream M(HttpRequest r) => new BrotliStream(r.Body, CompressionMode.Decompress);", FindingKind.InboundRequest, optimization);

    [TestMethod]
    [DataRow(OptimizationLevel.Release)]
    [DataRow(OptimizationLevel.Debug)]
    public void RequestBodyThroughLocalIsInbound(OptimizationLevel optimization) =>
        AssertSingle("Stream M(HttpRequest r) { Stream body = r.Body; Console.WriteLine(body.CanRead); return new BrotliStream(body, CompressionMode.Decompress, leaveOpen: true); }",
            FindingKind.InboundRequest, optimization);

    [TestMethod]
    [DataRow(OptimizationLevel.Release)]
    [DataRow(OptimizationLevel.Debug)]
    public void RequestBodyAcrossAwaitIsInbound(OptimizationLevel optimization) =>
        AssertSingle("async Task<int> M(HttpRequest r) { Stream body = r.Body; await Task.Yield(); using var b = new BrotliStream(body, CompressionMode.Decompress); return b.ReadByte(); }",
            FindingKind.InboundRequest, optimization);

    [TestMethod]
    public void DecompressionProviderIsInbound()
    {
        var findings = ScanSource($$"""
            {{Usings}}
            public sealed class P : Microsoft.AspNetCore.RequestDecompression.IDecompressionProvider
            {
                public Stream GetDecompressionStream(Stream stream) => new BrotliStream(stream, CompressionMode.Decompress);
            }
            """);
        Assert.AreEqual(FindingKind.InboundRequest, findings.Single().Kind);
        StringAssert.Contains(findings.Single().Detail, "IDecompressionProvider");
    }

    [TestMethod]
    public void ReAddedBrProviderIsInbound()
    {
        var findings = Scan("void M(RequestDecompressionOptions o) { o.DecompressionProviders.Remove(\"br\"); o.DecompressionProviders[\"br\"] = new object(); }", OptimizationLevel.Release);
        CollectionAssert.AreEquivalent(new[] { FindingKind.Mitigation, FindingKind.InboundRequest }, findings.Select(f => f.Kind).ToArray());
    }

    private static Finding AssertSingle(string member, FindingKind kind, OptimizationLevel optimization = OptimizationLevel.Release)
    {
        var findings = Scan(member, optimization);
        Assert.AreEqual(1, findings.Count, string.Join("; ", findings));
        Assert.AreEqual(kind, findings[0].Kind);
        return findings[0];
    }

    private static void AssertNone(string member) =>
        Assert.AreEqual(0, Scan(member, OptimizationLevel.Release).Count);

    private static IReadOnlyList<Finding> Scan(string member, OptimizationLevel optimization) =>
        ScanSource($"{Usings}\npublic static class Sample {{ public static {member} }}", optimization);

    private static IReadOnlyList<Finding> ScanSource(string source, OptimizationLevel optimization = OptimizationLevel.Release)
    {
        using var pe = new PEReader(new MemoryStream(Compiler.Compile(source, optimization)));
        return AssemblyScanner.Scan(pe, "Sample.dll").Findings;
    }
}
