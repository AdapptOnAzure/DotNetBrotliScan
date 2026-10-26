namespace BrotliScan.Tests;

[TestClass]
public sealed class SourceScannerTests
{
    [TestMethod]
    [DataRow("app.UseRequestDecompression();", FindingKind.InboundRequest)]
    [DataRow("app?.UseRequestDecompression();", FindingKind.InboundRequest)]
    [DataRow("o.DecompressionProviders.Remove(\"br\");", FindingKind.Mitigation)]
    [DataRow("o.DecompressionProviders.Add(\"br\", p);", FindingKind.InboundRequest)]
    [DataRow("var h = new HttpClientHandler { AutomaticDecompression = DecompressionMethods.All };", FindingKind.OutboundResponse)]
    [DataRow("h.AutomaticDecompression = System.Net.DecompressionMethods.GZip | System.Net.DecompressionMethods.Brotli;", FindingKind.OutboundResponse)]
    [DataRow("h.AutomaticDecompression |= DecompressionMethods.Brotli;", FindingKind.OutboundResponse)]
    [DataRow("h.AutomaticDecompression = (DecompressionMethods)7;", FindingKind.OutboundResponse)]
    [DataRow("h.AutomaticDecompression = settings.Methods;", FindingKind.Ambiguous)]
    [DataRow("using var s = new BrotliStream(input, CompressionMode.Decompress);", FindingKind.DirectDecode)]
    [DataRow("using var s = new System.IO.Compression.BrotliStream(input, mode: CompressionMode.Decompress, leaveOpen: true);", FindingKind.DirectDecode)]
    [DataRow("BrotliStream s = new(input, CompressionMode.Decompress);", FindingKind.DirectDecode)]
    [DataRow("using var s = new BrotliStream(input, mode);", FindingKind.Ambiguous)]
    [DataRow("BrotliDecoder.TryDecompress(src, dst, out _);", FindingKind.DirectDecode)]
    [DataRow("Configure(DecompressionMethods.Brotli);", FindingKind.Ambiguous)]
    [DataRow("app.UseResponseCompression();", FindingKind.Info)]
    [DataRow("using var s = new BrotliStream(context.Request.Body, CompressionMode.Decompress);", FindingKind.InboundRequest)]
    [DataRow("context.Request.Body = new BrotliStream(context.Request.Body, CompressionMode.Decompress, leaveOpen: true);", FindingKind.InboundRequest)]
    [DataRow("var body = request.Body; using var s = new BrotliStream(body, CompressionMode.Decompress);", FindingKind.InboundRequest)]
    [DataRow("using var s = new BrotliStream(request.BodyReader.AsStream(), CompressionMode.Decompress);", FindingKind.InboundRequest)]
    [DataRow("o.DecompressionProviders[\"br\"] = new MyProvider();", FindingKind.InboundRequest)]
    [DataRow("using var s = new BrotliStream(File.OpenRead(path), CompressionMode.Decompress);", FindingKind.DirectDecode)]
    public void FindsPattern(string statement, FindingKind expected)
    {
        var findings = ScanStatement(statement);
        Assert.AreEqual(1, findings.Count, string.Join("; ", findings));
        Assert.AreEqual(expected, findings[0].Kind);
    }

    [TestMethod]
    [DataRow("h.AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate;")]
    [DataRow("h.AutomaticDecompression &= ~DecompressionMethods.Brotli;")]
    [DataRow("using var s = new BrotliStream(output, CompressionLevel.Optimal);")]
    [DataRow("using var s = new BrotliStream(output, CompressionMode.Compress);")]
    [DataRow("using var s = new BrotliStream(output, new BrotliCompressionOptions { Quality = 5 });")]
    [DataRow("// app.UseRequestDecompression();")]
    [DataRow("var text = \"app.UseRequestDecompression()\";")]
    public void IgnoresSafeCode(string statement) =>
        Assert.AreEqual(0, ScanStatement(statement).Count);

    [TestMethod]
    [DataRow("IDecompressionProvider", "request decompression provider")]
    [DataRow("ICompressionProvider", "gRPC compression provider")]
    public void DecompressionInsideAProviderIsInbound(string iface, string described)
    {
        var finding = SourceScanner.ScanCSharp(
            $"sealed class P : {iface} {{ public Stream GetDecompressionStream(Stream stream) => new BrotliStream(stream, CompressionMode.Decompress); }}",
            "P.cs").Single();
        Assert.AreEqual(FindingKind.InboundRequest, finding.Kind);
        StringAssert.Contains(finding.Detail, described);
    }

    [TestMethod]
    public void ReportsLineNumbers()
    {
        var findings = SourceScanner.ScanCSharp("class C {\n  void M(object app) {\n    app.UseRequestDecompression();\n  }\n}", "Program.cs");
        Assert.AreEqual("Program.cs:3", findings.Single().Location);
    }

    [TestMethod]
    public void VisualBasicIgnoresComments()
    {
        const string source = """
            ' AutomaticDecompression = DecompressionMethods.Brotli
            handler.AutomaticDecompression = DecompressionMethods.GZip Or DecompressionMethods.Brotli
            """;
        var finding = SourceScanner.ScanText(source, "Program.vb", fsharp: false).Single();
        Assert.AreEqual("Program.vb:2", finding.Location);
        Assert.IsTrue(finding.Heuristic);
    }

    [TestMethod]
    public void FSharpFindsDecompression()
    {
        const string source = """
            (* new BrotliStream(s, CompressionMode.Decompress) *)
            let handler = new HttpClientHandler(AutomaticDecompression = DecompressionMethods.All)
            """;
        Assert.AreEqual(FindingKind.OutboundResponse, SourceScanner.ScanText(source, "App.fs", fsharp: true).Single().Kind);
    }

    private static List<Finding> ScanStatement(string statement) =>
        SourceScanner.ScanCSharp($"class C {{ void M() {{ {statement} }} }}", "Test.cs");
}
