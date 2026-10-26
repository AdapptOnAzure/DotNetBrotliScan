namespace BrotliScan.Tests;

[TestClass]
public sealed class NativeScannerTests
{
    [TestMethod]
    public void PreFixDecoderIsVulnerable() =>
        Assert.AreEqual(DecoderStatus.Vulnerable, Scan(Fakes.VulnerableDecoder())?.Status);

    [TestMethod]
    public void FixMarkerMeansPatched() =>
        Assert.AreEqual(DecoderStatus.Patched, Scan(Fakes.PatchedDecoder())?.Status);

    [TestMethod]
    public void StrippedDecoderIsUnconfirmed() =>
        Assert.AreEqual(DecoderStatus.Unconfirmed, Scan(Fakes.Concat(Fakes.Dictionary, "BrotliDecoderDecompressStream"u8.ToArray()))?.Status);

    [TestMethod]
    public void SystemLinkedRuntimeIsReported() =>
        Assert.AreEqual(DecoderStatus.SystemLibrary, Scan(Fakes.Concat(Fakes.Filler(100), "libbrotlidec.so.1\0BrotliDecoderDecompressStream"u8.ToArray()))?.Status);

    [TestMethod]
    public void NoBrotliMeansNoDecoder() =>
        Assert.IsNull(Scan(Fakes.Filler(10_000)));

    [TestMethod]
    [DataRow(-30)] // starts before the chunk boundary and ends after it
    [DataRow(-5)]
    [DataRow(0)]
    public void MarkersAcrossChunkBoundaryAreFound(int offset)
    {
        var marker = "_ERROR_FORMAT_BLOCK_SWITCH"u8.ToArray();
        var bytes = new byte[NativeScanner.ChunkSize + 4096];
        Fakes.VulnerableDecoder().CopyTo(bytes, 0);
        marker.CopyTo(bytes, NativeScanner.ChunkSize + offset);
        Assert.AreEqual(DecoderStatus.Patched, Scan(bytes)?.Status);
    }

    [TestMethod]
    public void ReadsVersionStamp()
    {
        var bytes = Fakes.Concat(Fakes.VulnerableDecoder(), "@(#)Version 10.0.1325.45006 @Commit: abc123\0"u8.ToArray());
        Assert.AreEqual("10.0.1325.45006 @Commit: abc123", Scan(bytes)?.VersionStamp);
    }

    private static DecoderFingerprint? Scan(byte[] bytes) => NativeScanner.Scan(new MemoryStream(bytes)).Decoder;
}
