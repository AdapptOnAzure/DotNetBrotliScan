using System.IO.Compression;
using System.Text;

namespace BrotliScan.Tests;

[TestClass]
public sealed class BundleTests
{
    private static readonly byte[] Signature =
    [
        0x8b, 0x12, 0x02, 0xb9, 0x6a, 0x61, 0x20, 0x38, 0x72, 0x7b, 0x93, 0x02, 0x14, 0xd7, 0xa0, 0x32,
        0x13, 0xf5, 0xb9, 0xe6, 0xef, 0xae, 0x33, 0x18, 0xee, 0x3b, 0x2d, 0xce, 0x24, 0xb3, 0x6a, 0xae,
    ];

    [TestMethod]
    public void CompressedSelfContainedBundleIsAffected()
    {
        var app = Compiler.Compile("public static class P { public static object M(object a) => Microsoft.AspNetCore.Builder.RequestDecompressionBuilderExtensions.UseRequestDecompression(a); }");
        var config = Encoding.UTF8.GetBytes("""{ "runtimeOptions": { "includedFrameworks": [ { "name": "Microsoft.NETCore.App", "version": "10.0.13" } ] } }""");
        var report = ScanFile(BuildBundle(Fakes.VulnerableDecoder(), (app, 1, "App.dll", true), (config, 4, "App.runtimeconfig.json", false)));

        var target = report.Targets.Single();
        Assert.AreEqual("single-file app", target.Kind);
        Assert.AreEqual(Verdict.Affected, target.Verdict, target.Reason);
        StringAssert.Contains(target.Findings.Single().Location, "!App.dll: ");
    }

    [TestMethod]
    public void CorruptManifestIsIgnoredSafely()
    {
        var bundle = BuildBundle(Fakes.VulnerableDecoder(), (new byte[16], 1, "App.dll", false));
        // Overwrite the entry count with a huge value.
        long header = BitConverter.ToInt64(bundle, IndexOf(bundle, Signature) - 8);
        BitConverter.GetBytes(int.MaxValue).CopyTo(bundle, header + 8);

        var report = ScanFile(bundle);
        Assert.AreEqual(0, report.Targets.Count);
        Assert.AreEqual(DecoderStatus.Vulnerable, report.Components.Single().Status);
    }

    private static ScanReport ScanFile(byte[] bytes)
    {
        string path = Path.Combine(Path.GetTempPath(), $"bundle-{Guid.NewGuid():N}");
        File.WriteAllBytes(path, bytes);
        try
        {
            var options = new ScanOptions { IncludeHost = false };
            options.Paths.Add(path);
            return new Scanner(options).Run();
        }
        finally
        {
            File.Delete(path);
        }
    }

    /// <summary>Lays out a v6 single-file bundle the way the .NET bundler does.</summary>
    private static byte[] BuildBundle(byte[] host, params (byte[] Content, byte Type, string Path, bool Compress)[] files)
    {
        using var output = new MemoryStream();
        using var writer = new BinaryWriter(output, Encoding.UTF8, leaveOpen: true);
        writer.Write(host);
        long placeholder = output.Position;
        writer.Write(0L);
        writer.Write(Signature);
        writer.Write(Fakes.Filler(64));

        var entries = new List<(long Offset, long Size, long Compressed, byte Type, string Path)>();
        foreach (var (content, type, path, compress) in files)
        {
            long offset = output.Position;
            if (compress)
            {
                using var deflated = new MemoryStream();
                using (var deflate = new DeflateStream(deflated, CompressionLevel.Optimal, leaveOpen: true))
                {
                    deflate.Write(content);
                }

                writer.Write(deflated.ToArray());
                entries.Add((offset, content.Length, deflated.Length, type, path));
            }
            else
            {
                writer.Write(content);
                entries.Add((offset, content.Length, 0, type, path));
            }
        }

        long header = output.Position;
        writer.Write(6u);
        writer.Write(0u);
        writer.Write(entries.Count);
        writer.Write("bundle-id");
        writer.Write(new byte[4 * sizeof(long) + sizeof(ulong)]);
        foreach (var entry in entries)
        {
            writer.Write(entry.Offset);
            writer.Write(entry.Size);
            writer.Write(entry.Compressed);
            writer.Write(entry.Type);
            writer.Write(entry.Path);
        }

        output.Position = placeholder;
        writer.Write(header);
        writer.Flush();
        return output.ToArray();
    }

    private static int IndexOf(byte[] haystack, byte[] needle) => haystack.AsSpan().IndexOf(needle);
}
