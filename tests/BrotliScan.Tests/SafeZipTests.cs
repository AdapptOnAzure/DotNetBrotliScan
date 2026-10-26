using System.IO.Compression;
using BrotliScan.AppService;

namespace BrotliScan.Tests;

[TestClass]
public sealed class SafeZipTests
{
    [TestMethod]
    public void RejectsPathTraversal()
    {
        using var temp = new TempDir();
        string zip = temp.Write("evil.zip", Fakes.Zip(("ok.txt", [1]), ("../escaped.txt", [2])));
        Assert.ThrowsExactly<InvalidDataException>(() => SafeZip.Extract(zip, Path.Combine(temp.Path, "out"), 1 << 20));
        Assert.IsFalse(File.Exists(Path.Combine(temp.Path, "escaped.txt")));
    }

    [TestMethod]
    [DataRow("file.txt:hidden")]
    [DataRow("C:/Windows/evil.txt")]
    public void RejectsNamesWindowsTreatsSpecially(string name)
    {
        using var temp = new TempDir();
        string zip = temp.Write("ads.zip", Fakes.Zip((name, [1])));
        Assert.ThrowsExactly<InvalidDataException>(() => SafeZip.Extract(zip, Path.Combine(temp.Path, "out"), 1 << 20));
    }

    [TestMethod]
    public void StopsAtSizeLimitEvenWhenHeadersLie()
    {
        using var temp = new TempDir();
        string zip = temp.Write("bomb.zip", Fakes.Zip(("zeros.bin", new byte[4 << 20])));
        Assert.ThrowsExactly<InvalidDataException>(() => SafeZip.Extract(zip, Path.Combine(temp.Path, "out"), 1 << 20));
    }

    [TestMethod]
    public void SkipsSymlinks()
    {
        using var temp = new TempDir();
        using var buffer = new MemoryStream();
        using (var archive = new ZipArchive(buffer, ZipArchiveMode.Create, leaveOpen: true))
        {
            var link = archive.CreateEntry("link");
            link.ExternalAttributes = unchecked((int)(0xA1FFu << 16));
            using (var stream = link.Open())
            {
                stream.Write("/etc/passwd"u8);
            }

            using var file = archive.CreateEntry("real.txt").Open();
            file.Write("hi"u8);
        }

        string zip = temp.Write("links.zip", buffer.ToArray());
        string output = Path.Combine(temp.Path, "out");
        SafeZip.Extract(zip, output, 1 << 20);
        Assert.IsFalse(File.Exists(Path.Combine(output, "link")));
        Assert.IsTrue(File.Exists(Path.Combine(output, "real.txt")));
    }
}

internal sealed class TempDir : IDisposable
{
    public string Path { get; } = Directory.CreateTempSubdirectory("brotli-scan-test-").FullName;

    public string Write(string name, byte[] content)
    {
        string file = System.IO.Path.Combine(Path, name);
        File.WriteAllBytes(file, content);
        return file;
    }

    public void Dispose() => Directory.Delete(Path, recursive: true);
}
