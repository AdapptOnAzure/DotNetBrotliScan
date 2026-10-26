using System.IO.Compression;

namespace BrotliScan.AppService;

/// <summary>
/// Extracts an untrusted zip: entries can't escape the destination (zip slip), symlinks are skipped,
/// and entry count and total size are capped against what is actually inflated, not what headers claim.
/// </summary>
internal static class SafeZip
{
    public const int MaxEntries = 200_000;

    public static void Extract(string zipPath, string destination, long maxTotalBytes)
    {
        string root = Path.GetFullPath(destination);
        string rootWithSeparator = root.EndsWith(Path.DirectorySeparatorChar) ? root : root + Path.DirectorySeparatorChar;
        Directory.CreateDirectory(root);

        using var archive = ZipFile.OpenRead(zipPath);
        if (archive.Entries.Count > MaxEntries)
        {
            throw new InvalidDataException($"Archive has {archive.Entries.Count:N0} entries; the limit is {MaxEntries:N0}.");
        }

        long total = 0;
        foreach (var entry in archive.Entries)
        {
            // "name:stream" would write an NTFS alternate data stream; other invalid characters vary by OS.
            if (entry.FullName.Contains(':') || entry.FullName.IndexOfAny(['\0', '<', '>', '"', '|', '?', '*']) >= 0)
            {
                throw new InvalidDataException($"Archive entry '{entry.FullName}' has characters that aren't valid in a file name.");
            }

            string target = Path.GetFullPath(Path.Combine(root, entry.FullName));
            if (!target.StartsWith(rootWithSeparator, StringComparison.Ordinal) && target != root)
            {
                throw new InvalidDataException($"Archive entry '{entry.FullName}' points outside the extraction folder.");
            }

            if (entry.FullName.EndsWith('/') || entry.FullName.EndsWith('\\'))
            {
                Directory.CreateDirectory(target);
                continue;
            }

            // Unix mode bits live in the high word; 0xA000 is a symbolic link.
            if (((entry.ExternalAttributes >> 16) & 0xF000) == 0xA000)
            {
                continue;
            }

            Directory.CreateDirectory(Path.GetDirectoryName(target)!);
            using var source = entry.Open();
            using var output = new FileStream(target, FileMode.CreateNew, FileAccess.Write, FileShare.None);
            total += CopyBounded(source, output, maxTotalBytes - total, entry.FullName);
        }
    }

    private static long CopyBounded(Stream source, Stream destination, long remaining, string name)
    {
        var buffer = new byte[81920];
        long copied = 0;
        int read;
        while ((read = source.Read(buffer, 0, buffer.Length)) > 0)
        {
            copied += read;
            if (copied > remaining)
            {
                throw new InvalidDataException($"Archive expands past the size limit (at '{name}').");
            }

            destination.Write(buffer, 0, read);
        }

        return copied;
    }
}
