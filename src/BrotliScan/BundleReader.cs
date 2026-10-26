using System.IO.Compression;
using System.Text;

namespace BrotliScan;

internal enum BundleFileType : byte
{
    Unknown,
    Assembly,
    NativeBinary,
    DepsJson,
    RuntimeConfigJson,
    Symbols,
}

internal sealed record BundleEntry(string RelativePath, BundleFileType Type, long Offset, long Size, long CompressedSize);

/// <summary>
/// Reads the manifest of a .NET single-file bundle (src/native/corehost/bundle/header.cpp and file_entry.cpp).
/// Every length and offset is bounds-checked, since the input is untrusted.
/// </summary>
internal static class BundleReader
{
    private const int MaxEntries = 100_000;
    private const int MaxPathBytes = 4096;

    /// <returns>Null when the offset doesn't point at a manifest this reader understands.</returns>
    public static IReadOnlyList<BundleEntry>? TryRead(Stream stream, long headerOffset)
    {
        if (headerOffset <= 0 || headerOffset >= stream.Length)
        {
            return null;
        }

        try
        {
            stream.Position = headerOffset;
            using var reader = new BinaryReader(stream, Encoding.UTF8, leaveOpen: true);

            uint major = reader.ReadUInt32();
            _ = reader.ReadUInt32(); // minor
            // 1 = .NET Core 3.x, 2 = .NET 5, 6 = .NET 6 and later.
            if (major is not (1 or 2 or 6))
            {
                return null;
            }

            int count = reader.ReadInt32();
            if (count is < 0 or > MaxEntries)
            {
                return null;
            }

            _ = ReadPath(reader); // bundle id
            if (major >= 2)
            {
                // deps.json and runtimeconfig.json locations (offset + size each), then flags.
                reader.BaseStream.Seek(4 * sizeof(long) + sizeof(ulong), SeekOrigin.Current);
            }

            var entries = new List<BundleEntry>(count);
            for (int i = 0; i < count; i++)
            {
                long offset = reader.ReadInt64();
                long size = reader.ReadInt64();
                long compressedSize = major >= 6 ? reader.ReadInt64() : 0;
                var type = (BundleFileType)reader.ReadByte();
                string path = ReadPath(reader);

                long stored = compressedSize > 0 ? compressedSize : size;
                if (offset <= 0 || size < 0 || compressedSize < 0 || stored > stream.Length - offset)
                {
                    return null;
                }

                entries.Add(new BundleEntry(path, type, offset, size, compressedSize));
            }

            return entries;
        }
        catch (Exception ex) when (ex is EndOfStreamException or InvalidDataException or IOException or FormatException)
        {
            return null;
        }
    }

    /// <summary>Returns the entry's bytes, inflating compressed entries; null if larger than <paramref name="maxBytes"/>.</summary>
    public static MemoryStream? Extract(Stream stream, BundleEntry entry, long maxBytes)
    {
        if (entry.Size > maxBytes || entry.Size > int.MaxValue)
        {
            return null;
        }

        var output = new MemoryStream((int)entry.Size);
        stream.Position = entry.Offset;
        if (entry.CompressedSize == 0)
        {
            CopyBounded(stream, output, entry.Size);
        }
        else
        {
            // The bundler writes raw deflate (no zlib header).
            using var compressed = new MemoryStream(ReadExactly(stream, entry.CompressedSize));
            using var inflater = new DeflateStream(compressed, CompressionMode.Decompress);
            CopyBounded(inflater, output, entry.Size);
            if (inflater.ReadByte() != -1)
            {
                throw new InvalidDataException($"Bundle entry '{entry.RelativePath}' inflates past its declared size.");
            }
        }

        output.Position = 0;
        return output;
    }

    private static string ReadPath(BinaryReader reader)
    {
        int length = reader.Read7BitEncodedInt();
        if (length is < 0 or > MaxPathBytes)
        {
            throw new InvalidDataException("Bundle path length out of range.");
        }

        byte[] bytes = reader.ReadBytes(length);
        if (bytes.Length != length)
        {
            throw new EndOfStreamException();
        }

        return Encoding.UTF8.GetString(bytes);
    }

    private static byte[] ReadExactly(Stream stream, long count)
    {
        if (count > int.MaxValue)
        {
            throw new InvalidDataException("Bundle entry too large.");
        }

        var bytes = new byte[count];
        stream.ReadExactly(bytes);
        return bytes;
    }

    private static void CopyBounded(Stream source, Stream destination, long count)
    {
        var buffer = new byte[81920];
        long remaining = count;
        while (remaining > 0)
        {
            int read = source.Read(buffer, 0, (int)Math.Min(buffer.Length, remaining));
            if (read == 0)
            {
                throw new EndOfStreamException();
            }

            destination.Write(buffer, 0, read);
            remaining -= read;
        }
    }
}
