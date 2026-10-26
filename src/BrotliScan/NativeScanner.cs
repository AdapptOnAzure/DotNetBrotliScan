using System.Buffers.Binary;
using System.Text;

namespace BrotliScan;

internal sealed record DecoderFingerprint(DecoderStatus Status, string Evidence, string? VersionStamp);

/// <param name="Decoder">Null when the binary contains no brotli.</param>
/// <param name="BundleHeaderOffset">Non-zero when the binary is a .NET single-file bundle.</param>
internal sealed record NativeScanResult(DecoderFingerprint? Decoder, long BundleHeaderOffset);

/// <summary>
/// Classifies a native binary's brotli decoder from byte signatures. Nothing is loaded or executed.
/// </summary>
internal static class NativeScanner
{
    // Start of brotli's built-in dictionary (RFC 7932, appendix A). Every brotli build carries it, stripped or not.
    private static readonly byte[] Dictionary = "timedownlifeleftbackcodedatashow"u8.ToArray();
    private static readonly byte[] DecoderEntryPoint = "BrotliDecoderDecompressStream"u8.ToArray();

    // BrotliDecoderErrorString() stringifies every error code. -16 exists in all affected releases; -17
    // (BLOCK_SWITCH) was added by the fix, google/brotli 0ed4268a, shipped in 1.0.10, 1.1.1 and 1.2.1.
    private static readonly byte[] ErrorDistance = "_ERROR_FORMAT_DISTANCE"u8.ToArray();
    private static readonly byte[] ErrorBlockSwitch = "_ERROR_FORMAT_BLOCK_SWITCH"u8.ToArray();

    // Builds configured with CLR_CMAKE_USE_SYSTEM_BROTLI import the OS library instead of embedding brotli.
    private static readonly byte[] SystemBrotli = "libbrotlidec"u8.ToArray();
    private static readonly byte[] VersionStamp = "@(#)Version "u8.ToArray();

    // SHA-256 of ".net core bundle". The apphost stores the bundle header offset in the 8 bytes before it
    // (src/native/corehost/apphost/bundle_marker.cpp); a plain apphost leaves them zero.
    private static readonly byte[] BundleSignature =
    [
        0x8b, 0x12, 0x02, 0xb9, 0x6a, 0x61, 0x20, 0x38, 0x72, 0x7b, 0x93, 0x02, 0x14, 0xd7, 0xa0, 0x32,
        0x13, 0xf5, 0xb9, 0xe6, 0xef, 0xae, 0x33, 0x18, 0xee, 0x3b, 0x2d, 0xce, 0x24, 0xb3, 0x6a, 0xae,
    ];

    internal const int ChunkSize = 4 << 20;
    // Re-scanned between chunks; longer than any needle plus the version text captured after the stamp.
    private const int Overlap = 256;
    private const int MaxStampLength = 120;

    public static NativeScanResult Scan(Stream stream)
    {
        var buffer = new byte[ChunkSize + Overlap];
        int carried = 0;
        bool dictionary = false, entryPoint = false, distance = false, blockSwitch = false, systemBrotli = false;
        string? stamp = null;
        long bundleHeaderOffset = 0;

        while (true)
        {
            int read = stream.ReadAtLeast(buffer.AsSpan(carried, ChunkSize), ChunkSize, throwOnEndOfStream: false);
            bool last = read < ChunkSize;
            var span = buffer.AsSpan(0, carried + read);

            dictionary |= span.IndexOf(Dictionary) >= 0;
            entryPoint |= span.IndexOf(DecoderEntryPoint) >= 0;
            distance |= span.IndexOf(ErrorDistance) >= 0;
            blockSwitch |= span.IndexOf(ErrorBlockSwitch) >= 0;
            systemBrotli |= span.IndexOf(SystemBrotli) >= 0;
            stamp ??= ReadStamp(span, last);
            if (bundleHeaderOffset == 0)
            {
                bundleHeaderOffset = ReadBundleHeaderOffset(span);
            }

            if (last)
            {
                break;
            }

            carried = Math.Min(Overlap, span.Length);
            span[^carried..].CopyTo(buffer);
        }

        return new NativeScanResult(
            Classify(dictionary, entryPoint, distance, blockSwitch, systemBrotli, stamp),
            bundleHeaderOffset);
    }

    private static DecoderFingerprint? Classify(
        bool dictionary, bool entryPoint, bool distance, bool blockSwitch, bool systemBrotli, string? stamp)
    {
        if (blockSwitch)
        {
            return new(DecoderStatus.Patched, "decoder error table includes BLOCK_SWITCH (-17), added by the fix", stamp);
        }

        if (distance)
        {
            return new(DecoderStatus.Vulnerable, "decoder error table lacks BLOCK_SWITCH (-17): pre-fix brotli", stamp);
        }

        if (!dictionary && systemBrotli)
        {
            return new(DecoderStatus.SystemLibrary, "links the OS brotli library (libbrotlidec); patch state follows the OS package", stamp);
        }

        if (dictionary && entryPoint)
        {
            return new(DecoderStatus.Unconfirmed, "brotli decoder embedded, but its error strings are stripped, so the fix can't be confirmed from the binary", stamp);
        }

        if (dictionary)
        {
            return new(DecoderStatus.Unknown, "brotli dictionary present without the C decoder's signature (encoder-only build or another implementation)", stamp);
        }

        return null;
    }

    private static string? ReadStamp(ReadOnlySpan<byte> span, bool last)
    {
        int index = span.IndexOf(VersionStamp);
        if (index < 0)
        {
            return null;
        }

        int start = index + VersionStamp.Length;
        int end = start;
        while (end < span.Length && end - start < MaxStampLength && span[end] is >= 0x20 and < 0x7f)
        {
            end++;
        }

        // Cut off by the chunk boundary: it sits in the carried-over tail, so the next chunk sees it whole.
        if (end == span.Length && !last)
        {
            return null;
        }

        return Encoding.ASCII.GetString(span[start..end]);
    }

    private static long ReadBundleHeaderOffset(ReadOnlySpan<byte> span)
    {
        int index = span.IndexOf(BundleSignature);
        return index >= sizeof(long) ? BinaryPrimitives.ReadInt64LittleEndian(span[(index - sizeof(long))..]) : 0;
    }
}
