using System.IO.Compression;

using var input = File.OpenRead(args[0]);
using var brotli = new BrotliStream(input, CompressionMode.Decompress);
using var output = File.Create(args[1]);
brotli.CopyTo(output);
