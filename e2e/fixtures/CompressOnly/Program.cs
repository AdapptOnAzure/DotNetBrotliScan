using System.IO.Compression;

using var input = File.OpenRead(args[0]);
using var output = File.Create(args[1]);
using var brotli = new BrotliStream(output, CompressionLevel.Optimal);
input.CopyTo(brotli);
