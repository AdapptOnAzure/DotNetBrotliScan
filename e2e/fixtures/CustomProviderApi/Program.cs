using System.IO.Compression;
using Microsoft.AspNetCore.RequestDecompression;

var builder = WebApplication.CreateBuilder(args);

// Removes the built-in brotli provider, then registers its own: still accepts brotli from clients.
builder.Services.AddRequestDecompression(o =>
{
    o.DecompressionProviders.Remove("br");
    o.DecompressionProviders["br"] = new BrotliProvider();
});

var app = builder.Build();
app.UseRequestDecompression();

app.MapPost("/hello", async (HttpRequest request) =>
{
    using var reader = new StreamReader(request.Body);
    string body = await reader.ReadToEndAsync();
    return Results.Ok(new { message = "Hello, world!", received = body.Length });
});

app.Run();

internal sealed class BrotliProvider : IDecompressionProvider
{
    public Stream GetDecompressionStream(Stream stream) => new BrotliStream(stream, CompressionMode.Decompress);
}
