using System.IO.Compression;

var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

// Accepts brotli-compressed bodies without the request decompression middleware.
app.MapPost("/hello", async (HttpRequest request) =>
{
    Stream body = request.Body;
    if (request.Headers.ContentEncoding == "br")
    {
        body = new BrotliStream(body, CompressionMode.Decompress);
    }

    using var reader = new StreamReader(body);
    string text = await reader.ReadToEndAsync();
    return Results.Ok(new { message = "Hello, world!", received = text.Length });
});

app.Run();
