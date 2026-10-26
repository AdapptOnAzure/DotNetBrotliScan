var builder = WebApplication.CreateBuilder(args);
builder.Services.AddResponseCompression();

var app = builder.Build();
app.UseResponseCompression();

app.MapPost("/hello", async (HttpRequest request) =>
{
    using var reader = new StreamReader(request.Body);
    string body = await reader.ReadToEndAsync();
    return Results.Ok(new { message = "Hello, world!", received = body.Length });
});

app.Run();
