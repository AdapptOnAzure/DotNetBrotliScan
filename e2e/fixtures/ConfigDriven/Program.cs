using System.Net;

var methods = Enum.Parse<DecompressionMethods>(Environment.GetEnvironmentVariable("DECOMPRESSION") ?? "None");
using var handler = new HttpClientHandler();
handler.AutomaticDecompression = methods;
using var client = new HttpClient(handler);
Console.WriteLine(await client.GetStringAsync(args[0]));
