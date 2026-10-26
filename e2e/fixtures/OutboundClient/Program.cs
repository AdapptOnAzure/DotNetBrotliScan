using System.Net;

using var handler = new HttpClientHandler { AutomaticDecompression = DecompressionMethods.All };
using var client = new HttpClient(handler);
Console.WriteLine(await client.GetStringAsync(args[0]));
