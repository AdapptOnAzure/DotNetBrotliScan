using System.Net;

using var handler = new SocketsHttpHandler
{
    AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate,
};
using var client = new HttpClient(handler);
Console.WriteLine(await client.GetStringAsync(args[0]));
