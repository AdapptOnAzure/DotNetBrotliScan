using System.Net;

namespace BrotliScan.AppService;

internal static class SafeHttp
{
    /// <param name="handler">For tests; shared between clients, so it isn't disposed with them.</param>
    public static HttpClient Create(HttpMessageHandler? handler = null)
    {
        var client = handler is null
            ? new HttpClient(new SocketsHttpHandler
            {
                // A redirect could carry a bearer token to another host; none of these APIs need one.
                AllowAutoRedirect = false,
                // Deliberately None: this tool must not decode brotli from the network (CVE-2026-111497).
                AutomaticDecompression = DecompressionMethods.None,
            })
            : new HttpClient(handler, disposeHandler: false);
        client.Timeout = TimeSpan.FromMinutes(30);
        return client;
    }
}
