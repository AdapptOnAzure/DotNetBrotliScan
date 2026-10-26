using System.Net.Http.Headers;
using System.Xml;
using System.Xml.Linq;

namespace BrotliScan.AppService;

/// <summary>
/// Downloads a Flex Consumption function app's deployment packages from its blob container, with an
/// Entra token from the Azure CLI. The caller needs Storage Blob Data Reader; account keys are never used.
/// </summary>
internal sealed class BlobDownloader(ITokenSource tokens, HttpMessageHandler? handler = null) : IDisposable
{
    private const string StorageApiVersion = "2023-11-03";
    private const string BlobDomain = ".blob.core.windows.net";

    private static readonly XmlReaderSettings XmlSettings = new() { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null };

    private readonly HttpClient _http = SafeHttp.Create(handler);

    public async Task<IReadOnlyList<string>> DownloadPackagesAsync(Uri container, string subscriptionId, string destinationDir, long maxBytes, CancellationToken cancellationToken)
    {
        if (container.Scheme != Uri.UriSchemeHttps || !container.Host.EndsWith(BlobDomain, StringComparison.OrdinalIgnoreCase)
            || container.AbsolutePath.Trim('/').Contains('/') || !string.IsNullOrEmpty(container.Query))
        {
            throw new AzureScanException($"Refusing to send credentials to '{container.GetLeftPart(UriPartial.Path)}': not an Azure blob container URL.");
        }

        string containerUrl = container.GetLeftPart(UriPartial.Path).TrimEnd('/');
        var packages = new List<string>();
        long total = 0;
        string? marker = null;
        do
        {
            string listUrl = $"{containerUrl}?restype=container&comp=list" + (marker is null ? "" : "&marker=" + Uri.EscapeDataString(marker));
            using var listResponse = await SendAsync(listUrl, subscriptionId, cancellationToken);
            await using var listStream = await listResponse.Content.ReadAsStreamAsync(cancellationToken);
            using var reader = XmlReader.Create(listStream, XmlSettings);
            var results = XDocument.Load(reader).Root;

            foreach (var blob in results?.Element("Blobs")?.Elements("Blob") ?? [])
            {
                string? name = blob.Element("Name")?.Value;
                if (name is null || !name.EndsWith(".zip", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                total += long.TryParse(blob.Element("Properties")?.Element("Content-Length")?.Value, out long length) ? length : 0;
                if (total > maxBytes)
                {
                    throw new AzureScanException($"Deployment packages are over the {maxBytes / (1 << 20):N0} MB limit (--azure-max-download-mb).");
                }

                string escaped = string.Join('/', name.Split('/').Select(Uri.EscapeDataString));
                string file = Path.Combine(destinationDir, $"package-{packages.Count}.zip");
                using var blobResponse = await SendAsync($"{containerUrl}/{escaped}", subscriptionId, cancellationToken);
                await using var source = await blobResponse.Content.ReadAsStreamAsync(cancellationToken);
                await using var output = new FileStream(file, FileMode.CreateNew, FileAccess.Write, FileShare.None);
                await CopyBoundedAsync(source, output, maxBytes, cancellationToken);
                packages.Add(file);
            }

            marker = results?.Element("NextMarker")?.Value is { Length: > 0 } next ? next : null;
        }
        while (marker is not null);

        return packages;
    }

    private async Task<HttpResponseMessage> SendAsync(string url, string subscriptionId, CancellationToken cancellationToken)
    {
        string token = await tokens.GetTokenAsync(AzCli.StorageResource, subscriptionId, cancellationToken);
        using var request = new HttpRequestMessage(HttpMethod.Get, url);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        request.Headers.Add("x-ms-version", StorageApiVersion);
        var response = await _http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
        if (response.IsSuccessStatusCode)
        {
            return response;
        }

        int status = (int)response.StatusCode;
        response.Dispose();
        throw new AzureScanException(status is 401 or 403
            ? $"Blob storage returned {status}: your identity needs Storage Blob Data Reader on the deployment storage account."
            : $"Blob storage returned {status}.");
    }

    private static async Task CopyBoundedAsync(Stream source, Stream destination, long maxBytes, CancellationToken cancellationToken)
    {
        var buffer = new byte[81920];
        long total = 0;
        int read;
        while ((read = await source.ReadAsync(buffer, cancellationToken)) > 0)
        {
            total += read;
            if (total > maxBytes)
            {
                throw new AzureScanException($"Deployment package is over the {maxBytes / (1 << 20):N0} MB limit (--azure-max-download-mb).");
            }

            await destination.WriteAsync(buffer.AsMemory(0, read), cancellationToken);
        }
    }

    public void Dispose() => _http.Dispose();
}
