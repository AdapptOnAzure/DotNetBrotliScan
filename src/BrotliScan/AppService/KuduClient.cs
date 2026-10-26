using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;

namespace BrotliScan.AppService;

internal sealed class AzureScanException(string message) : Exception(message);

/// <summary>
/// Reads deployed files through the Kudu (SCM) API with a Microsoft Entra token from the Azure CLI, which works
/// when SCM basic auth is disabled. The caller needs Microsoft.Web/sites/publish/Action (e.g. Website Contributor).
/// </summary>
internal sealed class KuduClient : IDisposable
{
    // An ARM token is powerful, so it's only ever sent to App Service hosts.
    private static readonly string[] DefaultDomains = [".azurewebsites.net", ".appserviceenvironment.net"];

    private readonly HttpClient _http;
    private readonly ITokenSource _tokens;
    private readonly string[] _trustedDomains;

    public KuduClient(ITokenSource tokens, IEnumerable<string> extraDomains, HttpMessageHandler? handler = null)
    {
        _tokens = tokens;
        _trustedDomains = [.. DefaultDomains, .. extraDomains.Select(d => d.StartsWith('.') ? d : "." + d)];
        _http = SafeHttp.Create(handler);
    }

    /// <summary>Streams a zip of site/wwwroot to <paramref name="destinationFile"/>.</summary>
    public async Task DownloadWwwrootAsync(AzureSite site, string destinationFile, long maxBytes, CancellationToken cancellationToken)
    {
        using var response = await SendAsync(site, "/api/zip/site/wwwroot/", cancellationToken);
        if (response.Content.Headers.ContentLength > maxBytes)
        {
            throw new AzureScanException($"site/wwwroot is {response.Content.Headers.ContentLength / (1 << 20):N0} MB, over the {maxBytes / (1 << 20):N0} MB limit (--azure-max-download-mb).");
        }

        await using var source = await response.Content.ReadAsStreamAsync(cancellationToken);
        await using var file = new FileStream(destinationFile, FileMode.CreateNew, FileAccess.Write, FileShare.None);
        var buffer = new byte[81920];
        long total = 0;
        int read;
        while ((read = await source.ReadAsync(buffer, cancellationToken)) > 0)
        {
            total += read;
            if (total > maxBytes)
            {
                throw new AzureScanException($"site/wwwroot is over the {maxBytes / (1 << 20):N0} MB limit (--azure-max-download-mb).");
            }

            await file.WriteAsync(buffer.AsMemory(0, read), cancellationToken);
        }
    }

    /// <summary>Lists the subdirectories of a Kudu VFS path, or returns empty when it doesn't exist.</summary>
    public async Task<IReadOnlyList<string>> ListDirectoriesAsync(AzureSite site, string vfsPath, CancellationToken cancellationToken)
    {
        using var response = await SendAsync(site, "/api/vfs/" + vfsPath.TrimEnd('/') + "/", cancellationToken, allowNotFound: true);
        if (response.StatusCode == HttpStatusCode.NotFound)
        {
            return [];
        }

        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken);
        using var document = await JsonDocument.ParseAsync(stream, new JsonDocumentOptions { MaxDepth = 8 }, cancellationToken);
        if (document.RootElement.ValueKind != JsonValueKind.Array)
        {
            return [];
        }

        return document.RootElement.EnumerateArray()
            .Where(e => e.TryGetProperty("mime", out var mime) && mime.GetString() == "inode/directory")
            .Select(e => e.TryGetProperty("name", out var name) ? name.GetString() : null)
            .OfType<string>()
            .ToList();
    }

    /// <summary>Reads a file through the Kudu VFS, or returns null when it doesn't exist.</summary>
    public async Task<MemoryStream?> ReadFileAsync(AzureSite site, string vfsPath, long maxBytes, CancellationToken cancellationToken)
    {
        using var response = await SendAsync(site, "/api/vfs/" + vfsPath, cancellationToken, allowNotFound: true);
        if (response.StatusCode == HttpStatusCode.NotFound)
        {
            return null;
        }

        if (response.Content.Headers.ContentLength > maxBytes)
        {
            throw new AzureScanException($"{vfsPath} is over the size limit.");
        }

        var buffer = new MemoryStream();
        await using var source = await response.Content.ReadAsStreamAsync(cancellationToken);
        await source.CopyToAsync(buffer, cancellationToken);
        buffer.Position = 0;
        return buffer;
    }

    public bool IsTrustedHost(string host) =>
        Uri.CheckHostName(host) == UriHostNameType.Dns
        && host.Contains(".scm.", StringComparison.OrdinalIgnoreCase)
        && _trustedDomains.Any(d => host.EndsWith(d, StringComparison.OrdinalIgnoreCase));

    private async Task<HttpResponseMessage> SendAsync(AzureSite site, string path, CancellationToken cancellationToken, bool allowNotFound = false)
    {
        string scmHost = site.ScmHost ?? throw new AzureScanException("The app has no Kudu (SCM) endpoint.");
        if (!IsTrustedHost(scmHost))
        {
            throw new AzureScanException($"Refusing to send credentials to '{scmHost}': not an App Service Kudu host. Add its domain with --azure-scm-domain if it's an App Service Environment.");
        }

        // Kudu accepts Azure Resource Manager tokens.
        string token = await _tokens.GetTokenAsync(AzCli.ArmResource, site.SubscriptionId, cancellationToken);
        using var request = new HttpRequestMessage(HttpMethod.Get, new UriBuilder(Uri.UriSchemeHttps, scmHost) { Path = path }.Uri);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);

        var response = await _http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
        if (response.IsSuccessStatusCode || (allowNotFound && response.StatusCode == HttpStatusCode.NotFound))
        {
            return response;
        }

        var status = response.StatusCode;
        response.Dispose();
        throw new AzureScanException(status switch
        {
            HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden =>
                $"Kudu returned {(int)status}: your identity needs Microsoft.Web/sites/publish/Action on the app (e.g. Website Contributor), and the SCM site must allow Entra ID access.",
            _ when (int)status is >= 300 and < 400 => $"Kudu redirected ({(int)status}); not followed, so credentials aren't sent elsewhere.",
            _ => $"Kudu returned {(int)status} for {path}.",
        });
    }

    public void Dispose() => _http.Dispose();
}
