using System.Net;
using System.Net.Http.Headers;
using System.Runtime.CompilerServices;
using System.Text.Json;

namespace BrotliScan.AppService;

/// <summary>Minimal read-only Azure Resource Manager client, authenticated with Azure CLI tokens.</summary>
internal sealed class ArmRestClient(ITokenSource tokens, HttpMessageHandler? handler = null) : IDisposable
{
    public const string Endpoint = "https://management.azure.com";
    private const string ApiVersion = "2024-04-01";

    private readonly HttpClient _http = SafeHttp.Create(handler);

    /// <summary>Lists a collection, following nextLink paging.</summary>
    public async IAsyncEnumerable<JsonElement> ListAsync(string path, string subscriptionId, [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        string? url = $"{Endpoint}{path}?api-version={ApiVersion}";
        while (url is not null)
        {
            using var document = await GetJsonAsync(url, subscriptionId, cancellationToken);
            if (document.RootElement.TryGetProperty("value", out var items) && items.ValueKind == JsonValueKind.Array)
            {
                foreach (var item in items.EnumerateArray())
                {
                    yield return item.Clone();
                }
            }

            url = document.RootElement.TryGetProperty("nextLink", out var next) && next.GetString() is { } link
                ? (link.StartsWith(Endpoint + "/", StringComparison.OrdinalIgnoreCase) ? link : throw new AzureScanException($"Unexpected ARM paging link host: {link}"))
                : null;
        }
    }

    public async Task<JsonElement> GetAsync(string resourceId, string subscriptionId, CancellationToken cancellationToken)
    {
        using var document = await GetJsonAsync($"{Endpoint}{resourceId}?api-version={ApiVersion}", subscriptionId, cancellationToken);
        return document.RootElement.Clone();
    }

    private async Task<JsonDocument> GetJsonAsync(string url, string subscriptionId, CancellationToken cancellationToken)
    {
        string token = await tokens.GetTokenAsync(AzCli.ArmResource, subscriptionId, cancellationToken);
        using var request = new HttpRequestMessage(HttpMethod.Get, url);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        using var response = await _http.SendAsync(request, cancellationToken);
        if (!response.IsSuccessStatusCode)
        {
            throw new AzureScanException(response.StatusCode switch
            {
                HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden => $"Azure Resource Manager returned {(int)response.StatusCode}: the Azure CLI identity needs Reader on the subscription or resource group.",
                HttpStatusCode.NotFound => $"Not found in Azure Resource Manager: {new Uri(url).AbsolutePath}",
                _ => $"Azure Resource Manager returned {(int)response.StatusCode} for {new Uri(url).AbsolutePath}.",
            });
        }

        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken);
        return await JsonDocument.ParseAsync(stream, new JsonDocumentOptions { MaxDepth = 64 }, cancellationToken);
    }

    public void Dispose() => _http.Dispose();
}
