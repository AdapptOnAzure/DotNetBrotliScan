using System.Text.Json;

namespace BrotliScan.AppService;

/// <param name="Label">resource-group/site, or resource-group/site/slots/slot.</param>
/// <param name="ScmHost">Kudu host from the site's Repository host name; null when the site has none.</param>
/// <param name="ContainerImage">Set for apps deployed as a container image, whose files aren't in wwwroot.</param>
/// <param name="FlexDeploymentContainer">Blob container holding a Flex Consumption app's deployment package.</param>
internal sealed record AzureSite(
    string ResourceId,
    string Label,
    string Kind,
    string? ScmHost,
    bool IsLinux,
    string? ContainerImage,
    Uri? FlexDeploymentContainer)
{
    public string SubscriptionId => ResourceId.Split('/', StringSplitOptions.RemoveEmptyEntries)[1];

    public bool IsFunctionApp => Kind.Contains("functionapp", StringComparison.OrdinalIgnoreCase);

    public string TargetKind => IsFunctionApp ? "azure function app" : "azure web app";

    /// <summary>Builds a site from the "properties" object of a Microsoft.Web/sites (or sites/slots) resource.</summary>
    public static AzureSite FromProperties(string resourceId, string label, string? kind, JsonElement properties)
    {
        kind ??= "";
        string? scmHost = null;
        if (properties.TryGetProperty("hostNameSslStates", out var hosts) && hosts.ValueKind == JsonValueKind.Array)
        {
            scmHost = hosts.EnumerateArray()
                .Where(h => h.TryGetProperty("hostType", out var t) && t.ValueKind == JsonValueKind.String && t.GetString() == "Repository")
                .Select(h => h.TryGetProperty("name", out var n) ? n.GetString() : null)
                .FirstOrDefault(n => !string.IsNullOrEmpty(n));
        }

        bool linux = kind.Contains("linux", StringComparison.OrdinalIgnoreCase)
            || (properties.TryGetProperty("reserved", out var reserved) && reserved.ValueKind == JsonValueKind.True);

        string? fx = properties.TryGetProperty("siteConfig", out var config) && config.ValueKind == JsonValueKind.Object
            && config.TryGetProperty("linuxFxVersion", out var fxValue) && fxValue.ValueKind == JsonValueKind.String
            ? fxValue.GetString()
            : null;
        string? image = fx switch
        {
            not null when fx.StartsWith("DOCKER|", StringComparison.OrdinalIgnoreCase) => fx["DOCKER|".Length..],
            not null when fx.StartsWith("COMPOSE|", StringComparison.OrdinalIgnoreCase) => "docker compose",
            not null when fx.Equals("SITECONTAINERS", StringComparison.OrdinalIgnoreCase) => "sidecar containers",
            _ when kind.Contains("container", StringComparison.OrdinalIgnoreCase) => "container",
            _ => null,
        };

        Uri? flex = null;
        if (properties.TryGetProperty("functionAppConfig", out var functionConfig) && functionConfig.ValueKind == JsonValueKind.Object
            && functionConfig.TryGetProperty("deployment", out var deployment) && deployment.ValueKind == JsonValueKind.Object
            && deployment.TryGetProperty("storage", out var storage) && storage.ValueKind == JsonValueKind.Object
            && storage.TryGetProperty("value", out var url) && url.ValueKind == JsonValueKind.String
            && Uri.TryCreate(url.GetString(), UriKind.Absolute, out var parsed))
        {
            flex = parsed;
        }

        return new AzureSite(resourceId, label, kind, scmHost, linux, image, flex);
    }
}
