using System.Text.Json;
using System.Text.RegularExpressions;

namespace BrotliScan.AppService;

/// <summary>Finds the App Service and Functions apps (and optionally slots) the options select.</summary>
internal static partial class SiteDiscovery
{
    [GeneratedRegex(@"^/subscriptions/[0-9a-fA-F-]{36}/resourceGroups/[-\w.()]{1,90}/providers/Microsoft\.Web/sites/[A-Za-z0-9-]{1,60}(/slots/[A-Za-z0-9-]{1,59})?$", RegexOptions.IgnoreCase)]
    public static partial Regex SiteResourceId();

    [GeneratedRegex(@"^[-\w.()]{1,90}$")]
    public static partial Regex ResourceGroupName();

    [GeneratedRegex(@"^[A-Za-z0-9-]{1,60}$")]
    public static partial Regex AppName();

    public static async Task<IReadOnlyList<AzureSite>> FindAsync(
        ArmRestClient arm, AzureOptions options, IReadOnlyList<string> subscriptions, List<string> errors, CancellationToken cancellationToken)
    {
        var ids = new List<string>(options.ResourceIds);

        foreach (string subscription in subscriptions)
        {
            var scopes = options.ResourceGroups.Count == 0
                ? [$"/subscriptions/{subscription}"]
                : options.ResourceGroups.Select(rg => $"/subscriptions/{subscription}/resourceGroups/{rg}").ToList();

            foreach (string scope in scopes)
            {
                try
                {
                    await foreach (var site in arm.ListAsync($"{scope}/providers/Microsoft.Web/sites", subscription, cancellationToken))
                    {
                        string? id = site.TryGetProperty("id", out var value) ? value.GetString() : null;
                        string? name = site.TryGetProperty("name", out var n) ? n.GetString() : null;
                        if (id is null || (options.AppNames.Count > 0 && !options.AppNames.Contains(name ?? "", StringComparer.OrdinalIgnoreCase)))
                        {
                            continue;
                        }

                        ids.Add(id);
                        if (options.IncludeSlots)
                        {
                            await foreach (var slot in arm.ListAsync($"{id}/slots", subscription, cancellationToken))
                            {
                                if (slot.TryGetProperty("id", out var slotId) && slotId.GetString() is { } s)
                                {
                                    ids.Add(s);
                                }
                            }
                        }
                    }
                }
                catch (AzureScanException ex)
                {
                    errors.Add($"{scope}: {ex.Message}");
                }
            }
        }

        var sites = new List<AzureSite>();
        foreach (string id in ids.Distinct(StringComparer.OrdinalIgnoreCase))
        {
            // Resource IDs end up in URLs; only well-formed site IDs are used.
            if (!SiteResourceId().IsMatch(id))
            {
                errors.Add($"{id}: not a Microsoft.Web/sites resource ID; skipped.");
                continue;
            }

            try
            {
                var resource = await arm.GetAsync(id, AzureSiteId.Subscription(id), cancellationToken);
                string? kind = resource.TryGetProperty("kind", out var k) ? k.GetString() : null;
                var properties = resource.TryGetProperty("properties", out var p) ? p : default;
                sites.Add(AzureSite.FromProperties(id, AzureSiteId.Label(id), kind, properties.ValueKind == JsonValueKind.Object ? properties : JsonDocument.Parse("{}").RootElement));
            }
            catch (AzureScanException ex)
            {
                errors.Add($"{id}: {ex.Message}");
            }
        }

        return sites;
    }
}

internal static class AzureSiteId
{
    public static string Subscription(string id) => id.Split('/', StringSplitOptions.RemoveEmptyEntries)[1];

    /// <summary>resource-group/site or resource-group/site/slots/slot.</summary>
    public static string Label(string id)
    {
        var parts = id.Split('/', StringSplitOptions.RemoveEmptyEntries);
        return parts.Length >= 10 ? $"{parts[3]}/{parts[7]}/slots/{parts[9]}" : $"{parts[3]}/{parts[7]}";
    }
}
