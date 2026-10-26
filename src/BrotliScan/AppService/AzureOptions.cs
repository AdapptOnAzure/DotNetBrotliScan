namespace BrotliScan.AppService;

internal sealed class AzureOptions
{
    /// <summary>Scan the Azure CLI's current subscription.</summary>
    public bool UseCurrentSubscription { get; set; }

    /// <summary>Scan every enabled subscription the Azure CLI login can see.</summary>
    public bool AllSubscriptions { get; set; }

    public List<string> Subscriptions { get; } = [];
    public List<string> ResourceGroups { get; } = [];
    public List<string> AppNames { get; } = [];
    public List<string> ResourceIds { get; } = [];
    public bool IncludeSlots { get; set; }
    public long MaxDownloadBytes { get; set; } = 2L << 30;

    /// <summary>Extra Kudu domain suffixes to trust, for App Service Environments with a custom DNS suffix.</summary>
    public List<string> ExtraScmDomains { get; } = [];

    public bool Enabled => UseCurrentSubscription || AllSubscriptions || Subscriptions.Count > 0 || ResourceIds.Count > 0;
}
