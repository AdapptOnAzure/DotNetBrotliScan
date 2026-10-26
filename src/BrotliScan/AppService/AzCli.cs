using System.Collections.Concurrent;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace BrotliScan.AppService;

internal sealed class AzCliException(string message) : Exception(message);

internal interface ITokenSource
{
    /// <summary>Returns a bearer token for <paramref name="resource"/>, issued in the subscription's tenant.</summary>
    Task<string> GetTokenAsync(string resource, string subscriptionId, CancellationToken cancellationToken);
}

/// <summary>
/// Uses the Azure CLI on this machine as the identity: whoever ran 'az login' (or the CLI's managed or
/// federated identity in CI). Only fixed arguments and validated GUIDs reach the command line, because on
/// Windows 'az' is a batch file and its arguments pass through cmd.exe.
/// </summary>
internal sealed partial class AzCli : ITokenSource, IDisposable
{
    public const string ArmResource = "https://management.azure.com/";
    public const string StorageResource = "https://storage.azure.com/";

    private static readonly TimeSpan CommandTimeout = TimeSpan.FromMinutes(2);
    private static readonly TimeSpan RefreshMargin = TimeSpan.FromMinutes(5);

    private readonly string _executable;
    private readonly ConcurrentDictionary<(string Resource, string Subscription), (string Token, DateTimeOffset Expires)> _tokens = new();
    private readonly SemaphoreSlim _tokenLock = new(1, 1);

    private AzCli(string executable) => _executable = executable;

    public void Dispose() => _tokenLock.Dispose();

    public static AzCli Locate()
    {
        string name = RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? "az.cmd" : "az";
        foreach (string dir in (Environment.GetEnvironmentVariable("PATH") ?? "").Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries))
        {
            string candidate = Path.Combine(dir.Trim('"'), name);
            if (File.Exists(candidate))
            {
                return new AzCli(candidate);
            }
        }

        string install = OperatingSystem.IsWindows() ? "winget install -e --id Microsoft.AzureCLI"
            : OperatingSystem.IsMacOS() ? "brew install azure-cli"
            : "see https://aka.ms/azure-cli";
        throw new AzCliException($"The Azure CLI isn't installed (or isn't on PATH). Install it ({install}), run 'az login', then try again.");
    }

    public sealed record Account(string SubscriptionId, string TenantId, string User, string Cloud, bool Enabled);

    public async Task<Account> GetCurrentAccountAsync(CancellationToken cancellationToken)
    {
        using var document = await RunJsonAsync(["account", "show", "--output", "json"], cancellationToken);
        return ParseAccount(document.RootElement);
    }

    public async Task<IReadOnlyList<Account>> ListAccountsAsync(CancellationToken cancellationToken)
    {
        using var document = await RunJsonAsync(["account", "list", "--output", "json"], cancellationToken);
        return document.RootElement.EnumerateArray().Select(ParseAccount).ToList();
    }

    public async Task<string> GetTokenAsync(string resource, string subscriptionId, CancellationToken cancellationToken)
    {
        if (resource is not (ArmResource or StorageResource))
        {
            throw new ArgumentOutOfRangeException(nameof(resource));
        }

        string subscription = ValidateSubscription(subscriptionId);
        var key = (resource, subscription);
        if (_tokens.TryGetValue(key, out var cached) && cached.Expires - RefreshMargin > DateTimeOffset.UtcNow)
        {
            return cached.Token;
        }

        // One az process at a time; parallel site scans would otherwise each start their own.
        await _tokenLock.WaitAsync(cancellationToken);
        try
        {
            if (_tokens.TryGetValue(key, out cached) && cached.Expires - RefreshMargin > DateTimeOffset.UtcNow)
            {
                return cached.Token;
            }

            using var document = await RunJsonAsync(
                ["account", "get-access-token", "--resource", resource, "--subscription", subscription, "--output", "json"],
                cancellationToken);
            var root = document.RootElement;
            string token = root.GetProperty("accessToken").GetString()
                ?? throw new AzCliException("Azure CLI returned no access token.");
            var expires = root.TryGetProperty("expires_on", out var epoch) && epoch.ValueKind == JsonValueKind.Number
                ? DateTimeOffset.FromUnixTimeSeconds(epoch.GetInt64())
                : DateTimeOffset.UtcNow.AddMinutes(30);
            _tokens[key] = (token, expires);
            return token;
        }
        finally
        {
            _tokenLock.Release();
        }
    }

    public static string ValidateSubscription(string value) =>
        Guid.TryParse(value, out var id) ? id.ToString("D") : throw new AzCliException($"'{value}' isn't a subscription ID (GUID).");

    private static Account ParseAccount(JsonElement e) => new(
        e.GetProperty("id").GetString() ?? "",
        e.TryGetProperty("tenantId", out var tenant) ? tenant.GetString() ?? "" : "",
        e.TryGetProperty("user", out var user) && user.TryGetProperty("name", out var name) ? name.GetString() ?? "" : "",
        e.TryGetProperty("environmentName", out var cloud) ? cloud.GetString() ?? "" : "",
        !e.TryGetProperty("state", out var state) || state.GetString() == "Enabled");

    [GeneratedRegex(@"^[A-Za-z0-9._:/\-]+$")]
    private static partial Regex SafeArgument();

    private async Task<JsonDocument> RunJsonAsync(IReadOnlyList<string> arguments, CancellationToken cancellationToken)
    {
        // Defence in depth for the cmd.exe concern above: nothing outside this set ever reaches az.
        if (arguments.FirstOrDefault(a => !SafeArgument().IsMatch(a)) is { } unsafeArgument)
        {
            throw new AzCliException($"Refusing to pass '{unsafeArgument}' to the Azure CLI.");
        }

        var start = new ProcessStartInfo(_executable)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        };
        foreach (string argument in arguments)
        {
            start.ArgumentList.Add(argument);
        }

        start.Environment["AZURE_CORE_ONLY_SHOW_ERRORS"] = "true";
        start.Environment["AZURE_CORE_NO_COLOR"] = "true";

        using var process = Process.Start(start) ?? throw new AzCliException("Couldn't start the Azure CLI.");
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(CommandTimeout);
        var stdout = process.StandardOutput.ReadToEndAsync(timeout.Token);
        var stderr = process.StandardError.ReadToEndAsync(timeout.Token);
        try
        {
            await process.WaitForExitAsync(timeout.Token);
        }
        catch (OperationCanceledException)
        {
            process.Kill(entireProcessTree: true);
            throw new AzCliException($"'az {arguments[0]} {arguments[1]}' timed out.");
        }

        if (process.ExitCode != 0)
        {
            string error = (await stderr).Trim();
            if (error.Contains("az login", StringComparison.OrdinalIgnoreCase) || error.Contains("AADSTS", StringComparison.Ordinal))
            {
                throw new AzCliException($"Azure CLI isn't logged in or the login expired; run 'az login'. ({FirstLine(error)})");
            }

            throw new AzCliException($"'az {arguments[0]} {arguments[1]}' failed: {FirstLine(error)}");
        }

        try
        {
            return JsonDocument.Parse(await stdout);
        }
        catch (JsonException)
        {
            throw new AzCliException($"'az {arguments[0]} {arguments[1]}' returned output that isn't JSON.");
        }
    }

    private static string FirstLine(string text) => text.Split('\n', 2)[0].Trim();
}
