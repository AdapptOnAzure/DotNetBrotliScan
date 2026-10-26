using System.Diagnostics;
using System.Runtime.InteropServices;
using BrotliScan.AppService;

namespace BrotliScan;

internal static partial class Program
{
    private const int ExitClean = 0, ExitAffected = 1, ExitReview = 2, ExitUsage = 64;

    private const string Usage = """
        Usage: brotli-scan [options] [path ...]

          brotli-scan                      Scan the current folder and this machine's .NET installs
          brotli-scan C:\src\myapp         Scan a source tree, build output or publish folder
          brotli-scan --azure              Scan your Azure App Service and Functions apps (after 'az login')

        Flags .NET projects, compiled apps and runtimes affected by CVE-2026-111497, the brotli
        decoder flaw fixed upstream in google/brotli 0ed4268a (brotli 1.0.10, 1.1.1 and 1.2.1).

        An app is affected when it decodes brotli it doesn't control (request decompression,
        HttpClient automatic decompression, or BrotliStream/BrotliDecoder) on a decoder without
        the fix. Response compression uses the encoder and isn't affected.

        Paths can be source trees, build output, publish folders or single files. Without a path,
        the current directory is scanned. Nothing scanned is loaded or executed.

        Options:
          --no-host        Don't inspect this machine's .NET runtimes, packs and NuGet cache
          --host-only      Inspect only this machine's .NET installs
          --json           Print the report as JSON instead of text
          --output <file>  Also write the JSON report to <file>
          --include-obj    Also scan obj/ folders (skipped by default as intermediate output)
          --max-file-mb <n> Skip files larger than <n> MB (default 1024)
          --verbose        List every decoder, finding and unreadable file
          -h, --help       Show this help

        Azure App Service and Functions (uses your Azure CLI login; run 'az login' first):
          --azure                        Scan apps in the Azure CLI's current subscription
          --azure-subscription <id>      Scan apps in this subscription (repeatable)
          --azure-all-subscriptions      Scan apps in every enabled subscription you can see
          --azure-resource-group <name>  Only apps in this resource group (repeatable)
          --azure-app <name>             Only apps with this name (repeatable)
          --azure-resource <id>          Scan this app or slot by resource ID (repeatable)
          --azure-slots                  Include deployment slots
          --azure-max-download-mb <n>    Per-app download limit (default 2048)
          --azure-scm-domain <suffix>    Also trust this Kudu domain (App Service Environment, custom DNS)

          Deployed files are downloaded through Kudu with your Entra login, scanned in a private
          temp folder, and deleted. Needs Reader to find apps and Website Contributor (or
          Microsoft.Web/sites/publish/Action) to download them; Flex Consumption apps also need
          Storage Blob Data Reader on their deployment storage. No keys or passwords are used.

        Exit codes: 0 nothing affected or to review, 1 affected or likely affected found,
                    2 only items to review, 64 bad arguments.
        """;

    public static async Task<int> Main(string[] args)
    {
        // Double-clicked on Windows: there's no folder to scan and the window would close at once,
        // so check this machine and wait for Enter.
        if (args.Length == 0 && OwnsConsoleWindow())
        {
            int code = await RunAsync(["--host-only"]);
            Console.WriteLine();
            Console.Write("Press Enter to close.");
            Console.ReadLine();
            return code;
        }

        return await RunAsync(args);
    }

    private static async Task<int> RunAsync(string[] args)
    {
        var options = new ScanOptions();
        var azure = new AzureOptions();
        bool json = false, verbose = false, hostOnly = false;
        string? outputFile = null;

        for (int i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "-h" or "--help" or "-?":
                    Console.WriteLine(Usage);
                    return ExitClean;
                case "--no-host":
                    options.IncludeHost = false;
                    break;
                case "--host-only":
                    hostOnly = true;
                    break;
                case "--json":
                    json = true;
                    break;
                case "--verbose" or "-v":
                    verbose = true;
                    break;
                case "--include-obj":
                    options.IncludeObj = true;
                    break;
                case "--output" when i + 1 < args.Length:
                    outputFile = args[++i];
                    break;
                case "--max-file-mb" when i + 1 < args.Length && long.TryParse(args[i + 1], out long mb) && mb > 0:
                    options.MaxFileBytes = mb << 20;
                    i++;
                    break;
                case "--azure":
                    azure.UseCurrentSubscription = true;
                    break;
                case "--azure-all-subscriptions":
                    azure.AllSubscriptions = true;
                    break;
                case "--azure-slots":
                    azure.IncludeSlots = true;
                    break;
                case "--azure-subscription" when i + 1 < args.Length && Guid.TryParse(args[i + 1], out var subscription):
                    azure.Subscriptions.Add(subscription.ToString("D"));
                    i++;
                    break;
                case "--azure-resource-group" when i + 1 < args.Length && SiteDiscovery.ResourceGroupName().IsMatch(args[i + 1]):
                    azure.ResourceGroups.Add(args[++i]);
                    break;
                case "--azure-app" when i + 1 < args.Length && SiteDiscovery.AppName().IsMatch(args[i + 1]):
                    azure.AppNames.Add(args[++i]);
                    break;
                case "--azure-resource" when i + 1 < args.Length && SiteDiscovery.SiteResourceId().IsMatch(args[i + 1]):
                    azure.ResourceIds.Add(args[++i]);
                    break;
                case "--azure-max-download-mb" when i + 1 < args.Length && long.TryParse(args[i + 1], out long downloadMb) && downloadMb > 0:
                    azure.MaxDownloadBytes = downloadMb << 20;
                    i++;
                    break;
                case "--azure-scm-domain" when i + 1 < args.Length && Uri.CheckHostName(args[i + 1].TrimStart('.')) == UriHostNameType.Dns && args[i + 1].Contains('.'):
                    azure.ExtraScmDomains.Add(args[++i]);
                    break;
                case var arg when arg.StartsWith("--azure-", StringComparison.Ordinal) && i + 1 < args.Length:
                    Console.Error.WriteLine($"Invalid value for {arg}: '{args[i + 1]}'. Subscriptions are GUIDs, resource IDs are Microsoft.Web/sites (or slots) IDs, and app and group names are Azure resource names.");
                    return ExitUsage;
                case var arg when arg.StartsWith('-'):
                    Console.Error.WriteLine($"Unknown or incomplete option: {arg}\n");
                    Console.Error.WriteLine(Usage);
                    return ExitUsage;
                case var path:
                    if (!File.Exists(path) && !Directory.Exists(path))
                    {
                        Console.Error.WriteLine($"Path not found: {path}");
                        return ExitUsage;
                    }

                    options.Paths.Add(path);
                    break;
            }
        }

        if (hostOnly && (options.Paths.Count > 0 || !options.IncludeHost))
        {
            Console.Error.WriteLine("--host-only can't be combined with paths or --no-host.");
            return ExitUsage;
        }

        if ((azure.ResourceGroups.Count > 0 || azure.AppNames.Count > 0)
            && !(azure.UseCurrentSubscription || azure.AllSubscriptions || azure.Subscriptions.Count > 0))
        {
            Console.Error.WriteLine("--azure-resource-group and --azure-app need --azure, --azure-subscription or --azure-all-subscriptions.");
            return ExitUsage;
        }

        // An Azure-only run doesn't also scan the current directory.
        if (!hostOnly && options.Paths.Count == 0 && !azure.Enabled)
        {
            options.Paths.Add(Directory.GetCurrentDirectory());
        }

        var stopwatch = Stopwatch.StartNew();
        var report = new Scanner(options).Run();

        if (azure.Enabled)
        {
            try
            {
                report = await ScanAzureAsync(azure, report);
            }
            catch (AzCliException ex)
            {
                Console.Error.WriteLine(ex.Message);
                return ExitUsage;
            }
        }

        if (outputFile is not null)
        {
            File.WriteAllText(outputFile, Reporter.ToJson(report));
        }

        if (json)
        {
            Console.WriteLine(Reporter.ToJson(report));
        }
        else
        {
            bool color = !Console.IsOutputRedirected && Environment.GetEnvironmentVariable("NO_COLOR") is null;
            new Reporter(Console.Out, report.Roots, color, verbose).WriteText(report, stopwatch.Elapsed);
        }

        if (report.Targets.Any(t => t.Verdict is Verdict.Affected or Verdict.LikelyAffected))
        {
            return ExitAffected;
        }

        return report.Targets.Any(t => t.Verdict == Verdict.Review) ? ExitReview : ExitClean;
    }

    private static async Task<ScanReport> ScanAzureAsync(AzureOptions azure, ScanReport local)
    {
        using var cli = AzCli.Locate();
        var current = await cli.GetCurrentAccountAsync(CancellationToken.None);
        if (!current.Cloud.Equals("AzureCloud", StringComparison.OrdinalIgnoreCase))
        {
            throw new AzCliException($"The Azure CLI is set to '{current.Cloud}'; only the public cloud (AzureCloud) is supported.");
        }

        var subscriptions = new List<string>(azure.Subscriptions);
        if (azure.UseCurrentSubscription)
        {
            subscriptions.Add(current.SubscriptionId);
        }

        if (azure.AllSubscriptions)
        {
            subscriptions.AddRange((await cli.ListAccountsAsync(CancellationToken.None)).Where(a => a.Enabled).Select(a => a.SubscriptionId));
        }

        subscriptions = subscriptions.Select(AzCli.ValidateSubscription).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        Console.Error.WriteLine($"Scanning Azure as {current.User} ({subscriptions.Count} subscription(s){(azure.ResourceIds.Count > 0 ? $", {azure.ResourceIds.Count} resource(s)" : "")})...");

        var result = await new AppServiceScanner(azure, cli).ScanAsync(subscriptions, CancellationToken.None);
        return local with
        {
            Roots = [.. local.Roots, .. subscriptions.Select(s => $"azure:/subscriptions/{s}"), .. azure.ResourceIds.Select(r => "azure:" + r)],
            FilesExamined = local.FilesExamined + result.FilesExamined,
            Components = [.. local.Components, .. result.Components],
            Targets = [.. local.Targets.Concat(result.Targets).OrderBy(t => t.Verdict).ThenBy(t => t.Path, StringComparer.Ordinal)],
            Errors = [.. local.Errors, .. result.Errors],
        };
    }

    /// <summary>True on Windows when this process has its console to itself, i.e. it was started from Explorer.</summary>
    private static bool OwnsConsoleWindow()
    {
        if (!OperatingSystem.IsWindows() || Console.IsInputRedirected || Console.IsOutputRedirected)
        {
            return false;
        }

        var processes = new uint[2];
        return GetConsoleProcessList(processes, (uint)processes.Length) == 1;
    }

    [LibraryImport("kernel32.dll", SetLastError = true)]
    private static partial uint GetConsoleProcessList([Out] uint[] processList, uint processCount);
}
