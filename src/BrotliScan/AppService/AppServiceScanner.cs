using System.Collections.Concurrent;

namespace BrotliScan.AppService;

internal sealed record AzureScanResult(
    IReadOnlyList<TargetReport> Targets,
    IReadOnlyList<ComponentReport> Components,
    IReadOnlyList<string> Errors,
    long FilesExamined);

/// <summary>
/// Downloads each app's deployed files into a private temp folder, scans them like a local publish
/// folder, and deletes them. Nothing downloaded is executed.
/// </summary>
internal sealed class AppServiceScanner(AzureOptions options, ITokenSource tokens, HttpMessageHandler? handler = null)
{
    private const int MaxParallelApps = 4;
    private const long MaxRuntimeLibraryBytes = 64 << 20;

    // Where Windows App Service keeps its .NET runtimes, as Kudu VFS paths.
    private static readonly string[] WindowsRuntimeDirectories =
    [
        "SystemDrive/Program Files/dotnet/shared/Microsoft.NETCore.App",
        "SystemDrive/Program Files (x86)/dotnet/shared/Microsoft.NETCore.App",
    ];

    public async Task<AzureScanResult> ScanAsync(IReadOnlyList<string> subscriptions, CancellationToken cancellationToken)
    {
        using var arm = new ArmRestClient(tokens, handler);
        var errors = new List<string>();
        var sites = await SiteDiscovery.FindAsync(arm, options, subscriptions, errors, cancellationToken);
        var result = await ScanSitesAsync(sites, cancellationToken);
        return result with { Errors = [.. errors, .. result.Errors] };
    }

    internal async Task<AzureScanResult> ScanSitesAsync(IReadOnlyList<AzureSite> sites, CancellationToken cancellationToken)
    {
        using var kudu = new KuduClient(tokens, options.ExtraScmDomains, handler);
        using var blobs = new BlobDownloader(tokens, handler);
        var targets = new ConcurrentBag<TargetReport>();
        var components = new ConcurrentBag<ComponentReport>();
        var errors = new ConcurrentBag<string>();
        long files = 0;

        await Parallel.ForEachAsync(sites, new ParallelOptions { MaxDegreeOfParallelism = MaxParallelApps, CancellationToken = cancellationToken }, async (site, token) =>
        {
            var report = await ScanSiteAsync(site, kudu, blobs, token);
            foreach (var target in report.Targets) targets.Add(target);
            foreach (var component in report.Components) components.Add(component);
            foreach (var error in report.Errors) errors.Add(error);
            Interlocked.Add(ref files, report.FilesExamined);
        });

        return new AzureScanResult([.. targets], [.. components], [.. errors], files);
    }

    private async Task<AzureScanResult> ScanSiteAsync(AzureSite site, KuduClient kudu, BlobDownloader blobs, CancellationToken cancellationToken)
    {
        string label = $"azure:{site.Label}";

        if (site.ContainerImage is { } image)
        {
            return Single(site, Verdict.Review,
                $"deployed as a container image ({image}), so its files aren't in wwwroot. Export the image's filesystem (e.g. docker export) and scan that folder");
        }

        var temp = Directory.CreateTempSubdirectory("brotli-scan-");
        try
        {
            string content = Path.Combine(temp.FullName, "content");
            string runtimeNote;
            if (site.FlexDeploymentContainer is { } container)
            {
                var packages = await blobs.DownloadPackagesAsync(container, site.SubscriptionId, temp.FullName, options.MaxDownloadBytes, cancellationToken);
                if (packages.Count == 0)
                {
                    return Single(site, Verdict.Review, "the Flex Consumption deployment container holds no packages to scan");
                }

                // Normally one package; when there are several, each gets its own folder so results can be told apart.
                for (int i = 0; i < packages.Count; i++)
                {
                    SafeZip.Extract(packages[i], packages.Count == 1 ? content : Path.Combine(content, $"package-{i}"), options.MaxDownloadBytes);
                    File.Delete(packages[i]);
                }

                runtimeNote = "runs on the Functions platform's .NET runtime, which can't be fingerprinted remotely; runtimes without the brotli fix are affected";
            }
            else
            {
                string zip = Path.Combine(temp.FullName, "wwwroot.zip");
                await kudu.DownloadWwwrootAsync(site, zip, options.MaxDownloadBytes, cancellationToken);
                SafeZip.Extract(zip, content, options.MaxDownloadBytes);
                File.Delete(zip);
                runtimeNote = site.IsLinux
                    ? "runs on the App Service Linux platform's .NET runtime, which Kudu can't reach to fingerprint; runtimes without the brotli fix are affected"
                    : "runs on the App Service platform's .NET runtime, which couldn't be read through Kudu; runtimes without the brotli fix are affected";
            }

            var platform = site.IsLinux || site.FlexDeploymentContainer is not null
                ? []
                : await WindowsPlatformRuntimesAsync(site, content, kudu, cancellationToken);

            var scanOptions = new ScanOptions
            {
                IncludeHost = false,
                RuntimeInventory = new HostInventory(platform, [.. platform.Select(r => r.Decoder)]),
                UnknownRuntimeNote = runtimeNote,
                MaxFileBytes = options.MaxDownloadBytes,
            };
            scanOptions.Paths.Add(content);
            var report = new Scanner(scanOptions).Run();

            var targets = report.Targets.Select(t => Relabel(t, content, label, site)).ToList();
            if (targets.Count == 0)
            {
                targets.Add(Single(site, Verdict.NotExposed, $"no .NET app found in the deployed files ({report.FilesExamined:N0} files)").Targets[0]);
            }

            return new AzureScanResult(
                targets,
                report.Components.Select(c => c with { Path = Map(c.Path, content, label) }).ToList(),
                report.Errors.Select(e => Map(e, content, label)).ToList(),
                report.FilesExamined);
        }
        catch (Exception ex) when (ex is AzureScanException or AzCliException or InvalidDataException or IOException or HttpRequestException or UnauthorizedAccessException)
        {
            return Single(site, Verdict.Review, $"couldn't scan: {ex.Message}", error: $"{label}: {ex.Message}");
        }
        finally
        {
            try
            {
                temp.Delete(recursive: true);
            }
            catch (IOException)
            {
            }
        }
    }

    /// <summary>
    /// Fingerprints the platform runtime each framework-dependent app rolls forward to: the highest patch of
    /// the major.minor it targets, read through Kudu's VFS. Windows only; Linux apps run outside Kudu's container.
    /// </summary>
    private static async Task<List<HostRuntime>> WindowsPlatformRuntimesAsync(AzureSite site, string content, KuduClient kudu, CancellationToken cancellationToken)
    {
        var requested = Directory.EnumerateFiles(content, "*.runtimeconfig.json", new EnumerationOptions { RecurseSubdirectories = true, AttributesToSkip = FileAttributes.ReparsePoint })
            .Select(path =>
            {
                using var stream = File.OpenRead(path);
                return ProjectReader.ReadRuntimeConfig(stream);
            })
            .Where(c => c is { SelfContained: false })
            .SelectMany(c => c!.FrameworkVersions)
            .Select(v => Version.TryParse(v.Split('-')[0], out var parsed) ? parsed : null)
            .OfType<Version>()
            .Select(v => (v.Major, v.Minor))
            .Distinct()
            .ToList();

        var runtimes = new List<HostRuntime>();
        foreach (string directory in WindowsRuntimeDirectories)
        {
            var installed = (await kudu.ListDirectoriesAsync(site, directory, cancellationToken))
                .Select(name => (Name: name, Version: Version.TryParse(name.Split('-')[0], out var v) ? v : null))
                .Where(x => x.Version is not null)
                .ToList();

            foreach (var (major, minor) in requested)
            {
                var sameMinor = installed.Where(x => x.Version!.Major == major && x.Version.Minor == minor).ToList();
                var candidates = sameMinor.Count > 0 ? sameMinor : installed.Where(x => x.Version!.Major == major).ToList();
                if (candidates.Count == 0)
                {
                    continue;
                }

                var match = candidates.MaxBy(x => x.Version);

                string file = $"{directory}/{match.Name}/System.IO.Compression.Native.dll";
                using var library = await kudu.ReadFileAsync(site, file, MaxRuntimeLibraryBytes, cancellationToken);
                if (library is not null && NativeScanner.Scan(library).Decoder is { } decoder)
                {
                    runtimes.Add(new HostRuntime(match.Version!, new ComponentReport(
                        "platform-runtime", $"azure:{site.Label}/{file}", $"App Service .NET runtime {match.Name}",
                        decoder.Status, decoder.Evidence, decoder.VersionStamp)));
                }
            }
        }

        return runtimes;
    }

    private static TargetReport Relabel(TargetReport target, string content, string label, AzureSite site)
    {
        bool isApp = target.Kind is "app" or "single-file app";
        return target with
        {
            Kind = isApp ? site.TargetKind : $"azure {target.Kind}",
            Path = Map(target.Path, content, label),
            Description = string.Join("; ", new[] { target.Description, site.IsLinux ? "Linux" : "Windows" }.Where(d => !string.IsNullOrEmpty(d))),
            Decoders = target.Decoders.Select(d => d with { Path = Map(d.Path, content, label) }).ToList(),
            Findings = target.Findings.Select(f => f with { Location = Map(f.Location, content, label) }).ToList(),
        };
    }

    private static string Map(string text, string content, string label) =>
        text.Replace(content, label, StringComparison.Ordinal).Replace('\\', '/');

    private static AzureScanResult Single(AzureSite site, Verdict verdict, string reason, string? error = null) =>
        new([new TargetReport(site.TargetKind, $"azure:{site.Label}", site.IsLinux ? "Linux" : "Windows", verdict, reason, [], [])],
            [], error is null ? [] : [error], 0);
}
