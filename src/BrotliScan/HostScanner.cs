using System.Runtime.InteropServices;

namespace BrotliScan;

internal sealed record HostRuntime(Version Version, ComponentReport Decoder);

internal sealed record HostInventory(
    IReadOnlyList<HostRuntime> Runtimes,
    IReadOnlyList<ComponentReport> Components);

/// <summary>
/// Inspects this machine's .NET installs: the shared runtimes apps run on, the runtime and host packs
/// that self-contained, single-file and Native AOT publishes copy in, and (when a runtime links it)
/// the OS brotli library. Directories are read directly; no dotnet command is executed.
/// </summary>
internal static class HostScanner
{
    private static readonly string[] NativeLibraryNames =
        ["System.IO.Compression.Native.dll", "libSystem.IO.Compression.Native.so", "libSystem.IO.Compression.Native.dylib"];

    private static readonly string[] BuildInputNames =
    [
        .. NativeLibraryNames, "libSystem.IO.Compression.Native.a", "System.IO.Compression.Native.lib",
        "singlefilehost", "singlefilehost.exe",
    ];

    public static HostInventory Scan(Func<string, DecoderFingerprint?> fingerprint)
    {
        var runtimes = new List<HostRuntime>();
        var components = new List<ComponentReport>();

        foreach (string root in DotNetRoots())
        {
            string shared = Path.Combine(root, "shared", "Microsoft.NETCore.App");
            foreach (var versionDir in SafeDirectories(shared))
            {
                if (!Version.TryParse(versionDir.Name.Split('-')[0], out var version))
                {
                    continue;
                }

                foreach (string library in NativeLibraryNames.Select(n => Path.Combine(versionDir.FullName, n)).Where(File.Exists))
                {
                    if (fingerprint(library) is { } found)
                    {
                        var report = new ComponentReport("runtime", library, $".NET runtime {versionDir.Name}", found.Status, found.Evidence, found.VersionStamp);
                        runtimes.Add(new HostRuntime(version, report));
                        components.Add(report);
                    }
                }
            }

            foreach (var pack in SafeDirectories(Path.Combine(root, "packs"))
                .Where(d => d.Name.StartsWith("Microsoft.NETCore.App.Runtime.", StringComparison.OrdinalIgnoreCase)
                         || d.Name.StartsWith("Microsoft.NETCore.App.Host.", StringComparison.OrdinalIgnoreCase)))
            {
                components.AddRange(BuildInputs(pack, fingerprint));
            }
        }

        string nuget = Environment.GetEnvironmentVariable("NUGET_PACKAGES")
            ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".nuget", "packages");
        foreach (var package in SafeDirectories(nuget)
            .Where(d => d.Name.StartsWith("microsoft.netcore.app.runtime.", StringComparison.OrdinalIgnoreCase)
                     || d.Name.StartsWith("microsoft.netcore.app.host.", StringComparison.OrdinalIgnoreCase)
                     || (d.Name.StartsWith("runtime.", StringComparison.OrdinalIgnoreCase) && d.Name.EndsWith(".microsoft.dotnet.ilcompiler", StringComparison.OrdinalIgnoreCase))))
        {
            components.AddRange(BuildInputs(package, fingerprint));
        }

        // Distro builds made with CLR_CMAKE_USE_SYSTEM_BROTLI decode with the OS library.
        if (runtimes.Any(r => r.Decoder.Status == DecoderStatus.SystemLibrary))
        {
            foreach (string library in OsBrotliLibraries())
            {
                if (fingerprint(library) is { } found)
                {
                    components.Add(new ComponentReport("os-library", library, "OS brotli decoder (used by .NET runtimes that link it)", found.Status, found.Evidence, found.VersionStamp));
                }
            }
        }

        return new HostInventory(runtimes, components.DistinctBy(c => c.Path).ToList());
    }

    private static IEnumerable<ComponentReport> BuildInputs(DirectoryInfo package, Func<string, DecoderFingerprint?> fingerprint)
    {
        foreach (var versionDir in SafeDirectories(package.FullName))
        {
            var files = SafeFiles(versionDir, recursive: true).Where(f => BuildInputNames.Contains(f.Name, StringComparer.OrdinalIgnoreCase));
            foreach (var file in files)
            {
                if (fingerprint(file.FullName) is { } found)
                {
                    string use = file.Name.StartsWith("singlefilehost", StringComparison.OrdinalIgnoreCase)
                        ? "single-file apps published from this machine embed it"
                        : "self-contained and Native AOT apps published from this machine copy it in";
                    yield return new ComponentReport("build-input", file.FullName, $"{package.Name} {versionDir.Name}: {use}", found.Status, found.Evidence, found.VersionStamp);
                }
            }
        }
    }

    private static IEnumerable<string> DotNetRoots()
    {
        var candidates = new List<string?>();
        foreach (string variable in new[] { "DOTNET_ROOT", "DOTNET_ROOT_X64", "DOTNET_ROOT_ARM64", "DOTNET_ROOT_X86", "DOTNET_ROOT(x86)" })
        {
            candidates.Add(Environment.GetEnvironmentVariable(variable));
        }

        // The dotnet on PATH, following symlinks such as /usr/bin/dotnet -> /usr/share/dotnet/dotnet.
        string executable = RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? "dotnet.exe" : "dotnet";
        foreach (string dir in (Environment.GetEnvironmentVariable("PATH") ?? "").Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries))
        {
            string candidate = Path.Combine(dir, executable);
            try
            {
                if (File.Exists(candidate))
                {
                    var target = File.ResolveLinkTarget(candidate, returnFinalTarget: true);
                    candidates.Add(Path.GetDirectoryName(target?.FullName ?? candidate));
                }
            }
            catch (IOException)
            {
            }
            catch (UnauthorizedAccessException)
            {
            }
        }

        string home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        candidates.Add(Path.Combine(home, ".dotnet"));
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            foreach (var folder in new[] { Environment.SpecialFolder.ProgramFiles, Environment.SpecialFolder.ProgramFilesX86 })
            {
                candidates.Add(Path.Combine(Environment.GetFolderPath(folder), "dotnet"));
            }

            candidates.Add(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Microsoft", "dotnet"));
        }
        else
        {
            candidates.AddRange(
            [
                "/usr/share/dotnet", "/usr/lib/dotnet", "/usr/lib64/dotnet", "/usr/local/share/dotnet",
                "/usr/local/share/dotnet/x64", "/opt/dotnet", "/snap/dotnet-sdk/current",
                "/opt/homebrew/opt/dotnet/libexec", "/usr/local/opt/dotnet/libexec",
            ]);
        }

        return candidates
            .OfType<string>()
            .Where(c => c.Length > 0 && Directory.Exists(Path.Combine(c, "shared", "Microsoft.NETCore.App")))
            .Select(c => Path.GetFullPath(c).TrimEnd(Path.DirectorySeparatorChar))
            .Distinct(OperatingSystem.IsWindows() || OperatingSystem.IsMacOS() ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal);
    }

    private static IEnumerable<string> OsBrotliLibraries()
    {
        string[] directories =
        [
            "/usr/lib", "/usr/lib64", "/lib", "/lib64", "/usr/lib/x86_64-linux-gnu", "/usr/lib/aarch64-linux-gnu",
            "/lib/x86_64-linux-gnu", "/lib/aarch64-linux-gnu", "/usr/local/lib", "/opt/homebrew/lib",
        ];

        // Symlinks are skipped, so each real library is fingerprinted once.
        return directories
            .SelectMany(d => SafeFiles(new DirectoryInfo(d), recursive: false))
            .Where(f => f.Name.StartsWith("libbrotlidec", StringComparison.Ordinal) && (f.Name.Contains(".so", StringComparison.Ordinal) || f.Name.EndsWith(".dylib", StringComparison.Ordinal)))
            .Select(f => f.FullName)
            .Distinct();
    }

    private static readonly EnumerationOptions Shallow = new()
    {
        IgnoreInaccessible = true,
        AttributesToSkip = FileAttributes.ReparsePoint,
    };

    private static readonly EnumerationOptions Deep = new()
    {
        IgnoreInaccessible = true,
        AttributesToSkip = FileAttributes.ReparsePoint,
        RecurseSubdirectories = true,
        MaxRecursionDepth = 8,
    };

    private static IEnumerable<DirectoryInfo> SafeDirectories(string path)
    {
        var dir = new DirectoryInfo(path);
        return dir.Exists ? dir.EnumerateDirectories("*", Shallow) : [];
    }

    private static IEnumerable<FileInfo> SafeFiles(DirectoryInfo dir, bool recursive) =>
        dir.Exists ? dir.EnumerateFiles("*", recursive ? Deep : Shallow) : [];
}
