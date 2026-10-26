using System.Collections.Concurrent;
using System.Reflection.Metadata;
using System.Reflection.PortableExecutable;
using System.Xml;

namespace BrotliScan;

internal sealed class ScanOptions
{
    public List<string> Paths { get; } = [];
    public bool IncludeHost { get; set; } = true;
    public bool IncludeObj { get; set; }
    public long MaxFileBytes { get; set; } = 1L << 30;

    /// <summary>Runtimes to judge framework-dependent apps against, instead of this machine's (used for Azure apps).</summary>
    public HostInventory? RuntimeInventory { get; set; }

    /// <summary>Explains a missing runtime fingerprint for framework-dependent apps.</summary>
    public string? UnknownRuntimeNote { get; set; }
}

internal sealed record BundleScan(
    string Path,
    DecoderFingerprint? HostDecoder,
    IReadOnlyList<Finding> Findings,
    IReadOnlyList<(string Path, DecoderFingerprint Decoder)> EmbeddedDecoders,
    RuntimeConfigInfo? Config);

internal sealed class Scanner(ScanOptions options)
{
    private static readonly HashSet<string> SkippedDirectories =
        new(StringComparer.OrdinalIgnoreCase) { ".git", ".hg", ".svn", "node_modules", ".vs", ".idea" };

    private static readonly HashSet<string> BinaryExtensions =
        new(StringComparer.OrdinalIgnoreCase) { "", ".dll", ".exe", ".so", ".dylib", ".a", ".lib" };

    private static readonly StringComparer PathComparer =
        OperatingSystem.IsWindows() || OperatingSystem.IsMacOS() ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal;

    private static readonly EnumerationOptions Shallow = new()
    {
        IgnoreInaccessible = true,
        AttributesToSkip = FileAttributes.ReparsePoint, // don't follow symlinks out of the tree or into loops
    };

    private const long MaxSourceBytes = 8 << 20;
    private const string NativeLibraryName = "System.IO.Compression.Native";

    private readonly ConcurrentBag<string> _errors = [];
    private readonly ConcurrentBag<(string Path, List<Finding> Findings)> _sources = [];
    private readonly ConcurrentBag<ProjectInfo> _projects = [];
    private readonly ConcurrentBag<(string Path, AssemblyScanResult Result)> _assemblies = [];
    private readonly ConcurrentBag<(string Path, DecoderFingerprint Decoder)> _natives = [];
    private readonly ConcurrentBag<(string Path, RuntimeConfigInfo? Config)> _appMarkers = [];
    private readonly ConcurrentBag<BundleScan> _bundles = [];
    private long _files;

    public ScanReport Run()
    {
        var host = options.RuntimeInventory ?? (options.IncludeHost ? HostScanner.Scan(Fingerprint) : new HostInventory([], []));
        var roots = options.Paths.Select(p => Path.GetFullPath(p).TrimEnd(Path.DirectorySeparatorChar)).Distinct(PathComparer).ToList();

        Parallel.ForEach(
            roots.SelectMany(Enumerate),
            new ParallelOptions { MaxDegreeOfParallelism = Environment.ProcessorCount },
            Process);

        var standalone = new List<ComponentReport>();
        var targets = BuildTargets(roots, host, standalone);

        return new ScanReport(
            "brotli-scan",
            typeof(Scanner).Assembly.GetName().Version?.ToString(3) ?? "0.0.0",
            "CVE-2026-111497 (brotli decoder out-of-bounds write; fixed in brotli 1.0.10, 1.1.1, 1.2.1)",
            DateTimeOffset.UtcNow,
            roots,
            _files,
            [.. host.Components, .. standalone],
            targets.OrderBy(t => t.Verdict).ThenBy(t => t.Path, PathComparer).ToList(),
            _errors.Order(StringComparer.Ordinal).ToList());
    }

    private IEnumerable<string> Enumerate(string root)
    {
        if (File.Exists(root))
        {
            yield return root;
            yield break;
        }

        var pending = new Stack<DirectoryInfo>();
        pending.Push(new DirectoryInfo(root));
        while (pending.Count > 0)
        {
            var dir = pending.Pop();
            List<FileSystemInfo> entries;
            try
            {
                entries = dir.EnumerateFileSystemInfos("*", Shallow).ToList();
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                _errors.Add($"{dir.FullName}: {ex.Message}");
                continue;
            }

            foreach (var entry in entries)
            {
                if (entry is DirectoryInfo child)
                {
                    bool skip = SkippedDirectories.Contains(child.Name)
                        || (!options.IncludeObj && child.Name.Equals("obj", StringComparison.OrdinalIgnoreCase));
                    if (!skip)
                    {
                        pending.Push(child);
                    }
                }
                else
                {
                    yield return entry.FullName;
                }
            }
        }
    }

    private void Process(string path)
    {
        Interlocked.Increment(ref _files);
        string name = Path.GetFileName(path);
        string extension = Path.GetExtension(name);
        try
        {
            if (name.EndsWith(".runtimeconfig.json", StringComparison.OrdinalIgnoreCase))
            {
                using var stream = File.OpenRead(path);
                _appMarkers.Add((path, ProjectReader.ReadRuntimeConfig(stream)));
                return;
            }

            if (name.EndsWith(".deps.json", StringComparison.OrdinalIgnoreCase))
            {
                _appMarkers.Add((path, null));
                return;
            }

            switch (extension.ToLowerInvariant())
            {
                case ".cs" when new FileInfo(path).Length <= MaxSourceBytes:
                    _sources.Add((path, SourceScanner.ScanCSharp(File.ReadAllText(path), path)));
                    return;
                case ".vb" or ".fs" when new FileInfo(path).Length <= MaxSourceBytes:
                    _sources.Add((path, SourceScanner.ScanText(File.ReadAllText(path), path, fsharp: extension.Equals(".fs", StringComparison.OrdinalIgnoreCase))));
                    return;
                case ".csproj" or ".vbproj" or ".fsproj":
                    _projects.Add(ProjectReader.Read(path));
                    return;
            }

            if (BinaryExtensions.Contains(extension) || name.Contains(".so.", StringComparison.Ordinal))
            {
                ScanBinary(path);
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or BadImageFormatException or XmlException or InvalidDataException)
        {
            _errors.Add($"{path}: {ex.Message}");
        }
    }

    private enum BinaryKind { None, PortableExecutable, Native }

    private void ScanBinary(string path)
    {
        var info = new FileInfo(path);
        if (info.Length < 64 || info.Length > options.MaxFileBytes)
        {
            return;
        }

        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 1 << 16, FileOptions.SequentialScan);
        var kind = Sniff(stream);
        if (kind == BinaryKind.None)
        {
            return;
        }

        if (kind == BinaryKind.PortableExecutable)
        {
            using var pe = new PEReader(stream, PEStreamOptions.LeaveOpen);
            if (HasMetadata(pe))
            {
                _assemblies.Add((path, AssemblyScanner.Scan(pe, path)));
                return;
            }
        }

        stream.Position = 0;
        var native = NativeScanner.Scan(stream);
        if (native.BundleHeaderOffset != 0 && BundleReader.TryRead(stream, native.BundleHeaderOffset) is { } entries)
        {
            _bundles.Add(ScanBundle(path, stream, native.Decoder, entries));
        }
        else if (native.Decoder is { } decoder)
        {
            _natives.Add((path, decoder));
        }
    }

    private BundleScan ScanBundle(string path, Stream stream, DecoderFingerprint? hostDecoder, IReadOnlyList<BundleEntry> entries)
    {
        var findings = new List<Finding>();
        var decoders = new List<(string, DecoderFingerprint)>();
        RuntimeConfigInfo? config = null;

        foreach (var entry in entries.Where(e => e.Type is BundleFileType.Assembly or BundleFileType.NativeBinary or BundleFileType.RuntimeConfigJson))
        {
            string where = $"{path}!{entry.RelativePath}";
            try
            {
                using var content = BundleReader.Extract(stream, entry, options.MaxFileBytes);
                if (content is null)
                {
                    continue;
                }

                switch (entry.Type)
                {
                    case BundleFileType.Assembly:
                        using (var pe = new PEReader(content, PEStreamOptions.LeaveOpen))
                        {
                            if (HasMetadata(pe))
                            {
                                findings.AddRange(AssemblyScanner.Scan(pe, where).Findings);
                            }
                        }

                        break;
                    case BundleFileType.NativeBinary when NativeScanner.Scan(content).Decoder is { } decoder:
                        decoders.Add((where, decoder));
                        break;
                    case BundleFileType.RuntimeConfigJson:
                        config = ProjectReader.ReadRuntimeConfig(content);
                        break;
                }
            }
            catch (Exception ex) when (ex is IOException or BadImageFormatException or InvalidDataException)
            {
                _errors.Add($"{where}: {ex.Message}");
            }
        }

        return new BundleScan(path, hostDecoder, findings, decoders, config);
    }

    private DecoderFingerprint? Fingerprint(string path)
    {
        try
        {
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 1 << 16, FileOptions.SequentialScan);
            return NativeScanner.Scan(stream).Decoder;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            _errors.Add($"{path}: {ex.Message}");
            return null;
        }
    }

    private static BinaryKind Sniff(Stream stream)
    {
        Span<byte> magic = stackalloc byte[4];
        int read = stream.ReadAtLeast(magic, 4, throwOnEndOfStream: false);
        stream.Position = 0;
        if (read < 4)
        {
            return BinaryKind.None;
        }

        uint big = (uint)(magic[0] << 24 | magic[1] << 16 | magic[2] << 8 | magic[3]);
        return magic switch
        {
            [(byte)'M', (byte)'Z', ..] => BinaryKind.PortableExecutable,
            [0x7f, (byte)'E', (byte)'L', (byte)'F'] => BinaryKind.Native,
            [(byte)'!', (byte)'<', (byte)'a', (byte)'r'] => BinaryKind.Native, // static library archive
            _ when big is 0xfeedface or 0xfeedfacf or 0xcefaedfe or 0xcffaedfe or 0xcafebabe or 0xbebafeca => BinaryKind.Native, // Mach-O
            _ => BinaryKind.None,
        };
    }

    private static bool HasMetadata(PEReader pe)
    {
        try
        {
            return pe.HasMetadata;
        }
        catch (BadImageFormatException)
        {
            return false;
        }
    }

    private List<TargetReport> BuildTargets(List<string> roots, HostInventory host, List<ComponentReport> standalone)
    {
        var targets = new List<TargetReport>();

        // Source: attribute each file to the nearest project above it.
        var projectDirs = _projects
            .GroupBy(p => Path.GetDirectoryName(p.Path)!, PathComparer)
            .ToDictionary(g => g.Key, g => g.First(), PathComparer);
        var sourceFindings = _projects.ToDictionary(p => p.Path, _ => new List<Finding>(), PathComparer);
        var looseFindings = new List<Finding>();
        foreach (var (path, findings) in _sources)
        {
            string? dir = Nearest(Path.GetDirectoryName(path)!, projectDirs.ContainsKey, roots);
            (dir is null ? looseFindings : sourceFindings[projectDirs[dir].Path]).AddRange(findings);
        }

        foreach (var project in _projects)
        {
            var findings = sourceFindings[project.Path];
            findings.AddRange(project.BrotliPackages.Select(p => new Finding(FindingKind.ThirdPartyBrotli, Rules.BrotliPackage, project.Path,
                $"references package '{p}', a brotli implementation outside .NET; check it against CVE-2026-111497")));

            var majors = new List<int>();
            bool anyRuntime = false;
            foreach (string tfm in project.TargetFrameworks)
            {
                switch (ProjectReader.ParseTfm(tfm))
                {
                    case (TfmFamily.DotNet, { } version) when ProjectReader.HasInboxBrotli(version):
                        majors.Add(version.Major);
                        break;
                    case (TfmFamily.NetStandard or TfmFamily.Unknown, _):
                        anyRuntime = true;
                        break;
                }
            }

            var decoders = anyRuntime || project.TargetFrameworks.Count == 0
                ? host.Runtimes.Select(r => r.Decoder).ToList()
                : host.Runtimes.Where(r => majors.Contains(r.Version.Major)).Select(r => r.Decoder).ToList();
            string missing = majors.Count > 0
                ? $"no .NET {string.Join("/", majors.Distinct())} runtime on this machine to check; runtimes without the brotli fix are affected"
                : "no runtime on this machine to check; runtimes without the brotli fix are affected";

            var flags = new List<string>(project.TargetFrameworks);
            if (project.SelfContained) flags.Add("self-contained");
            if (project.SingleFile) flags.Add("single-file");
            if (project.NativeAot) flags.Add("Native AOT");

            var (verdict, reason) = Decide(findings, Effective(decoders, host), missing);
            if (verdict == Verdict.NotExposed && findings.All(f => f.Kind != FindingKind.Mitigation))
            {
                reason += ". A source scan can't see NuGet dependencies; scan the build output to cover them";
            }

            targets.Add(new TargetReport("project", project.Path, string.Join(", ", flags), verdict, reason, decoders, findings));
        }

        if (looseFindings.Count > 0)
        {
            var decoders = host.Runtimes.Select(r => r.Decoder).ToList();
            var (verdict, reason) = Decide(looseFindings, Effective(decoders, host), "no runtime on this machine to check");
            targets.Add(new TargetReport("sources", roots.Count == 1 ? roots[0] : "(scan roots)", "source files outside any project", verdict, reason, decoders, looseFindings));
        }

        // Compiled apps: anything under a directory holding a .runtimeconfig.json or .deps.json.
        var appDirs = _appMarkers
            .GroupBy(m => Path.GetDirectoryName(m.Path)!, PathComparer)
            .ToDictionary(g => g.Key, g => g.Select(m => m.Config).FirstOrDefault(c => c is not null), PathComparer);
        var appFindings = appDirs.Keys.ToDictionary(k => k, _ => new List<Finding>(), PathComparer);
        var appDecoders = appDirs.Keys.ToDictionary(k => k, _ => new List<(string Path, DecoderFingerprint Decoder)>(), PathComparer);

        foreach (var (path, result) in _assemblies.Where(a => !a.Result.IsFramework))
        {
            string? dir = Nearest(Path.GetDirectoryName(path)!, appDirs.ContainsKey, roots);
            if (dir is not null)
            {
                appFindings[dir].AddRange(result.Findings);
            }
            else if (result.Findings.Count > 0)
            {
                var decoders = host.Runtimes.Select(r => r.Decoder).ToList();
                var (verdict, reason) = Decide(result.Findings, Effective(decoders, host), "no runtime on this machine to check");
                targets.Add(new TargetReport("assembly", path, result.Name, verdict, reason, decoders, result.Findings));
            }
        }

        foreach (var (path, decoder) in _natives)
        {
            string? dir = Nearest(Path.GetDirectoryName(path)!, appDirs.ContainsKey, roots);
            if (dir is not null)
            {
                appDecoders[dir].Add((path, decoder));
            }
            else
            {
                standalone.Add(new ComponentReport("standalone", path, null, decoder.Status, decoder.Evidence, decoder.VersionStamp));
            }
        }

        foreach (var (dir, config) in appDirs)
        {
            var findings = appFindings[dir];
            var own = appDecoders[dir];
            targets.Add(AppTarget("app", dir, config, findings, own, host, options.UnknownRuntimeNote));
        }

        foreach (var bundle in _bundles)
        {
            var own = bundle.EmbeddedDecoders.ToList();
            if (bundle.HostDecoder is { } statically)
            {
                // Self-contained single-file hosts link the runtime's native libraries in.
                own.Add((bundle.Path, statically));
            }

            targets.Add(AppTarget("single-file app", bundle.Path, bundle.Config, bundle.Findings.ToList(), own, host, options.UnknownRuntimeNote));
        }

        return targets;
    }

    private static TargetReport AppTarget(
        string kind, string path, RuntimeConfigInfo? config, List<Finding> findings,
        List<(string Path, DecoderFingerprint Decoder)> own, HostInventory host, string? unknownRuntimeNote)
    {
        bool IsRuntimeLibrary((string Path, DecoderFingerprint Decoder) d) =>
            Path.GetFileName(d.Path).Contains(NativeLibraryName, StringComparison.OrdinalIgnoreCase) || PathComparer.Equals(d.Path, path);

        // A native brotli that isn't the runtime's own is somebody else's copy, with its own patch cycle.
        foreach (var (file, decoder) in own.Where(d => !IsRuntimeLibrary(d)))
        {
            findings.Add(new Finding(FindingKind.ThirdPartyBrotli, Rules.BrotliPackage, file,
                $"ships a non-.NET brotli decoder ({decoder.Status}: {decoder.Evidence})"));
        }

        var runtimeOwn = own.Where(IsRuntimeLibrary)
            .Select(d => new ComponentReport("app", d.Path, null, d.Decoder.Status, d.Decoder.Evidence, d.Decoder.VersionStamp))
            .ToList();

        List<ComponentReport> decoders;
        string description;
        string missing;
        if (runtimeOwn.Count > 0 || config?.SelfContained == true)
        {
            decoders = runtimeOwn;
            description = "self-contained";
            missing = "the app carries its own runtime, but its brotli decoder wasn't found";
        }
        else
        {
            var majors = (config?.FrameworkVersions ?? [])
                .Select(v => Version.TryParse(v.Split('-')[0], out var parsed) ? parsed.Major : -1)
                .Where(m => m >= 0)
                .ToHashSet();
            decoders = host.Runtimes.Where(r => majors.Count == 0 || majors.Contains(r.Version.Major)).Select(r => r.Decoder).ToList();
            description = config is null
                ? "build output"
                : $"framework-dependent, .NET {string.Join("/", config.FrameworkVersions)}";
            missing = unknownRuntimeNote ?? (majors.Count > 0
                ? $"no .NET {string.Join("/", majors)} runtime on this machine to check; runtimes without the brotli fix are affected"
                : "no runtime on this machine to check; runtimes without the brotli fix are affected");
        }

        var (verdict, reason) = Decide(findings, Effective(decoders, host), missing);
        return new TargetReport(kind, path, description, verdict, reason, decoders, findings);
    }

    /// <summary>Swaps runtimes that link the OS library for the OS library itself, when it was found.</summary>
    private static List<ComponentReport> Effective(List<ComponentReport> decoders, HostInventory host)
    {
        var os = host.Components.Where(c => c.Category == "os-library").ToList();
        return decoders.Any(d => d.Status == DecoderStatus.SystemLibrary) && os.Count > 0
            ? [.. decoders.Where(d => d.Status != DecoderStatus.SystemLibrary), .. os]
            : decoders;
    }

    internal static (Verdict Verdict, string Reason) Decide(IReadOnlyList<Finding> findings, IReadOnlyList<ComponentReport> decoders, string noDecoderNote)
    {
        bool brDisabled = findings.Any(f => f.Kind == FindingKind.Mitigation);
        var exposures = findings
            .Where(f => f.Kind is FindingKind.OutboundResponse or FindingKind.DirectDecode
                || (f.Kind == FindingKind.InboundRequest && !(brDisabled && f.Rule == Rules.RequestDecompression)))
            .ToList();
        DecoderStatus? worst = decoders.Count > 0 ? decoders.Min(d => d.Status) : null;

        if (exposures.Count == 0)
        {
            if (findings.Any(f => f.Kind is FindingKind.Ambiguous or FindingKind.ThirdPartyBrotli))
            {
                return (Verdict.Review, "no confirmed brotli decode path, but some code needs a manual check");
            }

            string reason = brDisabled && findings.Any(f => f.Rule == Rules.RequestDecompression)
                ? "request decompression is on, but the 'br' provider is removed"
                : "no code path decodes brotli";
            if (worst is DecoderStatus.Vulnerable or DecoderStatus.Unconfirmed)
            {
                reason += " (a decoder without the fix is present, but nothing found feeds it)";
            }

            return (Verdict.NotExposed, reason);
        }

        var kinds = new List<string>();
        if (exposures.Any(f => f.Kind == FindingKind.InboundRequest)) kinds.Add("accepts brotli-compressed data from clients");
        if (exposures.Any(f => f.Kind == FindingKind.OutboundResponse)) kinds.Add("decompresses HTTP responses");
        if (exposures.Any(f => f.Kind == FindingKind.DirectDecode)) kinds.Add("decodes brotli directly");
        string paths = string.Join(", ", kinds);

        return worst switch
        {
            DecoderStatus.Vulnerable => (Verdict.Affected, $"{paths} with a brotli decoder that lacks the fix"),
            DecoderStatus.Patched => (Verdict.Patched, $"{paths}, and the decoder has the fix"),
            DecoderStatus.Unconfirmed => (Verdict.LikelyAffected, $"{paths}; the decoder's error strings are stripped, so the fix can't be confirmed from the binary"),
            DecoderStatus.SystemLibrary => (Verdict.LikelyAffected, $"{paths}; the runtime uses the OS brotli library, so check the OS package"),
            DecoderStatus.Unknown => (Verdict.LikelyAffected, $"{paths}; the decoder couldn't be identified"),
            _ => (Verdict.LikelyAffected, $"{paths}; {noDecoderNote}"),
        };
    }

    /// <summary>Walks up from <paramref name="start"/>, stopping at the scan root.</summary>
    private static string? Nearest(string start, Func<string, bool> isMatch, IReadOnlyList<string> roots)
    {
        for (string? dir = start; dir is not null; dir = Path.GetDirectoryName(dir))
        {
            if (isMatch(dir))
            {
                return dir;
            }

            if (roots.Contains(dir, PathComparer))
            {
                break;
            }
        }

        return null;
    }
}
