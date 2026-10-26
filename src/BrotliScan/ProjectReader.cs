using System.Text.Json;
using System.Xml;
using System.Xml.Linq;

namespace BrotliScan;

internal sealed record ProjectInfo(
    string Path,
    IReadOnlyList<string> TargetFrameworks,
    bool SelfContained,
    bool SingleFile,
    bool NativeAot,
    IReadOnlyList<string> BrotliPackages);

internal sealed record RuntimeConfigInfo(bool SelfContained, IReadOnlyList<string> FrameworkVersions);

internal enum TfmFamily { DotNet, NetFramework, NetStandard, Unknown }

internal static class ProjectReader
{
    // Project files are untrusted input: no DTDs and no external resolution (OWASP XXE guidance).
    private static readonly XmlReaderSettings XmlSettings = new()
    {
        DtdProcessing = DtdProcessing.Prohibit,
        XmlResolver = null,
        MaxCharactersInDocument = 20_000_000,
    };

    public static ProjectInfo Read(string path)
    {
        var properties = ReadProperties(path, out var packages);

        // TargetFramework often lives in the nearest Directory.Build.props.
        if (!properties.ContainsKey("TargetFramework") && !properties.ContainsKey("TargetFrameworks")
            && FindUpwards(Path.GetDirectoryName(path)!, "Directory.Build.props") is { } props)
        {
            foreach (var (key, value) in ReadProperties(props, out _))
            {
                properties.TryAdd(key, value);
            }
        }

        var frameworks = (properties.GetValueOrDefault("TargetFrameworks") ?? properties.GetValueOrDefault("TargetFramework") ?? "")
            .Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Where(f => !f.Contains("$(", StringComparison.Ordinal))
            .ToList();

        return new ProjectInfo(
            path,
            frameworks,
            IsTrue(properties, "SelfContained"),
            IsTrue(properties, "PublishSingleFile"),
            IsTrue(properties, "PublishAot"),
            packages.Where(p => p.Contains("brotli", StringComparison.OrdinalIgnoreCase)).ToList());
    }

    public static (TfmFamily Family, Version? Version) ParseTfm(string tfm)
    {
        string name = tfm.Split('-')[0].ToLowerInvariant();
        if (name.StartsWith("netstandard", StringComparison.Ordinal))
        {
            return (TfmFamily.NetStandard, null);
        }

        if (name.StartsWith("netcoreapp", StringComparison.Ordinal) && Version.TryParse(name["netcoreapp".Length..], out var core))
        {
            return (TfmFamily.DotNet, core);
        }

        if (name.StartsWith("net", StringComparison.Ordinal) && name.Length > 3 && char.IsAsciiDigit(name[3]))
        {
            // net5.0 and later have a dot; net48, net472 and friends are .NET Framework.
            return name.Contains('.') && Version.TryParse(name[3..], out var modern)
                ? (TfmFamily.DotNet, modern)
                : (TfmFamily.NetFramework, null);
        }

        return (TfmFamily.Unknown, null);
    }

    /// <summary>BrotliStream and the native decoder arrived in .NET Core 2.1.</summary>
    public static bool HasInboxBrotli(Version version) => version >= new Version(2, 1);

    public static RuntimeConfigInfo? ReadRuntimeConfig(Stream stream)
    {
        try
        {
            using var document = JsonDocument.Parse(stream, new JsonDocumentOptions
            {
                AllowTrailingCommas = true,
                CommentHandling = JsonCommentHandling.Skip,
                MaxDepth = 32,
            });

            if (!document.RootElement.TryGetProperty("runtimeOptions", out var options) || options.ValueKind != JsonValueKind.Object)
            {
                return null;
            }

            if (options.TryGetProperty("includedFrameworks", out var included) && included.ValueKind == JsonValueKind.Array)
            {
                return new RuntimeConfigInfo(true, NetCoreVersions(included));
            }

            var frameworks = new List<string>();
            if (options.TryGetProperty("framework", out var single) && single.ValueKind == JsonValueKind.Object)
            {
                frameworks.AddRange(NetCoreVersions([single]));
            }

            if (options.TryGetProperty("frameworks", out var many) && many.ValueKind == JsonValueKind.Array)
            {
                frameworks.AddRange(NetCoreVersions(many));
            }

            return new RuntimeConfigInfo(false, frameworks);
        }
        catch (JsonException)
        {
            return null;
        }
    }

    // Every shared framework sits on Microsoft.NETCore.App, which is where the brotli decoder lives.
    // ASP.NET Core and Windows Desktop share its major version, so any of them pins the major.
    private static List<string> NetCoreVersions(IEnumerable<JsonElement> frameworks) =>
        frameworks
            .Where(f => f.ValueKind == JsonValueKind.Object
                && f.TryGetProperty("name", out var n) && n.GetString() is "Microsoft.NETCore.App" or "Microsoft.AspNetCore.App" or "Microsoft.WindowsDesktop.App"
                && f.TryGetProperty("version", out var v) && v.ValueKind == JsonValueKind.String)
            .Select(f => f.GetProperty("version").GetString()!)
            .Distinct()
            .ToList();

    private static List<string> NetCoreVersions(JsonElement array) => NetCoreVersions(array.EnumerateArray());

    private static Dictionary<string, string> ReadProperties(string path, out List<string> packages)
    {
        using var reader = XmlReader.Create(path, XmlSettings);
        var document = XDocument.Load(reader);

        var properties = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var group in document.Descendants().Where(e => e.Name.LocalName == "PropertyGroup"))
        {
            foreach (var property in group.Elements())
            {
                properties[property.Name.LocalName] = property.Value.Trim();
            }
        }

        packages = document.Descendants()
            .Where(e => e.Name.LocalName == "PackageReference")
            .Select(e => (string?)e.Attribute("Include") ?? (string?)e.Attribute("Update"))
            .OfType<string>()
            .ToList();
        return properties;
    }

    private static bool IsTrue(Dictionary<string, string> properties, string name) =>
        properties.TryGetValue(name, out var value) && value.Equals("true", StringComparison.OrdinalIgnoreCase);

    private static string? FindUpwards(string directory, string fileName)
    {
        for (var dir = new DirectoryInfo(directory); dir is not null; dir = dir.Parent)
        {
            string candidate = Path.Combine(dir.FullName, fileName);
            if (File.Exists(candidate))
            {
                return candidate;
            }
        }

        return null;
    }
}
