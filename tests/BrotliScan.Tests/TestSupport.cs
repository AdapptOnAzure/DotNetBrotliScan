using System.Collections.Immutable;
using System.IO.Compression;
using System.Net;
using System.Text;
using BrotliScan.AppService;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;

[assembly: Parallelize(Scope = ExecutionScope.MethodLevel)]

namespace BrotliScan.Tests;

/// <summary>Compiles snippets in memory so the IL scanner sees real compiler output.</summary>
internal static class Compiler
{
    // Stands in for ASP.NET Core: the IL scanner matches on the referenced type and member names.
    private const string AspNetStub = """
        namespace Microsoft.AspNetCore.Builder
        {
            public static class RequestDecompressionBuilderExtensions { public static object UseRequestDecompression(this object app) => app; }
            public static class ResponseCompressionBuilderExtensions { public static object UseResponseCompression(this object app) => app; }
        }
        namespace Microsoft.AspNetCore.Http
        {
            public abstract class HttpRequest { public abstract System.IO.Stream Body { get; set; } }
        }
        namespace Microsoft.AspNetCore.RequestDecompression
        {
            public interface IDecompressionProvider { System.IO.Stream GetDecompressionStream(System.IO.Stream stream); }
            public sealed class RequestDecompressionOptions
            {
                public System.Collections.Generic.IDictionary<string, object> DecompressionProviders { get; } = new System.Collections.Generic.Dictionary<string, object>();
            }
        }
        """;

    private static readonly Lazy<ImmutableArray<MetadataReference>> Framework = new(() =>
        ((string)AppContext.GetData("TRUSTED_PLATFORM_ASSEMBLIES")!)
            .Split(Path.PathSeparator)
            .Select(p => (MetadataReference)MetadataReference.CreateFromFile(p))
            .ToImmutableArray());

    private static readonly Lazy<MetadataReference> Stub = new(() => MetadataReference.CreateFromImage(Emit("AspNetStub", AspNetStub, OptimizationLevel.Release, [])));

    public static byte[] Compile(string source, OptimizationLevel optimization = OptimizationLevel.Release) =>
        Emit("Sample", source, optimization, [Stub.Value]);

    private static byte[] Emit(string name, string source, OptimizationLevel optimization, MetadataReference[] extra)
    {
        var compilation = CSharpCompilation.Create(
            name,
            [CSharpSyntaxTree.ParseText(source)],
            [.. Framework.Value, .. extra],
            new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary, optimizationLevel: optimization, nullableContextOptions: NullableContextOptions.Enable));
        using var output = new MemoryStream();
        var result = compilation.Emit(output);
        if (!result.Success)
        {
            throw new InvalidOperationException(string.Join(Environment.NewLine, result.Diagnostics.Where(d => d.Severity == DiagnosticSeverity.Error)));
        }

        return output.ToArray();
    }
}

/// <summary>Byte fixtures that look like brotli builds to the native scanner.</summary>
internal static class Fakes
{
    public static readonly byte[] Dictionary = "timedownlifeleftbackcodedatashow"u8.ToArray();

    // Starts with an ELF header, as real binaries do; the scanner skips files that aren't executables.
    private static readonly byte[] Elf = [0x7f, (byte)'E', (byte)'L', (byte)'F'];

    public static byte[] VulnerableDecoder() => Concat(Elf, Filler(512), Dictionary, "BrotliDecoderDecompressStream\0_ERROR_FORMAT_DISTANCE\0"u8.ToArray(), Filler(512));

    public static byte[] PatchedDecoder() => Concat(Elf, Filler(512), Dictionary, "BrotliDecoderDecompressStream\0_ERROR_FORMAT_DISTANCE\0_ERROR_FORMAT_BLOCK_SWITCH\0"u8.ToArray(), Filler(512));

    public static byte[] Filler(int length) => Enumerable.Range(0, length).Select(i => (byte)(i * 7 % 251)).ToArray();

    public static byte[] Concat(params byte[][] parts) => parts.SelectMany(p => p).ToArray();

    public static byte[] RuntimeConfig(string version = "10.0.0") => Encoding.UTF8.GetBytes(
        $$"""{ "runtimeOptions": { "tfm": "net10.0", "framework": { "name": "Microsoft.AspNetCore.App", "version": "{{version}}" } } }""");

    public static byte[] Zip(params (string Name, byte[] Content)[] entries)
    {
        using var output = new MemoryStream();
        using (var archive = new ZipArchive(output, ZipArchiveMode.Create, leaveOpen: true))
        {
            foreach (var (name, content) in entries)
            {
                using var stream = archive.CreateEntry(name).Open();
                stream.Write(content);
            }
        }

        return output.ToArray();
    }
}

internal sealed class FakeTokens : ITokenSource
{
    public Task<string> GetTokenAsync(string resource, string subscriptionId, CancellationToken cancellationToken) =>
        Task.FromResult(resource == AzCli.StorageResource ? "storage-token" : "arm-token");
}

/// <summary>Routes requests to canned responses and records what was sent where.</summary>
internal sealed class FakeAzure : HttpMessageHandler
{
    private readonly Dictionary<string, Func<HttpResponseMessage>> _routes = new(StringComparer.Ordinal);

    public List<(Uri Uri, string? Authorization)> Requests { get; } = [];

    public FakeAzure Route(string url, Func<HttpResponseMessage> response)
    {
        _routes[url] = response;
        return this;
    }

    public FakeAzure Json(string url, string json) =>
        Route(url, () => new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(json, Encoding.UTF8, "application/json") });

    public FakeAzure Bytes(string url, byte[] bytes) =>
        Route(url, () => new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(bytes) });

    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        lock (Requests)
        {
            Requests.Add((request.RequestUri!, request.Headers.Authorization?.ToString()));
        }

        return Task.FromResult(_routes.TryGetValue(request.RequestUri!.AbsoluteUri, out var response)
            ? response()
            : new HttpResponseMessage(HttpStatusCode.NotFound));
    }
}
