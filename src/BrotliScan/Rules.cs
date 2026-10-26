namespace BrotliScan;

/// <summary>Stable rule identifiers, shared by the source and IL scanners.</summary>
internal static class Rules
{
    public const string RequestDecompression = "request-decompression";
    public const string BrProviderAdded = "request-decompression-br-provider";
    public const string BrProviderRemoved = "br-provider-removed";
    public const string ProvidersCleared = "decompression-providers-cleared";
    public const string AutomaticDecompression = "http-automatic-decompression";
    public const string AutomaticDecompressionUnknown = "http-automatic-decompression-unresolved";
    public const string DecompressionMethodsElsewhere = "decompression-methods-brotli-elsewhere";
    public const string BrotliStreamDecompress = "brotlistream-decompress";
    public const string RequestBodyBrotliStream = "request-body-brotlistream";
    public const string DecompressionProvider = "brotli-decompression-provider";
    public const string BrotliStreamUnknown = "brotlistream-mode-unresolved";
    public const string BrotliDecoder = "brotlidecoder";
    public const string ResponseCompression = "response-compression";
    public const string BrotliPackage = "third-party-brotli-package";
}
