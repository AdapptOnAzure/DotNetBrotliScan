namespace BrotliScan;

/// <summary>Outcome for a project or app, most severe first.</summary>
public enum Verdict
{
    /// <summary>Decodes brotli it may not trust, using a decoder known to lack the fix.</summary>
    Affected,
    /// <summary>Decodes brotli, but the decoder's patch state couldn't be confirmed.</summary>
    LikelyAffected,
    /// <summary>Needs a human: a value the scanner can't resolve, or a non-framework brotli implementation.</summary>
    Review,
    /// <summary>Decodes brotli, and the decoder carries the fix.</summary>
    Patched,
    /// <summary>No code path decodes brotli, even if a vulnerable decoder is present.</summary>
    NotExposed,
}

public enum DecoderStatus
{
    Vulnerable,
    /// <summary>Decoder embedded, but its error strings are stripped, so the fix marker can't be read.</summary>
    Unconfirmed,
    /// <summary>Links the OS libbrotlidec; patch state follows the OS package.</summary>
    SystemLibrary,
    /// <summary>Brotli present, but not recognisably the reference C decoder.</summary>
    Unknown,
    Patched,
}

public enum FindingKind
{
    /// <summary>A server decompresses request bodies, so anyone who can reach it controls the input.</summary>
    InboundRequest,
    /// <summary>An HTTP client decodes responses, so the remote server (or a man in the middle) controls the input.</summary>
    OutboundResponse,
    /// <summary>The code decodes brotli itself; exposure depends on where the data comes from.</summary>
    DirectDecode,
    /// <summary>Might decode brotli; the deciding value isn't known statically.</summary>
    Ambiguous,
    /// <summary>A brotli implementation or binding that isn't part of .NET.</summary>
    ThirdPartyBrotli,
    /// <summary>Turns off a decode path found elsewhere in the same target.</summary>
    Mitigation,
    /// <summary>Relevant context that isn't an exposure, such as response compression (encoder only).</summary>
    Info,
}

/// <param name="Rule">Stable identifier for the pattern that matched, for filtering JSON output.</param>
/// <param name="Heuristic">True when matched by text pattern rather than a syntax tree or IL.</param>
public sealed record Finding(FindingKind Kind, string Rule, string Location, string Detail, bool Heuristic = false);

/// <param name="Category">runtime, build-input, os-library or standalone.</param>
public sealed record ComponentReport(
    string Category,
    string Path,
    string? Description,
    DecoderStatus Status,
    string Evidence,
    string? VersionStamp);

/// <param name="Kind">project, sources, app, single-file app or assembly.</param>
public sealed record TargetReport(
    string Kind,
    string Path,
    string? Description,
    Verdict Verdict,
    string Reason,
    IReadOnlyList<ComponentReport> Decoders,
    IReadOnlyList<Finding> Findings);

public sealed record ScanReport(
    string Tool,
    string ToolVersion,
    string Vulnerability,
    DateTimeOffset ScannedAt,
    IReadOnlyList<string> Roots,
    long FilesExamined,
    IReadOnlyList<ComponentReport> Components,
    IReadOnlyList<TargetReport> Targets,
    IReadOnlyList<string> Errors);
