using System.Text.Json;
using System.Text.Json.Serialization;

namespace BrotliScan;

internal sealed class Reporter(TextWriter output, IReadOnlyList<string> roots, bool color, bool verbose)
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        Converters = { new JsonStringEnumConverter(JsonNamingPolicy.CamelCase) },
    };

    public static string ToJson(ScanReport report) => JsonSerializer.Serialize(report, JsonOptions);

    public void WriteText(ScanReport report, TimeSpan elapsed)
    {
        Line($"{report.Tool} {report.ToolVersion}: {report.Vulnerability}", ConsoleColor.White);
        Line(report.Roots.Count == 0
            ? $"Inspected this machine's .NET installs in {elapsed.TotalSeconds:0.0}s"
            : $"Scanned {report.FilesExamined:N0} files under {string.Join(", ", report.Roots)} in {elapsed.TotalSeconds:0.0}s");
        Line();

        WriteMachine(report);
        WriteTargets(report);
        WriteSummary(report);

        if (report.Errors.Count > 0)
        {
            Line();
            Line($"{report.Errors.Count} file(s) couldn't be read{(verbose ? ":" : " (--verbose lists them)")}", ConsoleColor.DarkYellow);
            if (verbose)
            {
                foreach (string error in report.Errors)
                {
                    Line($"  {error}", ConsoleColor.DarkGray);
                }
            }
        }
    }

    private void WriteMachine(ScanReport report)
    {
        var runtimes = report.Components.Where(c => c.Category is "runtime" or "os-library" or "platform-runtime").ToList();
        var buildInputs = report.Components.Where(c => c.Category == "build-input").ToList();
        var standalone = report.Components.Where(c => c.Category == "standalone").ToList();
        if (runtimes.Count + buildInputs.Count + standalone.Count == 0)
        {
            return;
        }

        Heading("BROTLI DECODERS");
        foreach (var component in runtimes)
        {
            Component(component, component.Description ?? component.Category);
        }

        if (buildInputs.Count > 0)
        {
            if (verbose)
            {
                foreach (var component in buildInputs)
                {
                    Component(component, component.Description ?? "build input");
                }
            }
            else
            {
                foreach (var group in buildInputs.GroupBy(c => c.Status).OrderBy(g => g.Key))
                {
                    Status(group.Key);
                    Line($"{group.Count()} build input(s) in runtime/host packs, copied into self-contained, single-file and Native AOT publishes (--verbose lists them)");
                }
            }
        }

        foreach (var component in standalone)
        {
            Component(component, "outside any app");
        }

        Line();
    }

    private void Component(ComponentReport component, string label)
    {
        Status(component.Status);
        Line($"{label}", ConsoleColor.White);
        Line($"{Indent}{Display(component.Path)}", ConsoleColor.DarkGray);
        if (verbose || component.Status != DecoderStatus.Vulnerable)
        {
            Line($"{Indent}{component.Evidence}", ConsoleColor.DarkGray);
        }
    }

    private void WriteTargets(ScanReport report)
    {
        if (report.Targets.Count == 0)
        {
            Line("No .NET projects, apps or assemblies found under the scanned paths.");
            Line();
            return;
        }

        Heading("PROJECTS AND APPS");
        foreach (var target in report.Targets)
        {
            Verdict(target.Verdict);
            Write($"{target.Kind,-16}", ConsoleColor.DarkGray);
            Write(Display(target.Path), ConsoleColor.White);
            Line(string.IsNullOrEmpty(target.Description) ? "" : $"  [{target.Description}]", ConsoleColor.DarkGray);
            Line($"{Indent}{target.Reason}");

            var shown = verbose || target.Verdict != BrotliScan.Verdict.NotExposed
                ? target.Findings
                : target.Findings.Where(f => f.Kind is FindingKind.Mitigation or FindingKind.Info).ToList();
            foreach (var finding in shown)
            {
                Write($"{Indent}{KindLabel(finding.Kind),-10}", KindColor(finding.Kind));
                Write($"{Display(finding.Location)}  ", ConsoleColor.DarkGray);
                Line(finding.Heuristic ? $"{finding.Detail} (text match)" : finding.Detail);
            }

            Line();
        }
    }

    private void WriteSummary(ScanReport report)
    {
        int Count(Verdict v) => report.Targets.Count(t => t.Verdict == v);
        Heading("SUMMARY");
        Write("  ");
        Write($"{Count(BrotliScan.Verdict.Affected)} affected", ConsoleColor.Red);
        Write(", ");
        Write($"{Count(BrotliScan.Verdict.LikelyAffected)} likely affected", ConsoleColor.Red);
        Write(", ");
        Write($"{Count(BrotliScan.Verdict.Review)} to review", ConsoleColor.Yellow);
        Write(", ");
        Write($"{Count(BrotliScan.Verdict.Patched)} patched", ConsoleColor.Green);
        Write(", ");
        Line($"{Count(BrotliScan.Verdict.NotExposed)} not exposed", ConsoleColor.Green);

        var exposed = report.Targets
            .Where(t => t.Verdict is BrotliScan.Verdict.Affected or BrotliScan.Verdict.LikelyAffected or BrotliScan.Verdict.Review)
            .SelectMany(t => t.Findings)
            .ToList();
        if (exposed.Count == 0)
        {
            return;
        }

        Line();
        Heading("WHAT TO DO");
        Line("  Install the fixed .NET runtime (released 2026-10-25) on every machine and image that runs");
        Line("  these apps, then republish self-contained, single-file and Native AOT apps and rescan:");
        Line("    .NET 10.0.14 (SDK 10.0.403 or 10.0.114), .NET 9.0.22 (SDK 9.0.320 or 9.0.123),", ConsoleColor.Cyan);
        Line("    .NET 8.0.33 (SDK 8.0.427 or 8.0.133)", ConsoleColor.Cyan);
        Line("  Older .NET versions are out of support and won't be fixed: move them to .NET 8 or later.");
        Line("  Until then, or for apps you can't update yet:");
        if (exposed.Any(f => f.Kind == FindingKind.InboundRequest))
        {
            Line("    Stop accepting brotli from clients: remove 'br' from request decompression, and don't wrap");
            Line("    request bodies in BrotliStream or register brotli decompression providers:");
            Line("      builder.Services.AddRequestDecompression(o => o.DecompressionProviders.Remove(\"br\"));", ConsoleColor.Cyan);
        }

        if (exposed.Any(f => f.Kind == FindingKind.OutboundResponse))
        {
            Line("    Drop Brotli from AutomaticDecompression:");
            Line("      handler.AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate;", ConsoleColor.Cyan);
        }

        if (exposed.Any(f => f.Kind == FindingKind.DirectDecode))
        {
            Line("    Don't pass brotli data you don't control to BrotliStream or BrotliDecoder.");
        }

        if (exposed.Any(f => f.Kind is FindingKind.Ambiguous or FindingKind.ThirdPartyBrotli))
        {
            Line("    Check each 'review' finding by hand: the scanner couldn't tell whether it decodes untrusted brotli.");
        }
    }

    private const string Indent = "                  ";

    private void Verdict(Verdict verdict)
    {
        var (label, color) = verdict switch
        {
            BrotliScan.Verdict.Affected => ("AFFECTED", ConsoleColor.Red),
            BrotliScan.Verdict.LikelyAffected => ("LIKELY AFFECTED", ConsoleColor.Red),
            BrotliScan.Verdict.Review => ("REVIEW", ConsoleColor.Yellow),
            BrotliScan.Verdict.Patched => ("PATCHED", ConsoleColor.Green),
            _ => ("NOT EXPOSED", ConsoleColor.Green),
        };
        Write($"  {label,-16}", color);
    }

    private void Status(DecoderStatus status)
    {
        var (label, color) = status switch
        {
            DecoderStatus.Vulnerable => ("VULNERABLE", ConsoleColor.Red),
            DecoderStatus.Unconfirmed => ("UNCONFIRMED", ConsoleColor.Yellow),
            DecoderStatus.SystemLibrary => ("OS LIBRARY", ConsoleColor.Yellow),
            DecoderStatus.Unknown => ("UNKNOWN", ConsoleColor.Yellow),
            _ => ("PATCHED", ConsoleColor.Green),
        };
        Write($"  {label,-16}", color);
    }

    private static string KindLabel(FindingKind kind) => kind switch
    {
        FindingKind.InboundRequest => "inbound",
        FindingKind.OutboundResponse => "outbound",
        FindingKind.DirectDecode => "decode",
        FindingKind.Ambiguous => "review",
        FindingKind.ThirdPartyBrotli => "3rd-party",
        FindingKind.Mitigation => "mitigated",
        _ => "info",
    };

    private static ConsoleColor KindColor(FindingKind kind) => kind switch
    {
        FindingKind.InboundRequest or FindingKind.OutboundResponse or FindingKind.DirectDecode => ConsoleColor.Red,
        FindingKind.Ambiguous or FindingKind.ThirdPartyBrotli => ConsoleColor.Yellow,
        FindingKind.Mitigation => ConsoleColor.Green,
        _ => ConsoleColor.DarkGray,
    };

    /// <summary>Shows paths relative to the scan root they came from.</summary>
    private string Display(string path)
    {
        foreach (string root in roots.OrderByDescending(r => r.Length))
        {
            if (path.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.Ordinal))
            {
                return path[(root.Length + 1)..];
            }
        }

        return path;
    }

    private void Heading(string text) => Line(text, ConsoleColor.White);

    private void Line(string text = "", ConsoleColor? foreground = null)
    {
        Write(text, foreground);
        output.WriteLine();
    }

    private void Write(string text, ConsoleColor? foreground = null)
    {
        if (color && foreground is { } c)
        {
            Console.ForegroundColor = c;
            output.Write(text);
            Console.ResetColor();
        }
        else
        {
            output.Write(text);
        }
    }
}
