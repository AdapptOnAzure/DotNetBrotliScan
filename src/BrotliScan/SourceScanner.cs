using System.Text.RegularExpressions;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;

namespace BrotliScan;

/// <summary>
/// Finds brotli decode paths in source. C# is parsed with Roslyn (syntax only, no compilation);
/// VB and F# use text patterns, and their findings are marked heuristic.
/// </summary>
internal static class SourceScanner
{
    private static readonly CSharpParseOptions ParseOptions = CSharpParseOptions.Default
        .WithLanguageVersion(LanguageVersion.Preview)
        .WithPreprocessorSymbols(PreprocessorSymbols());

    // Defining these keeps most #if-guarded code visible to the walker.
    private static IEnumerable<string> PreprocessorSymbols()
    {
        string[] fixedSymbols =
        [
            "DEBUG", "RELEASE", "TRACE", "NET", "NETCOREAPP", "NETSTANDARD",
            "NETCOREAPP2_1_OR_GREATER", "NETCOREAPP3_0_OR_GREATER", "NETCOREAPP3_1_OR_GREATER",
            "NETSTANDARD2_0_OR_GREATER", "NETSTANDARD2_1_OR_GREATER",
        ];
        return fixedSymbols.Concat(Enumerable.Range(5, 8).Select(v => $"NET{v}_0_OR_GREATER"));
    }

    public static List<Finding> ScanCSharp(string text, string displayPath)
    {
        var tree = CSharpSyntaxTree.ParseText(text, ParseOptions, displayPath);
        var walker = new CSharpWalker(displayPath);
        walker.Visit(tree.GetRoot());
        return walker.Findings;
    }

    private sealed class CSharpWalker(string displayPath) : CSharpSyntaxWalker
    {
        private readonly HashSet<(string Rule, int Line)> _seen = [];

        public List<Finding> Findings { get; } = [];

        public override void VisitInvocationExpression(InvocationExpressionSyntax node)
        {
            switch (InvokedName(node.Expression))
            {
                case "UseRequestDecompression":
                    Add(FindingKind.InboundRequest, Rules.RequestDecompression, node,
                        "UseRequestDecompression(): accepts brotli-compressed request bodies from clients ('br' is on unless removed)");
                    break;
                case "UseResponseCompression":
                    Add(FindingKind.Info, Rules.ResponseCompression, node,
                        "UseResponseCompression(): compresses responses with the brotli encoder, which isn't affected");
                    break;
                case "Remove" when OnDecompressionProviders(node.Expression) && FirstArgumentIsBr(node):
                    Add(FindingKind.Mitigation, Rules.BrProviderRemoved, node, "removes the 'br' request decompression provider");
                    break;
                case "Clear" when OnDecompressionProviders(node.Expression):
                    Add(FindingKind.Mitigation, Rules.ProvidersCleared, node, "clears the request decompression providers");
                    break;
                case "Add" or "TryAdd" when OnDecompressionProviders(node.Expression) && FirstArgumentIsBr(node):
                    Add(FindingKind.InboundRequest, Rules.BrProviderAdded, node, "registers a 'br' request decompression provider");
                    break;
            }

            base.VisitInvocationExpression(node);
        }

        public override void VisitIdentifierName(IdentifierNameSyntax node)
        {
            // BrotliDecoder exists only to decode, so any use of the type is a decode path.
            if (node.Identifier.ValueText == "BrotliDecoder")
            {
                Add(FindingKind.DirectDecode, Rules.BrotliDecoder, node, "uses BrotliDecoder");
            }

            base.VisitIdentifierName(node);
        }

        public override void VisitObjectCreationExpression(ObjectCreationExpressionSyntax node)
        {
            if (LastIdentifier(node.Type) == "BrotliStream")
            {
                CheckBrotliStream(node, node.ArgumentList);
            }

            base.VisitObjectCreationExpression(node);
        }

        public override void VisitImplicitObjectCreationExpression(ImplicitObjectCreationExpressionSyntax node)
        {
            // BrotliStream s = new(...);
            if (node.Parent is EqualsValueClauseSyntax { Parent: VariableDeclaratorSyntax { Parent: VariableDeclarationSyntax declaration } }
                && LastIdentifier(declaration.Type) == "BrotliStream")
            {
                CheckBrotliStream(node, node.ArgumentList);
            }

            base.VisitImplicitObjectCreationExpression(node);
        }

        public override void VisitAssignmentExpression(AssignmentExpressionSyntax node)
        {
            // options.DecompressionProviders["br"] = new MyProvider();
            if (node.Left is ElementAccessExpressionSyntax element && LastName(element.Expression) == "DecompressionProviders"
                && element.ArgumentList.Arguments.FirstOrDefault()?.Expression is LiteralExpressionSyntax { Token.ValueText: var key }
                && key.Equals("br", StringComparison.OrdinalIgnoreCase))
            {
                Add(FindingKind.InboundRequest, Rules.BrProviderAdded, node, "registers a 'br' request decompression provider: accepts brotli from clients");
            }

            // Covers plain and compound assignment and object initializers. "&=" can only remove flags.
            if (LastName(node.Left) == "AutomaticDecompression" && !node.IsKind(SyntaxKind.AndAssignmentExpression))
            {
                switch (ClassifyDecompressionMethods(node.Right))
                {
                    case MethodsValue.IncludesBrotli:
                        Add(FindingKind.OutboundResponse, Rules.AutomaticDecompression, node,
                            $"AutomaticDecompression = {node.Right}: responses with Content-Encoding: br are decoded");
                        break;
                    case MethodsValue.Unresolved:
                        Add(FindingKind.Ambiguous, Rules.AutomaticDecompressionUnknown, node,
                            $"AutomaticDecompression = {node.Right}: value can't be resolved statically (e.g. configuration)");
                        break;
                }
            }

            base.VisitAssignmentExpression(node);
        }

        public override void VisitMemberAccessExpression(MemberAccessExpressionSyntax node)
        {
            if (LastName(node.Expression) == "DecompressionMethods"
                && node.Name.Identifier.ValueText is "Brotli" or "All"
                && !node.Ancestors().OfType<AssignmentExpressionSyntax>().Any(a => LastName(a.Left) == "AutomaticDecompression"))
            {
                Add(FindingKind.Ambiguous, Rules.DecompressionMethodsElsewhere, node,
                    $"{node} used outside an AutomaticDecompression assignment; check where it flows");
            }

            base.VisitMemberAccessExpression(node);
        }

        private void CheckBrotliStream(ExpressionSyntax node, ArgumentListSyntax? arguments)
        {
            if (arguments is null)
            {
                return;
            }

            var argument = arguments.Arguments.FirstOrDefault(a => a.NameColon?.Name.Identifier.ValueText is "mode" or "compressionLevel" or "compressionOptions")
                ?? (arguments.Arguments.Count > 1 ? arguments.Arguments[1] : null);
            if (argument is null)
            {
                return;
            }

            switch (ClassifyMode(argument.Expression))
            {
                case StreamMode.Decompress when EnclosingProvider(node) is { } provider:
                    Add(FindingKind.InboundRequest, Rules.DecompressionProvider, node,
                        $"BrotliStream decompression in a {provider}: decodes brotli sent by clients");
                    break;
                case StreamMode.Decompress when StreamArgument(arguments) is { } stream && ReadsRequestBody(stream, node, 0):
                    Add(FindingKind.InboundRequest, Rules.RequestBodyBrotliStream, node,
                        "decodes the request body with BrotliStream: clients can send brotli-compressed data");
                    break;
                case StreamMode.Decompress:
                    Add(FindingKind.DirectDecode, Rules.BrotliStreamDecompress, node, "new BrotliStream(..., CompressionMode.Decompress)");
                    break;
                case StreamMode.Unresolved:
                    Add(FindingKind.Ambiguous, Rules.BrotliStreamUnknown, node,
                        $"new BrotliStream(..., {argument.Expression}): mode can't be resolved statically; check whether it decompresses");
                    break;
            }
        }

        private void Add(FindingKind kind, string rule, SyntaxNode node, string detail)
        {
            int line = node.GetLocation().GetLineSpan().StartLinePosition.Line + 1;
            if (_seen.Add((rule, line)))
            {
                Findings.Add(new Finding(kind, rule, $"{displayPath}:{line}", detail));
            }
        }
    }

    private enum StreamMode { Compress, Decompress, Unresolved }

    private static ExpressionSyntax? StreamArgument(ArgumentListSyntax arguments) =>
        (arguments.Arguments.FirstOrDefault(a => a.NameColon?.Name.Identifier.ValueText == "stream")
            ?? arguments.Arguments.FirstOrDefault(a => a.NameColon is null))?.Expression;

    /// <summary>
    /// True when the stream comes from an HTTP request body: request.Body or request.BodyReader directly,
    /// or a local assigned from one in the same method (followed a few hops).
    /// </summary>
    private static bool ReadsRequestBody(ExpressionSyntax expression, SyntaxNode site, int depth)
    {
        if (expression.DescendantNodesAndSelf().OfType<MemberAccessExpressionSyntax>()
            .Any(m => m.Name.Identifier.ValueText is "Body" or "BodyReader"))
        {
            return true;
        }

        if (depth >= 3 || expression is not IdentifierNameSyntax { Identifier.ValueText: var name })
        {
            return false;
        }

        // Top-level statements have no method, so the compilation unit is the scope.
        var scope = site.Ancestors().FirstOrDefault(a => a is BaseMethodDeclarationSyntax or LocalFunctionStatementSyntax
            or AnonymousFunctionExpressionSyntax or AccessorDeclarationSyntax or CompilationUnitSyntax);
        if (scope is null)
        {
            return false;
        }

        var sources = scope.DescendantNodes().OfType<VariableDeclaratorSyntax>()
            .Where(v => v.Identifier.ValueText == name && v.Initializer is not null)
            .Select(v => v.Initializer!.Value)
            .Concat(scope.DescendantNodes().OfType<AssignmentExpressionSyntax>()
                .Where(a => a.Left is IdentifierNameSyntax { Identifier.ValueText: var target } && target == name)
                .Select(a => a.Right));
        return sources.Any(source => ReadsRequestBody(source, site, depth + 1));
    }

    /// <summary>Names the request-decoding interface the enclosing type implements, if any.</summary>
    private static string? EnclosingProvider(SyntaxNode node) =>
        node.Ancestors().OfType<TypeDeclarationSyntax>().FirstOrDefault()?.BaseList?.Types
            .Select(t => LastIdentifier(t.Type))
            .Select(name => name switch
            {
                "IDecompressionProvider" => "request decompression provider (IDecompressionProvider)",
                "ICompressionProvider" => "gRPC compression provider (ICompressionProvider)",
                _ => null,
            })
            .FirstOrDefault(n => n is not null);

    private enum MethodsValue { WithoutBrotli, IncludesBrotli, Unresolved }

    private static StreamMode ClassifyMode(ExpressionSyntax expression)
    {
        while (expression is ParenthesizedExpressionSyntax or CastExpressionSyntax)
        {
            expression = expression is CastExpressionSyntax cast ? cast.Expression : ((ParenthesizedExpressionSyntax)expression).Expression;
        }

        return expression switch
        {
            LiteralExpressionSyntax { Token.Value: 0 } => StreamMode.Decompress,
            LiteralExpressionSyntax => StreamMode.Compress,
            MemberAccessExpressionSyntax { Name.Identifier.ValueText: "Decompress" } => StreamMode.Decompress,
            MemberAccessExpressionSyntax { Name.Identifier.ValueText: "Compress" } => StreamMode.Compress,
            MemberAccessExpressionSyntax access when LastName(access.Expression) == "CompressionLevel" => StreamMode.Compress,
            BaseObjectCreationExpressionSyntax => StreamMode.Compress, // new BrotliCompressionOptions { ... }
            _ => StreamMode.Unresolved,
        };
    }

    private static MethodsValue ClassifyDecompressionMethods(ExpressionSyntax expression)
    {
        bool brotli = false, unresolved = false;
        foreach (var node in expression.DescendantNodesAndSelf())
        {
            switch (node)
            {
                // Only member accesses in value position; "System.Net" in "System.Net.DecompressionMethods.GZip" isn't one.
                case MemberAccessExpressionSyntax access when access.Parent is not MemberAccessExpressionSyntax parent || parent.Expression != access:
                    if (LastName(access.Expression) == "DecompressionMethods")
                    {
                        string flag = access.Name.Identifier.ValueText;
                        if (flag is "Brotli" or "All")
                        {
                            brotli |= !access.Ancestors().TakeWhile(a => a != expression.Parent).Any(a => a.IsKind(SyntaxKind.BitwiseNotExpression));
                        }
                        else if (flag is not ("GZip" or "Deflate" or "None"))
                        {
                            unresolved = true;
                        }
                    }
                    else
                    {
                        unresolved = true;
                    }

                    break;
                case IdentifierNameSyntax when node.Parent is not MemberAccessExpressionSyntax:
                case InvocationExpressionSyntax:
                    unresolved = true;
                    break;
                case LiteralExpressionSyntax { Token.Value: int value }:
                    brotli |= value == -1 || (value & 4) != 0;
                    break;
            }
        }

        return brotli ? MethodsValue.IncludesBrotli : unresolved ? MethodsValue.Unresolved : MethodsValue.WithoutBrotli;
    }

    private static bool OnDecompressionProviders(ExpressionSyntax invoked) =>
        invoked is MemberAccessExpressionSyntax access && LastName(access.Expression) == "DecompressionProviders";

    private static bool FirstArgumentIsBr(InvocationExpressionSyntax node) =>
        node.ArgumentList.Arguments.FirstOrDefault()?.Expression is LiteralExpressionSyntax literal
        && string.Equals(literal.Token.ValueText, "br", StringComparison.OrdinalIgnoreCase);

    private static string? InvokedName(ExpressionSyntax expression) => expression switch
    {
        MemberAccessExpressionSyntax access => access.Name.Identifier.ValueText,
        MemberBindingExpressionSyntax binding => binding.Name.Identifier.ValueText,
        SimpleNameSyntax name => name.Identifier.ValueText,
        _ => null,
    };

    private static string? LastName(ExpressionSyntax expression) => expression switch
    {
        MemberAccessExpressionSyntax access => access.Name.Identifier.ValueText,
        MemberBindingExpressionSyntax binding => binding.Name.Identifier.ValueText,
        SimpleNameSyntax name => name.Identifier.ValueText,
        AliasQualifiedNameSyntax alias => alias.Name.Identifier.ValueText,
        _ => null,
    };

    private static string? LastIdentifier(TypeSyntax type) => type switch
    {
        SimpleNameSyntax name => name.Identifier.ValueText,
        QualifiedNameSyntax qualified => qualified.Right.Identifier.ValueText,
        AliasQualifiedNameSyntax alias => alias.Name.Identifier.ValueText,
        _ => null,
    };

    // VB and F#: patterns over comment-stripped text. The IL scanner is exact for these languages
    // once they're built, so point it at the build output for a definitive answer.
    private static readonly TimeSpan RegexTimeout = TimeSpan.FromSeconds(1);

    private static readonly (Regex Pattern, FindingKind Kind, string Rule, string Detail)[] TextRules =
    [
        (Pattern(@"\bUseRequestDecompression\s*\("), FindingKind.InboundRequest, Rules.RequestDecompression,
            "UseRequestDecompression(): accepts brotli-compressed request bodies from clients ('br' is on unless removed)"),
        (Pattern(@"\bBrotliStream\b[^\r\n]*\.(?:Body|BodyReader)\b[^\r\n]*\bCompressionMode\.Decompress\b"), FindingKind.InboundRequest, Rules.RequestBodyBrotliStream,
            "decodes the request body with BrotliStream: clients can send brotli-compressed data"),
        (Pattern(@"\bDecompressionProviders\b[^\r\n]*\.Remove\s*\(\s*""br"""), FindingKind.Mitigation, Rules.BrProviderRemoved,
            "removes the 'br' request decompression provider"),
        (Pattern(@"\bBrotliDecoder\b"), FindingKind.DirectDecode, Rules.BrotliDecoder, "uses BrotliDecoder"),
        (Pattern(@"\bBrotliStream\b[^\r\n]*\bCompressionMode\.Decompress\b"), FindingKind.DirectDecode, Rules.BrotliStreamDecompress,
            "BrotliStream with CompressionMode.Decompress"),
        (Pattern(@"\bAutomaticDecompression\s*(?:=|<-|:=)[^\r\n]*\b(?:Brotli|All)\b"), FindingKind.OutboundResponse, Rules.AutomaticDecompression,
            "AutomaticDecompression includes Brotli: responses with Content-Encoding: br are decoded"),
        (Pattern(@"\bUseResponseCompression\s*\("), FindingKind.Info, Rules.ResponseCompression,
            "UseResponseCompression(): compresses responses with the brotli encoder, which isn't affected"),
    ];

    private static Regex Pattern(string pattern) =>
        new(pattern, RegexOptions.CultureInvariant | RegexOptions.Compiled, RegexTimeout);

    private static readonly Regex VisualBasicComment = Pattern(@"(?m)(?:^|(?<=\s))(?:'|REM\s)[^\r\n]*");
    private static readonly Regex FSharpComment = Pattern(@"\(\*[\s\S]*?\*\)|//[^\r\n]*");

    public static List<Finding> ScanText(string text, string displayPath, bool fsharp)
    {
        // Blank comments out but keep their newlines, so line numbers still match the file.
        text = (fsharp ? FSharpComment : VisualBasicComment).Replace(text, m => new string(m.Value.Select(c => c is '\r' or '\n' ? c : ' ').ToArray()));

        var findings = new List<Finding>();
        foreach (var (pattern, kind, rule, detail) in TextRules)
        {
            try
            {
                foreach (Match match in pattern.Matches(text))
                {
                    int line = 1 + text.AsSpan(0, match.Index).Count('\n');
                    findings.Add(new Finding(kind, rule, $"{displayPath}:{line}", detail, Heuristic: true));
                }
            }
            catch (RegexMatchTimeoutException)
            {
                findings.Add(new Finding(FindingKind.Ambiguous, rule, displayPath, "pattern timed out on this file; review it manually", Heuristic: true));
            }
        }

        return findings;
    }
}
