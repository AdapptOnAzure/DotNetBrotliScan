using System.Buffers.Binary;
using System.Collections.Immutable;
using System.Reflection;
using System.Reflection.Emit;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using System.Reflection.PortableExecutable;
using System.Security.Cryptography;

namespace BrotliScan;

internal sealed record AssemblyScanResult(string Name, bool IsFramework, IReadOnlyList<Finding> Findings);

/// <summary>
/// Finds brotli decode paths in compiled IL. Reads metadata only; assemblies are never loaded.
/// Works for any .NET language, and sees code from NuGet dependencies that a source scan can't.
/// </summary>
internal static class AssemblyScanner
{
    // Shared-framework assemblies contain the decode paths themselves (e.g. System.Net.Http's
    // DecompressionHandler); they only matter when app code turns them on, which is what we look for.
    private static readonly HashSet<string> FrameworkKeyTokens =
        ["b03f5f7f11d50a3a", "cc7b13ffcd2ddd51", "adb9793829ddae60", "7cec85d7bea7798e", "31bf3856ad364e35"];

    private static readonly string[] FrameworkNamePrefixes =
    [
        "System.", "Microsoft.AspNetCore.", "Microsoft.Extensions.", "Microsoft.Win32.", "Microsoft.VisualBasic",
        "Microsoft.CSharp", "Microsoft.JSInterop", "Microsoft.Net.Http.Headers", "Microsoft.NETCore.",
        "WindowsBase", "PresentationCore", "PresentationFramework",
    ];

    private static readonly HashSet<string> FrameworkNames = ["System", "mscorlib", "netstandard"];

    private static readonly Dictionary<ushort, OpInfo> OpCodeTable = BuildOpCodeTable();

    /// <param name="Pops">Values popped; -1 when it depends on a signature (calls) or is unknown.</param>
    /// <param name="Pushes">Values pushed; -1 when it depends on a signature.</param>
    private readonly record struct OpInfo(OperandType Operand, int Pops, int Pushes, FlowControl Flow);

    private const ushort Call = 0x28, Callvirt = 0x6f, Newobj = 0x73, Ldstr = 0x72, Ldfld = 0x7b, Stfld = 0x7d;

    // Interfaces whose implementations decode what clients send.
    private static readonly Dictionary<string, string> ProviderInterfaces = new(StringComparer.Ordinal)
    {
        ["Microsoft.AspNetCore.RequestDecompression.IDecompressionProvider"] = "request decompression provider (IDecompressionProvider)",
        ["Grpc.Net.Compression.ICompressionProvider"] = "gRPC compression provider (ICompressionProvider)",
    };
    private const int DecompressionMethodsBrotli = 4;

    private enum Target
    {
        None,
        UseRequestDecompression,
        UseResponseCompression,
        SetAutomaticDecompression,
        BrotliStreamModeCtor,         // (Stream, CompressionMode)
        BrotliStreamModeLeaveOpenCtor, // (Stream, CompressionMode, bool)
        BrotliDecoderDecode,
        GetDecompressionProviders,
        GetRequestBody,
    }

    private readonly record struct Instruction(ushort OpCode, int Operand);

    public static AssemblyScanResult Scan(PEReader pe, string displayPath)
    {
        var md = pe.GetMetadataReader();
        string name = md.IsAssembly ? md.GetString(md.GetAssemblyDefinition().Name) : Path.GetFileNameWithoutExtension(displayPath);
        if (IsFramework(md, name))
        {
            return new(name, true, []);
        }

        var targets = ClassifyMemberReferences(md);
        if (targets.Count == 0)
        {
            return new(name, false, []);
        }

        var findings = new List<Finding>();
        foreach (var handle in md.MethodDefinitions)
        {
            var method = md.GetMethodDefinition(handle);
            if (method.RelativeVirtualAddress == 0)
            {
                continue;
            }

            byte[]? il;
            try
            {
                il = pe.GetMethodBody(method.RelativeVirtualAddress).GetILBytes();
            }
            catch (BadImageFormatException)
            {
                continue;
            }

            if (il is { Length: > 0 })
            {
                ScanBody(md, targets, il, method, displayPath, findings);
            }
        }

        return new(name, false, findings.DistinctBy(f => (f.Rule, f.Location)).ToList());
    }

    private static void ScanBody(
        MetadataReader md, Dictionary<EntityHandle, Target> targets, byte[] il,
        MethodDefinition method, string displayPath, List<Finding> findings)
    {
        Instruction prev1 = default, prev2 = default;
        bool brAfterProviders = false;
        string? provider = Provider(md, method);

        // Symbolic evaluation stack: each slot records whether the value is an HTTP request body. Locals and
        // fields (async state machines hoist locals into fields) carry that through. Branches aren't followed,
        // so anything this misses still reports as a direct decode, never as nothing.
        var stack = new List<bool>();
        var bodyLocals = new HashSet<int>();
        var bodyFields = new HashSet<int>();
        int position = 0;

        while (TryRead(il, ref position, out var ins))
        {
            if (ins.OpCode == Ldstr && brAfterProviders is false && IsCall(prev1, targets, Target.GetDecompressionProviders))
            {
                brAfterProviders = IsBrString(md, ins);
            }

            if (ins.OpCode is Call or Callvirt or Newobj)
            {
                var handle = Resolve(md, ins.Operand);
                targets.TryGetValue(handle, out var target);
                string Where() => $"{displayPath}: {Describe(md, method)}";

                switch (target)
                {
                    case Target.UseRequestDecompression:
                        findings.Add(new(FindingKind.InboundRequest, Rules.RequestDecompression, Where(),
                            "calls UseRequestDecompression(): accepts brotli-compressed request bodies from clients ('br' is on unless removed)"));
                        break;

                    case Target.UseResponseCompression:
                        findings.Add(new(FindingKind.Info, Rules.ResponseCompression, Where(),
                            "calls UseResponseCompression(): compresses responses with the brotli encoder, which isn't affected"));
                        break;

                    case Target.SetAutomaticDecompression:
                        switch (Constant(prev1))
                        {
                            case null:
                                findings.Add(new(FindingKind.Ambiguous, Rules.AutomaticDecompressionUnknown, Where(),
                                    "sets AutomaticDecompression from a value not known at compile time"));
                                break;
                            case int value when value == -1 || (value & DecompressionMethodsBrotli) != 0:
                                findings.Add(new(FindingKind.OutboundResponse, Rules.AutomaticDecompression, Where(),
                                    $"sets AutomaticDecompression = {DescribeMethods(value)}: responses with Content-Encoding: br are decoded"));
                                break;
                        }

                        break;

                    case Target.BrotliStreamModeCtor or Target.BrotliStreamModeLeaveOpenCtor:
                        bool leaveOpen = target == Target.BrotliStreamModeLeaveOpenCtor;
                        int? mode = !leaveOpen
                            ? Constant(prev1)
                            : Constant(prev1) is null ? null : Constant(prev2);
                        int streamSlot = stack.Count - (leaveOpen ? 3 : 2);
                        bool fromRequest = streamSlot >= 0 && stack[streamSlot];
                        if (mode == 0 && provider is not null)
                        {
                            findings.Add(new(FindingKind.InboundRequest, Rules.DecompressionProvider, Where(),
                                $"BrotliStream decompression in a {provider}: decodes brotli sent by clients"));
                        }
                        else if (mode == 0 && fromRequest)
                        {
                            findings.Add(new(FindingKind.InboundRequest, Rules.RequestBodyBrotliStream, Where(),
                                "decodes the request body with BrotliStream: clients can send brotli-compressed data"));
                        }
                        else if (mode == 0)
                        {
                            findings.Add(new(FindingKind.DirectDecode, Rules.BrotliStreamDecompress, Where(),
                                "creates BrotliStream(..., CompressionMode.Decompress)"));
                        }
                        else if (mode is null)
                        {
                            findings.Add(new(FindingKind.Ambiguous, Rules.BrotliStreamUnknown, Where(),
                                "creates BrotliStream with a CompressionMode not known at compile time"));
                        }

                        break;

                    case Target.BrotliDecoderDecode:
                        findings.Add(new(FindingKind.DirectDecode, Rules.BrotliDecoder, Where(),
                            $"calls BrotliDecoder.{MethodName(md, handle)}()"));
                        break;

                    case Target.None when brAfterProviders:
                        switch (MethodName(md, handle))
                        {
                            case "Remove":
                                findings.Add(new(FindingKind.Mitigation, Rules.BrProviderRemoved, Where(),
                                    "removes the 'br' request decompression provider"));
                                brAfterProviders = false;
                                break;
                            case "Add" or "TryAdd" or "set_Item":
                                findings.Add(new(FindingKind.InboundRequest, Rules.BrProviderAdded, Where(),
                                    "registers a 'br' request decompression provider"));
                                brAfterProviders = false;
                                break;
                        }

                        break;

                    case Target.None when MethodName(md, handle) == "Clear" && IsCall(prev1, targets, Target.GetDecompressionProviders):
                        findings.Add(new(FindingKind.Mitigation, Rules.ProvidersCleared, Where(),
                            "clears the request decompression providers"));
                        break;
                }
            }

            Simulate(md, targets, ins, stack, bodyLocals, bodyFields);
            prev2 = prev1;
            prev1 = ins;
        }
    }

    private static Dictionary<EntityHandle, Target> ClassifyMemberReferences(MetadataReader md)
    {
        var targets = new Dictionary<EntityHandle, Target>();
        foreach (var handle in md.MemberReferences)
        {
            var reference = md.GetMemberReference(handle);
            if (reference.GetKind() != MemberReferenceKind.Method)
            {
                continue;
            }

            string member = md.GetString(reference.Name);
            var target = (TypeName(md, reference.Parent), member) switch
            {
                ("Microsoft.AspNetCore.Builder.RequestDecompressionBuilderExtensions", "UseRequestDecompression") => Target.UseRequestDecompression,
                ("Microsoft.AspNetCore.Builder.ResponseCompressionBuilderExtensions", "UseResponseCompression") => Target.UseResponseCompression,
                ("Microsoft.AspNetCore.RequestDecompression.RequestDecompressionOptions", "get_DecompressionProviders") => Target.GetDecompressionProviders,
                ("Microsoft.AspNetCore.Http.HttpRequest", "get_Body") => Target.GetRequestBody,
                ("System.IO.Compression.BrotliDecoder", "Decompress" or "TryDecompress") => Target.BrotliDecoderDecode,
                ("System.IO.Compression.BrotliStream", ".ctor") => ClassifyBrotliStreamConstructor(md, reference),
                // Any handler type: HttpClientHandler, SocketsHttpHandler, WinHttpHandler, HttpWebRequest, subclasses.
                (_, "set_AutomaticDecompression") => Target.SetAutomaticDecompression,
                _ => Target.None,
            };

            if (target != Target.None)
            {
                targets[handle] = target;
            }
        }

        return targets;
    }

    private static Target ClassifyBrotliStreamConstructor(MetadataReader md, MemberReference reference)
    {
        // The CompressionLevel and BrotliCompressionOptions overloads only compress.
        return reference.DecodeMethodSignature(SignatureTypeNames.Instance, null).ParameterTypes switch
        {
            ["System.IO.Stream", "System.IO.Compression.CompressionMode"] => Target.BrotliStreamModeCtor,
            ["System.IO.Stream", "System.IO.Compression.CompressionMode", "System.Boolean"] => Target.BrotliStreamModeLeaveOpenCtor,
            _ => Target.None,
        };
    }

    private static bool IsFramework(MetadataReader md, string name)
    {
        if (!FrameworkNames.Contains(name) && !FrameworkNamePrefixes.Any(p => name.StartsWith(p, StringComparison.Ordinal)))
        {
            return false;
        }

        if (!md.IsAssembly)
        {
            return false;
        }

        byte[] key = md.GetBlobBytes(md.GetAssemblyDefinition().PublicKey);
        if (key.Length == 0)
        {
            return false;
        }

        // Public key token: last 8 bytes of the key's SHA-1, reversed (ECMA-335 II.6.3). Identification, not security.
#pragma warning disable CA5350
        var token = SHA1.HashData(key).AsSpan(^8).ToArray();
#pragma warning restore CA5350
        Array.Reverse(token);
        return FrameworkKeyTokens.Contains(Convert.ToHexString(token).ToLowerInvariant());
    }

    private static bool IsCall(Instruction ins, Dictionary<EntityHandle, Target> targets, Target target) =>
        ins.OpCode is Call or Callvirt && targets.TryGetValue(MetadataTokens.EntityHandle(ins.Operand), out var t) && t == target;

    private static bool IsBrString(MetadataReader md, Instruction ins)
    {
        try
        {
            return string.Equals(md.GetUserString(MetadataTokens.UserStringHandle(ins.Operand & 0x00ffffff)), "br", StringComparison.OrdinalIgnoreCase);
        }
        catch (BadImageFormatException)
        {
            return false;
        }
    }

    private static void Simulate(
        MetadataReader md, Dictionary<EntityHandle, Target> targets, Instruction ins,
        List<bool> stack, HashSet<int> bodyLocals, HashSet<int> bodyFields)
    {
        bool Pop()
        {
            if (stack.Count == 0)
            {
                return false;
            }

            bool top = stack[^1];
            stack.RemoveAt(stack.Count - 1);
            return top;
        }

        var info = OpCodeTable[ins.OpCode];
        switch (ins.OpCode)
        {
            case 0x25: // dup
                stack.Add(stack.Count > 0 && stack[^1]);
                return;
            case Ldfld:
                Pop();
                stack.Add(bodyFields.Contains(ins.Operand));
                return;
            case Stfld:
                if (Pop())
                {
                    bodyFields.Add(ins.Operand);
                }

                Pop();
                return;
        }

        if (LocalIndex(ins, load: true) is { } loaded)
        {
            stack.Add(bodyLocals.Contains(loaded));
            return;
        }

        if (LocalIndex(ins, load: false) is { } stored)
        {
            if (Pop())
            {
                bodyLocals.Add(stored);
            }
            else
            {
                bodyLocals.Remove(stored);
            }

            return;
        }

        int pops = info.Pops, pushes = info.Pushes;
        bool isBody = false;
        if (ins.OpCode is Call or Callvirt or Newobj)
        {
            if (CallStackEffect(md, ins) is not { } effect)
            {
                stack.Clear();
                return;
            }

            (pops, pushes) = effect;
            isBody = IsCall(ins, targets, Target.GetRequestBody);
        }

        // Control leaves this straight line (or the effect is unknown): the next instruction starts fresh.
        if (pops < 0 || pushes < 0 || info.Flow is FlowControl.Branch or FlowControl.Return or FlowControl.Throw)
        {
            stack.Clear();
            return;
        }

        for (int i = 0; i < pops; i++)
        {
            Pop();
        }

        for (int i = 0; i < pushes; i++)
        {
            stack.Add(isBody);
        }
    }

    /// <summary>How many values a call pops (arguments plus 'this') and pushes (its result).</summary>
    private static (int Pops, int Pushes)? CallStackEffect(MetadataReader md, Instruction ins)
    {
        try
        {
            var handle = Resolve(md, ins.Operand);
            MethodSignature<string> signature = handle.Kind switch
            {
                HandleKind.MemberReference => md.GetMemberReference((MemberReferenceHandle)handle).DecodeMethodSignature(SignatureTypeNames.Instance, null),
                HandleKind.MethodDefinition => md.GetMethodDefinition((MethodDefinitionHandle)handle).DecodeSignature(SignatureTypeNames.Instance, null),
                _ => throw new BadImageFormatException(),
            };
            bool instance = signature.Header.IsInstance;
            return ins.OpCode == Newobj
                ? (signature.ParameterTypes.Length, 1)
                : (signature.ParameterTypes.Length + (instance ? 1 : 0), signature.ReturnType == "System.Void" ? 0 : 1);
        }
        catch (BadImageFormatException)
        {
            return null;
        }
    }

    /// <summary>The local slot a ldloc (load) or stloc (store) instruction uses.</summary>
    private static int? LocalIndex(Instruction ins, bool load) => (load, ins.OpCode) switch
    {
        (true, >= 0x06 and <= 0x09) => ins.OpCode - 0x06,  // ldloc.0 .. ldloc.3
        (true, 0x11 or 0xfe0c) => ins.Operand,            // ldloc.s, ldloc
        (false, >= 0x0a and <= 0x0d) => ins.OpCode - 0x0a, // stloc.0 .. stloc.3
        (false, 0x13 or 0xfe0e) => ins.Operand,           // stloc.s, stloc
        _ => null,
    };

    /// <summary>Describes the request-decoding interface the method's type implements, if any.</summary>
    private static string? Provider(MetadataReader md, MethodDefinition method)
    {
        try
        {
            var type = md.GetTypeDefinition(method.GetDeclaringType());
            foreach (var handle in type.GetInterfaceImplementations())
            {
                if (ProviderInterfaces.TryGetValue(TypeName(md, md.GetInterfaceImplementation(handle).Interface), out var description))
                {
                    return description;
                }
            }
        }
        catch (BadImageFormatException)
        {
        }

        return null;
    }

    private static int? Constant(Instruction ins) => ins.OpCode switch
    {
        0x15 => -1,                       // ldc.i4.m1
        >= 0x16 and <= 0x1e => ins.OpCode - 0x16, // ldc.i4.0 .. ldc.i4.8
        0x1f or 0x20 => ins.Operand,      // ldc.i4.s, ldc.i4
        _ => null,
    };

    private static string DescribeMethods(int value)
    {
        if (value == -1)
        {
            return "DecompressionMethods.All";
        }

        var names = new List<string>();
        if ((value & 1) != 0) names.Add("GZip");
        if ((value & 2) != 0) names.Add("Deflate");
        if ((value & 4) != 0) names.Add("Brotli");
        return string.Join(" | ", names.Select(n => "DecompressionMethods." + n));
    }

    private static EntityHandle Resolve(MetadataReader md, int token)
    {
        var handle = MetadataTokens.EntityHandle(token);
        try
        {
            return handle.Kind == HandleKind.MethodSpecification
                ? md.GetMethodSpecification((MethodSpecificationHandle)handle).Method
                : handle;
        }
        catch (BadImageFormatException)
        {
            return handle;
        }
    }

    private static string? MethodName(MetadataReader md, EntityHandle handle)
    {
        try
        {
            return handle.Kind switch
            {
                HandleKind.MemberReference => md.GetString(md.GetMemberReference((MemberReferenceHandle)handle).Name),
                HandleKind.MethodDefinition => md.GetString(md.GetMethodDefinition((MethodDefinitionHandle)handle).Name),
                _ => null,
            };
        }
        catch (BadImageFormatException)
        {
            return null;
        }
    }

    private static string Describe(MetadataReader md, MethodDefinition method) =>
        $"{TypeName(md, method.GetDeclaringType())}::{md.GetString(method.Name)}";

    internal static string TypeName(MetadataReader md, EntityHandle handle, int depth = 0)
    {
        // Untrusted metadata can nest (or cycle) arbitrarily.
        if (depth > 16)
        {
            return "?";
        }

        try
        {
            switch (handle.Kind)
            {
                case HandleKind.TypeReference:
                    {
                        var type = md.GetTypeReference((TypeReferenceHandle)handle);
                        string name = md.GetString(type.Name);
                        if (type.ResolutionScope.Kind == HandleKind.TypeReference)
                        {
                            return TypeName(md, (EntityHandle)type.ResolutionScope, depth + 1) + "+" + name;
                        }

                        string ns = md.GetString(type.Namespace);
                        return ns.Length == 0 ? name : ns + "." + name;
                    }

                case HandleKind.TypeDefinition:
                    {
                        var type = md.GetTypeDefinition((TypeDefinitionHandle)handle);
                        string name = md.GetString(type.Name);
                        var declaring = type.GetDeclaringType();
                        if (!declaring.IsNil)
                        {
                            return TypeName(md, declaring, depth + 1) + "+" + name;
                        }

                        string ns = md.GetString(type.Namespace);
                        return ns.Length == 0 ? name : ns + "." + name;
                    }

                default:
                    return "";
            }
        }
        catch (BadImageFormatException)
        {
            return "?";
        }
    }

    private static bool TryRead(byte[] il, ref int position, out Instruction instruction)
    {
        instruction = default;
        if (position >= il.Length)
        {
            return false;
        }

        ushort code = il[position++];
        if (code == 0xfe)
        {
            if (position >= il.Length)
            {
                return false;
            }

            code = (ushort)(0xfe00 | il[position++]);
        }

        if (!OpCodeTable.TryGetValue(code, out var info))
        {
            return false;
        }

        var type = info.Operand;

        int size;
        switch (type)
        {
            case OperandType.InlineNone:
                size = 0;
                break;
            case OperandType.ShortInlineBrTarget or OperandType.ShortInlineI or OperandType.ShortInlineVar:
                size = 1;
                break;
            case OperandType.InlineVar:
                size = 2;
                break;
            case OperandType.InlineI8 or OperandType.InlineR:
                size = 8;
                break;
            case OperandType.InlineSwitch:
                if (il.Length - position < 4)
                {
                    return false;
                }

                int count = BinaryPrimitives.ReadInt32LittleEndian(il.AsSpan(position));
                if (count < 0 || count > (il.Length - position - 4) / 4)
                {
                    return false;
                }

                size = 4 + (4 * count);
                break;
            default:
                size = 4;
                break;
        }

        if (il.Length - position < size)
        {
            return false;
        }

        int operand = size switch
        {
            1 => type == OperandType.ShortInlineI ? (sbyte)il[position] : il[position],
            2 => BinaryPrimitives.ReadUInt16LittleEndian(il.AsSpan(position)),
            4 when type != OperandType.InlineSwitch => BinaryPrimitives.ReadInt32LittleEndian(il.AsSpan(position)),
            _ => 0,
        };

        position += size;
        instruction = new Instruction(code, operand);
        return true;
    }

    private static Dictionary<ushort, OpInfo> BuildOpCodeTable()
    {
        var table = new Dictionary<ushort, OpInfo>();
        foreach (var field in typeof(OpCodes).GetFields(BindingFlags.Public | BindingFlags.Static))
        {
            if (field.GetValue(null) is OpCode opCode)
            {
                table.TryAdd(unchecked((ushort)opCode.Value), new OpInfo(
                    opCode.OperandType, Count(opCode.StackBehaviourPop), Count(opCode.StackBehaviourPush), opCode.FlowControl));
            }
        }

        return table;

        // StackBehaviour names spell out their operands: Pop0, Pop1, Popi_popi, Popref_popi_popi, Push1_push1, Varpop...
        static int Count(StackBehaviour behaviour)
        {
            string name = behaviour.ToString();
            return name switch
            {
                "Varpop" or "Varpush" => -1,
                "Pop0" or "Push0" => 0,
                _ => name.Split('_').Length,
            };
        }
    }

    /// <summary>Renders signature types as full names, enough to tell BrotliStream's overloads apart.</summary>
    private sealed class SignatureTypeNames : ISignatureTypeProvider<string, object?>
    {
        public static readonly SignatureTypeNames Instance = new();

        public string GetPrimitiveType(PrimitiveTypeCode typeCode) => "System." + typeCode;
        public string GetTypeFromDefinition(MetadataReader reader, TypeDefinitionHandle handle, byte rawTypeKind) => TypeName(reader, handle);
        public string GetTypeFromReference(MetadataReader reader, TypeReferenceHandle handle, byte rawTypeKind) => TypeName(reader, handle);
        public string GetTypeFromSpecification(MetadataReader reader, object? genericContext, TypeSpecificationHandle handle, byte rawTypeKind) => "?";
        public string GetSZArrayType(string elementType) => elementType + "[]";
        public string GetArrayType(string elementType, ArrayShape shape) => elementType + "[*]";
        public string GetByReferenceType(string elementType) => elementType + "&";
        public string GetPointerType(string elementType) => elementType + "*";
        public string GetPinnedType(string elementType) => elementType;
        public string GetModifiedType(string modifier, string unmodifiedType, bool isRequired) => unmodifiedType;
        public string GetGenericInstantiation(string genericType, ImmutableArray<string> typeArguments) => $"{genericType}<{string.Join(",", typeArguments)}>";
        public string GetGenericMethodParameter(object? genericContext, int index) => "!!" + index;
        public string GetGenericTypeParameter(object? genericContext, int index) => "!" + index;
        public string GetFunctionPointerType(MethodSignature<string> signature) => "method*";
    }
}
