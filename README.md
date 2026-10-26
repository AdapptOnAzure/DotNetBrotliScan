<div align="center">

# brotli-scan

**Find the .NET apps exposed to CVE-2026-111497, on your machine, in your code, and in Azure.**

[![CI](https://github.com/AdapptOnAzure/DotNetBrotliScan/actions/workflows/ci.yml/badge.svg)](https://github.com/AdapptOnAzure/DotNetBrotliScan/actions/workflows/ci.yml)
![.NET 10](https://img.shields.io/badge/.NET-10-512BD4)
![Platforms](https://img.shields.io/badge/platforms-Windows%20%7C%20macOS%20%7C%20Linux-informational)

[Get it](#get-it) · [Use it](#use-it) · [What counts as exposed](#what-counts-as-exposed) · [Azure](#azure-app-service-and-azure-functions) · [How it works](#what-it-looks-at) · [Limits](#limits)

</div>

---

Checks whether your .NET apps are affected by **CVE-2026-111497**, the brotli decoder flaw fixed upstream in
[google/brotli@0ed4268a](https://github.com/google/brotli/commit/0ed4268a4401abcb4472096340477cf4af7d1a2b)
(brotli 1.0.10, 1.1.1 and 1.2.1). Every .NET release up to the time of writing vendors an unpatched copy.

Having a vulnerable runtime installed isn't the same as being exposed. An app is **affected** only when
it decodes brotli it doesn't control (for example, accepting brotli-compressed request bodies from
clients) *and* the decoder it uses lacks the fix. The scanner checks both.

```text
$ brotli-scan ~/src
brotli-scan 1.0.0: CVE-2026-111497 (brotli decoder out-of-bounds write; fixed in brotli 1.0.10, 1.1.1, 1.2.1)

BROTLI DECODERS
  VULNERABLE      .NET runtime 10.0.13
                  /usr/share/dotnet/shared/Microsoft.NETCore.App/10.0.13/libSystem.IO.Compression.Native.so

PROJECTS AND APPS
  AFFECTED        project         InboundApi/InboundApi.csproj  [net10.0]
                  accepts brotli-compressed data from clients with a brotli decoder that lacks the fix
                  inbound   InboundApi/Program.cs:5  UseRequestDecompression(): accepts brotli-compressed request bodies from clients ('br' is on unless removed)

  AFFECTED        project         OutboundClient/OutboundClient.csproj  [net10.0]
                  decompresses HTTP responses with a brotli decoder that lacks the fix
                  outbound  OutboundClient/Program.cs:3  AutomaticDecompression = DecompressionMethods.All: responses with Content-Encoding: br are decoded

  NOT EXPOSED     project         HelloApi/HelloApi.csproj  [net10.0]
                  info      HelloApi/Program.cs:5  UseResponseCompression(): compresses responses with the brotli encoder, which isn't affected

SUMMARY
  2 affected, 0 likely affected, 0 to review, 0 patched, 1 not exposed
```

Abridged. The full report ends with what to change in each affected app until .NET ships the fix.

## Get it

Download the file for your platform from the [Releases page](https://github.com/AdapptOnAzure/DotNetBrotliScan/releases). It's a single executable with nothing to
install, not even .NET.

| Platform | Download |
|---|---|
| Windows (Intel/AMD, Arm) | `brotli-scan-<version>-win-x64.zip`, `brotli-scan-<version>-win-arm64.zip` |
| macOS (Apple silicon, Intel) | `brotli-scan-<version>-osx-arm64.tar.gz`, `brotli-scan-<version>-osx-x64.tar.gz` |
| Linux (x64, Arm64) | `brotli-scan-<version>-linux-x64.tar.gz`, `brotli-scan-<version>-linux-arm64.tar.gz` |

Check the download against `SHA256SUMS`, or verify where it was built with
`gh attestation verify <file> --repo AdapptOnAzure/DotNetBrotliScan`.

## Use it

**Windows.** Unzip, then double-click `brotli-scan.exe` to check this machine. To scan code or an app,
open a terminal in the folder:

```powershell
.\brotli-scan.exe C:\src\myapp
```

If SmartScreen says "Windows protected your PC", choose *More info* then *Run anyway*, or run
`Unblock-File .\brotli-scan.exe` first.

**macOS.**

```sh
tar -xzf brotli-scan-*-osx-arm64.tar.gz
xattr -d com.apple.quarantine brotli-scan 2>/dev/null   # only needed when downloaded with a browser
./brotli-scan ~/src/myapp
```

**Linux.**

```sh
tar -xzf brotli-scan-*-linux-x64.tar.gz
./brotli-scan ~/src/myapp
```

**Azure App Service and Functions**, from any of the above: install the Azure CLI, sign in, and scan.

```sh
az login
brotli-scan --azure
```

| Command | What it checks |
|---|---|
| `brotli-scan` | The current folder, and this machine's .NET runtimes |
| `brotli-scan <path>` | A source tree, build output, publish folder or single file |
| `brotli-scan --azure` | Every App Service and Functions app in your current Azure subscription |
| `brotli-scan --help` | Every option |

Point it at whatever you have: source code, `bin/` output, a publish folder, a single-file executable,
or a whole drive. Results end with what to do for each affected app.

## What counts as exposed

| Pattern | Who controls the input | Default |
|---|---|---|
| `app.UseRequestDecompression()` (ASP.NET Core) | anyone who can send the app a request | off; `br` is accepted once it's on |
| `AutomaticDecompression` includes `Brotli` or `All` (`HttpClientHandler`, `SocketsHttpHandler`, …) | the server being called, or anyone in between | off (`None`) |
| `new BrotliStream(s, CompressionMode.Decompress)`, `BrotliDecoder` | wherever the data comes from | — |
| `app.UseResponseCompression()` | — | **not affected**: it only uses the encoder |

Verdicts:

| Verdict | Meaning |
|---|---|
| **affected** | Decodes brotli on a decoder known to lack the fix |
| **likely affected** | Decodes brotli, but the decoder's patch state couldn't be proven (stripped binary, remote platform runtime, no matching runtime to inspect) |
| **review** | A value the scanner can't resolve statically (e.g. `AutomaticDecompression` from configuration), or a non-.NET brotli implementation |
| **patched** | Decodes brotli, and the decoder has the fix |
| **not exposed** | Nothing decodes brotli, or `br` is removed from request decompression |

Exit codes: `0` nothing affected or to review, `1` affected or likely affected, `2` only review items, `64` bad arguments.
`--json` prints the full report, and `--output report.json` writes it alongside the text.
To list only the apps that accept brotli from clients:
`brotli-scan --json <path> | jq '.targets[] | select(any(.findings[]; .kind == "inboundRequest")) | .path'`

## What it looks at

- **C# source**, parsed with Roslyn (syntax only, nothing is compiled). VB.NET and F# use text patterns and are marked as text matches.
- **Compiled assemblies** in build output and publish folders, read as IL through metadata. Assemblies are never loaded, and this covers any .NET language and every NuGet dependency, which a source scan can't see.
- **Single-file apps.** The bundle is unpacked in memory, including compressed bundles, and both the bundled assemblies and the statically linked runtime are checked.
- **Native brotli decoders**, identified by byte signature: the runtime's `System.IO.Compression.Native`, single-file and Native AOT hosts, and third-party copies.
- **This machine's .NET installs** on Windows, macOS and Linux: shared runtimes, plus the runtime and host packs (and NuGet cache copies) that self-contained, single-file and Native AOT publishes copy in. Skip this with `--no-host`.

### How the decoder fingerprint works

Brotli's `BrotliDecoderErrorString()` embeds a string for every error code. The fix added error code
-17 (`_ERROR_FORMAT_BLOCK_SWITCH`) on all three fixed release lines. So a decoder carrying the error table
without `BLOCK_SWITCH` is pre-fix, and one with it is fixed. This was checked against real builds of
brotli 1.1.0 and 1.1.1 (stripped and unstripped) and against shipped .NET 8 and 10 binaries. When
Microsoft ships a patched runtime, the scanner reports it as **patched** without an update.

Some builds strip those strings (for example the .NET 8 single-file host). Those are reported as
*unconfirmed* rather than guessed at.

## Azure App Service and Azure Functions

The scanner can download what's deployed to App Service and Functions apps and scan it, from Windows,
macOS or Linux. It uses the **Azure CLI login on the machine running it**, so install the CLI once
(`winget install -e --id Microsoft.AzureCLI`, `brew install azure-cli`, or [the Linux instructions](https://aka.ms/azure-cli))
and sign in with `az login`:

```sh
brotli-scan --azure                                    # every app in the CLI's current subscription
brotli-scan --azure-subscription <id> --azure-resource-group rg-prod --azure-slots
brotli-scan --azure-resource /subscriptions/<id>/resourceGroups/rg/providers/Microsoft.Web/sites/my-api
brotli-scan --azure-all-subscriptions --output azure-report.json
```

### Permissions

| To | Role |
|---|---|
| Find apps | Reader on the subscription or resource group |
| Download an app's files through Kudu | Website Contributor, or a custom role with `Microsoft.Web/sites/publish/Action` |
| Download a Flex Consumption app's package | Storage Blob Data Reader on its deployment storage account |

### Coverage by hosting model

| Hosting | How files are read | Runtime the app uses |
|---|---|---|
| App Service and Functions on Windows (Premium, Dedicated, Consumption) | Kudu zip of `site/wwwroot` | Fingerprinted from the platform's runtime directory through Kudu's VFS |
| App Service and Functions on Linux | Kudu zip of `site/wwwroot` | Not reachable from Kudu: framework-dependent apps that decode brotli are reported **likely affected** |
| Functions Flex Consumption | Deployment package from its blob container | Not reachable: as above |
| Self-contained apps (any of the above) | As above | Fingerprinted from the app's own files |
| Container images (Web App for Containers, sidecars) | Not in `wwwroot`: reported for **review** | Export the image (`docker export`) and scan the folder |
| Linux Consumption Functions | No Kudu: reported for **review** with the reason | — |

### Security design

- **Identity-based only.** `az` issues short-lived Entra tokens (`az account get-access-token`). No client secrets, publish profiles, SCM basic auth, storage keys or connection strings are used, and tokens are held in memory and never logged.
- **Tokens only go where they belong.** Resource Manager tokens are sent only to `management.azure.com` and Kudu hosts under `*.azurewebsites.net` or `*.appserviceenvironment.net`, and storage tokens only to `*.blob.core.windows.net`. Redirects aren't followed. For an App Service Environment with a custom DNS suffix, add it with `--azure-scm-domain`.
- **No injection through `az`.** On Windows `az` is a batch file whose arguments pass through `cmd.exe`, so only fixed values and validated subscription GUIDs ever reach its command line. All other calls are plain HTTPS from the tool.
- **Downloads are hostile until proven otherwise.** Archives are extracted into a private temp folder with zip-slip, symlink, entry-count and inflated-size limits, scanned without loading or executing anything, and then deleted.
- **No brotli decoding of network input.** The tool's own HTTP clients have automatic decompression turned off.
- Only the public Azure cloud is supported.

### In CI, without secrets

Use workload identity federation, so the pipeline holds no credentials. In GitHub Actions:

```yaml
permissions:
  id-token: write
  contents: read
steps:
  - uses: azure/login@v2
    with:
      client-id: ${{ vars.AZURE_CLIENT_ID }}
      tenant-id: ${{ vars.AZURE_TENANT_ID }}
      subscription-id: ${{ vars.AZURE_SUBSCRIPTION_ID }}
  - run: |
      curl -sSfL -o brotli-scan.tar.gz https://github.com/AdapptOnAzure/DotNetBrotliScan/releases/download/v1.0.0/brotli-scan-1.0.0-linux-x64.tar.gz
      gh attestation verify brotli-scan.tar.gz --repo AdapptOnAzure/DotNetBrotliScan
      tar -xzf brotli-scan.tar.gz && ./brotli-scan --azure --output brotli-report.json
    env:
      GH_TOKEN: ${{ github.token }}
```

## Limits

- Detection is static. A value read from configuration at run time is flagged for review rather than resolved.
- Source scanning sees only the project's own code; scan build output to cover dependencies.
- Code under `#if` symbols that aren't commonly defined isn't parsed.
- A framework-dependent app is judged against runtimes on the machine doing the scan, matched by major version. Production may run a different patch level, so scan production hosts too, or the Azure apps directly.
- The Azure integration is covered by tests against simulated ARM, Kudu and Blob endpoints. Run it against one app you own first, to confirm your roles and network path.

## Building it yourself

Needs the [.NET 10 SDK](https://dotnet.microsoft.com/download).

```sh
dotnet run --project src/BrotliScan -- <path>    # run from source
build/package.sh                                 # all six standalone downloads + SHA256SUMS, into dist/
RIDS="osx-arm64" build/package.sh                # just one platform
dotnet pack src/BrotliScan -c Release -o nupkg   # or as a .NET tool: dotnet tool install -g BrotliScan --add-source nupkg
```

`build/package.sh` runs in bash, so use Git Bash on Windows.

### Signing for wider distribution

The Windows binaries are unsigned and the macOS ones only ad-hoc signed, which is why SmartScreen and
Gatekeeper ask before running them. To hand them to clients, sign in the release workflow: Windows with
Azure Trusted Signing (it authenticates with workload identity federation, so the pipeline holds no
certificate or secret), and macOS with an Apple Developer ID certificate plus notarization.

### The tool's own runtime

Each download includes the .NET 10 runtime, so it carries the same unpatched decoder. The tool never
decodes brotli: its HTTP clients have decompression turned off, and it never opens `BrotliStream` or
`BrotliDecoder`. Scanning the tool with itself reports **not exposed**. Rebuild the downloads once
Microsoft ships the fixed runtime.

## Development

```sh
dotnet test BrotliScan.slnx -c Release   # unit and integration tests (offline)
e2e/run.sh                               # source, IL, Linux/Windows/macOS single-file formats, the standalone binary, real brotli builds
```

CI (`.github/workflows/ci.yml`) runs a format and analyzer check, then both of the above on Windows,
macOS and Linux. Pushing a `v*.*.*` tag runs `.github/workflows/release.yml`, which reruns CI, builds the
six downloads, attaches a signed build-provenance attestation, and publishes a GitHub release with the
matching `CHANGELOG.md` section as its notes. Actions are pinned to commit SHAs and kept current by
Dependabot.

`e2e/fixtures` has one minimal project per pattern. They're compiled and scanned, never run or deployed.

See [CONTRIBUTING.md](CONTRIBUTING.md) to add a pattern, [SECURITY.md](SECURITY.md) to report a
vulnerability in the scanner, and [CHANGELOG.md](CHANGELOG.md) for release history.
