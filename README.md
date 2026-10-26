# .NET Brotli Scan

A very simple way to find out whether your .NET apps are exposed to **CVE-2026-111497**, the brotli decoder flaw fixed upstream in [google/brotli@0ed4268a](https://github.com/google/brotli/commit/0ed4268a4401abcb4472096340477cf4af7d1a2b) (brotli 1.0.10, 1.1.1 and 1.2.1). Works on Windows, macOS and Linux, and against Azure App Service and Azure Functions.

All it does is read your source code, build output, published apps and .NET runtimes, without loading or executing any of them, and work out two things: does anything decode brotli it doesn't control (for example, accepting brotli-compressed request bodies from clients), and does the brotli decoder it would use have the fix? Only when both answers are bad is an app **affected**. Having a vulnerable runtime installed is not the same as being exposed.

# The fix

Microsoft fixed this on 2026-10-25 in **.NET 10.0.14**, **.NET 9.0.22** and **.NET 8.0.33** (SDKs 10.0.403 / 10.0.114, 9.0.320 / 9.0.123 and 8.0.427 / 8.0.133). Every earlier .NET release vendors an unpatched copy of brotli, and versions older than .NET 8 are out of support and won't get the fix.

- Install the fixed runtime on every machine and container image that runs your apps. Azure App Service rolls out platform runtimes itself, so scan your Azure apps to see where that has landed
- Republish self-contained, single-file and Native AOT apps with a fixed SDK, because they carry their own copy of the runtime
- Rescan. The scanner tells you which apps still run on an unpatched decoder

# Features

- One self-contained executable per platform - nothing to install, not even .NET
- Windows, macOS and Linux, on both x64 and Arm64
- Double-click it on Windows to check the machine you're on
- Scans C# source (parsed with Roslyn), VB.NET and F# source, compiled assemblies (IL), publish folders and single-file apps
- Sees through your NuGet dependencies, by scanning build output rather than just your own source
- Fingerprints the actual native brotli decoder in shared runtimes, self-contained apps, single-file apps, Native AOT and third-party copies, so you get "vulnerable" or "patched" from the bytes, not from a version number
- Recognises patched decoders from the bytes, so it already knows 10.0.14, 9.0.22 and 8.0.33 are fixed, and will recognise any other fixed build too
- Optionally scans what's deployed to Azure App Service and Azure Functions, using your existing Azure CLI login
- Fully identity-based in Azure - no keys, no secrets, no publish profiles, no connection strings. ever.
- Never loads, executes or decompresses anything it scans
- Text report for humans, JSON report and exit codes for pipelines
- Tells you exactly what to do for each affected app, including interim mitigations for apps you can't update yet
- Every release is built in GitHub Actions with signed build provenance and SHA-256 checksums
- Very easy to audit. Why should you trust me? Trust yourself instead.
- No nonsense. If this has even a hint of nonsense anywhere, it is a bug. File an issue.

# What counts as exposed

| Pattern | Who controls the input | Default |
|---|---|---|
| `app.UseRequestDecompression()` (ASP.NET Core) | anyone who can send the app a request | off; `br` is accepted once it's on |
| Wrapping `Request.Body` in `BrotliStream`, or registering a brotli `IDecompressionProvider` | anyone who can send the app a request | — |
| `AutomaticDecompression` includes `Brotli` or `All` (`HttpClientHandler`, `SocketsHttpHandler`, …) | the server being called, or anyone in between | off (`None`) |
| `new BrotliStream(s, CompressionMode.Decompress)`, `BrotliDecoder` | wherever the data comes from | — |
| `app.UseResponseCompression()` | — | **not affected**: it only uses the encoder |

# Verdicts

- **affected**: decodes brotli on a decoder known to lack the fix
- **likely affected**: decodes brotli, but the decoder's patch state couldn't be proven (stripped binary, remote platform runtime, no matching runtime to inspect)
- **review**: a value the scanner can't resolve statically (e.g. `AutomaticDecompression` read from configuration), or a non-.NET brotli implementation
- **patched**: decodes brotli, and the decoder has the fix
- **not exposed**: nothing decodes brotli, or `br` is removed from request decompression

Exit codes: `0` nothing affected or to review, `1` affected or likely affected, `2` only review items, `64` bad arguments.

# Download

Grab the file for your platform from the [Releases page](https://github.com/AdapptOnAzure/DotNetBrotliScan/releases).

- Windows: `brotli-scan-<version>-win-x64.zip`, `brotli-scan-<version>-win-arm64.zip`
- macOS: `brotli-scan-<version>-osx-arm64.tar.gz` (Apple silicon), `brotli-scan-<version>-osx-x64.tar.gz` (Intel)
- Linux: `brotli-scan-<version>-linux-x64.tar.gz`, `brotli-scan-<version>-linux-arm64.tar.gz`

Check the download against `SHA256SUMS`, and verify it was built by this repo's release workflow:

```sh
gh attestation verify brotli-scan-<version>-linux-x64.tar.gz --repo AdapptOnAzure/DotNetBrotliScan
```

# Usage

## Windows

Unzip, then double-click `brotli-scan.exe` to check this machine. To scan code or an app, open a terminal in the folder:

```powershell
.\brotli-scan.exe C:\src\myapp
```

The binaries aren't code signed yet. If SmartScreen says "Windows protected your PC", choose *More info* then *Run anyway*, or run `Unblock-File .\brotli-scan.exe` first.

## macOS

```sh
tar -xzf brotli-scan-*-osx-arm64.tar.gz
xattr -d com.apple.quarantine brotli-scan 2>/dev/null   # only needed when downloaded with a browser
./brotli-scan ~/src/myapp
```

## Linux

```sh
tar -xzf brotli-scan-*-linux-x64.tar.gz
./brotli-scan ~/src/myapp
```

## Options

- `brotli-scan` - the current folder, and this machine's .NET runtimes
- `brotli-scan <path>` - a source tree, build output, publish folder, single file, or a whole drive
- `brotli-scan --no-host <path>` - skip this machine's .NET installs
- `brotli-scan --host-only` - only this machine's .NET installs
- `brotli-scan --json <path>` - the full report as JSON; `--output report.json` writes it alongside the text
- `brotli-scan --verbose <path>` - every decoder, finding and unreadable file
- `brotli-scan --help` - everything else

To list only the apps that accept brotli from clients:

```sh
brotli-scan --json ~/src | jq '.targets[] | select(any(.findings[]; .kind == "inboundRequest")) | .path'
```

## Sample output

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

Abridged. The full report ends with what to do for each affected app.

# Azure App Service and Azure Functions

The scanner can download what's deployed to your App Service and Functions apps and scan it, from Windows, macOS or Linux. It uses the Azure CLI login on the machine running it, so install the CLI once (`winget install -e --id Microsoft.AzureCLI`, `brew install azure-cli`, or [the Linux instructions](https://aka.ms/azure-cli)) and sign in:

```sh
az login
brotli-scan --azure                                    # every app in the CLI's current subscription
brotli-scan --azure-subscription <id> --azure-resource-group rg-prod --azure-slots
brotli-scan --azure-resource /subscriptions/<id>/resourceGroups/rg/providers/Microsoft.Web/sites/my-api
brotli-scan --azure-all-subscriptions --output azure-report.json
```

Start with a single app you own (`--azure-resource`), to confirm your roles and network path.

## Azure permissions shopping list

Use the least privilege that gets the job done. Don't cut corners here.

- To find apps
   - Must have the Azure RBAC role of "Reader" on the subscription or resource group
- To download an app's deployed files through Kudu
   - Must have the Azure RBAC role of "Website Contributor", or a custom role with `Microsoft.Web/sites/publish/Action`
   - Must have network access to the app's Kudu (SCM) site
- To download a Flex Consumption app's deployment package
   - Must have the Azure RBAC role of "Storage Blob Data Reader" on its deployment storage account
   - Must have network access to that storage account's blob endpoint
- The machine running the scan
   - Must have the Azure CLI installed and signed in with `az login` (or `azure/login` with workload identity federation in CI)
   - Must use the public Azure cloud (`AzureCloud`)

## Coverage by hosting model

- **App Service and Functions on Windows** (Premium, Dedicated, Consumption): files from a Kudu zip of `site/wwwroot`; the platform's .NET runtime is fingerprinted through Kudu's VFS
- **App Service and Functions on Linux**: files from a Kudu zip of `site/wwwroot`; the platform runtime isn't reachable from Kudu, so framework-dependent apps that decode brotli are reported **likely affected**
- **Functions Flex Consumption**: the deployment package from its blob container; platform runtime as for Linux
- **Self-contained apps** on any of the above: the decoder is fingerprinted from the app's own files
- **Containers** (Web App for Containers, sidecars): not in `wwwroot`, so reported for **review**; export the image (`docker export`) and scan the folder
- **Linux Consumption Functions**: no Kudu, so reported for **review** with the reason

## In CI, without secrets

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
      gh release download v1.0.0 --repo AdapptOnAzure/DotNetBrotliScan --pattern 'brotli-scan-*-linux-x64.tar.gz' --output brotli-scan.tar.gz
      gh attestation verify brotli-scan.tar.gz --repo AdapptOnAzure/DotNetBrotliScan
      tar -xzf brotli-scan.tar.gz && ./brotli-scan --azure --output brotli-report.json
    env:
      GH_TOKEN: ${{ github.token }}
```

# Security design

- **Identity-based only.** `az` issues short-lived Entra tokens (`az account get-access-token`). No client secrets, publish profiles, SCM basic auth, storage keys or connection strings are used, and tokens are held in memory and never logged.
- **Tokens only go where they belong.** Resource Manager tokens are sent only to `management.azure.com` and Kudu hosts under `*.azurewebsites.net` or `*.appserviceenvironment.net`, and storage tokens only to `*.blob.core.windows.net`. Redirects aren't followed. For an App Service Environment with a custom DNS suffix, add it with `--azure-scm-domain`.
- **No injection through `az`.** On Windows `az` is a batch file whose arguments pass through `cmd.exe`, so only fixed values and validated subscription GUIDs ever reach its command line. Everything else is plain HTTPS from the tool.
- **Downloads are hostile until proven otherwise.** Archives are extracted into a private temp folder with zip-slip, symlink, entry-count and inflated-size limits, scanned without loading or executing anything, and then deleted.
- **No brotli decoding, ever.** The tool's own HTTP clients have automatic decompression turned off, and it never opens `BrotliStream` or `BrotliDecoder`. Each download includes the .NET 10 runtime, and the release workflow refuses to publish a build whose embedded decoder lacks the fix.
- **Supply chain.** One dependency (Roslyn, from Microsoft), restored from nuget.org only, with NuGet vulnerability auditing failing the build. GitHub Actions are pinned to commit SHAs and kept current by Dependabot.

See [SECURITY.md](SECURITY.md) to report a vulnerability in the scanner itself.

# Limitations

- Detection is static. A value read from configuration at run time is flagged for **review** rather than resolved.
- Source scanning sees only the project's own code. Scan the build output to cover NuGet dependencies.
- VB.NET and F# source use text patterns rather than a parser, and their findings are marked as such.
- Code under `#if` symbols that aren't commonly defined isn't parsed.
- Some builds strip the strings the fingerprint relies on (for example the .NET 8 single-file host). Those decoders are reported as *unconfirmed* rather than guessed at.
- A framework-dependent app is judged against the runtimes on the machine doing the scan, matched by major version. Production may run a different patch level, so scan production hosts too, or the Azure apps directly.
- The Azure integration is tested against simulated ARM, Kudu and Blob endpoints. Only the public Azure cloud is supported.
- The Windows binaries are unsigned and the macOS binaries only ad-hoc signed, so SmartScreen and Gatekeeper will ask before running them.

# How it works

1. The scanner walks every path you give it, skipping `.git`, `node_modules` and `obj`, and never following symlinks or junctions
2. C# source is parsed with Roslyn (syntax only, nothing is compiled), and each finding is attributed to the nearest project file
3. Compiled assemblies are read as IL through `System.Reflection.Metadata`, never loaded. A small stack simulation tracks whether `request.Body` flows into a `BrotliStream`, and which `AutomaticDecompression` flags are set
4. Single-file apps (Windows PE, Linux ELF, macOS Mach-O) are unpacked in memory, compressed or not, and both the bundled assemblies and the statically linked runtime are checked
5. Native brotli decoders are fingerprinted by their error-string table. The fix added error code -17 (`_ERROR_FORMAT_BLOCK_SWITCH`) on all three fixed release lines, so a decoder carrying the table without it is pre-fix, and one with it is fixed. This was checked against real builds of brotli 1.1.0 and 1.1.1 (stripped and unstripped) and against shipped .NET 8 and 10 binaries, both before the fix and Microsoft's fixed 10.0.14 runtime packs for Windows, macOS and Linux
6. This machine's .NET installs (shared runtimes, plus the runtime and host packs and NuGet cache copies that self-contained, single-file and Native AOT publishes copy in) are fingerprinted the same way
7. Each project and app gets a verdict from what decodes brotli and which decoder it runs on, and the report says what to change

# Building it yourself

Needs the [.NET 10 SDK](https://dotnet.microsoft.com/download). On Windows, run the shell scripts in Git Bash.

```sh
dotnet run --project src/BrotliScan -- <path>    # run from source
dotnet test BrotliScan.slnx -c Release           # unit and integration tests (offline)
e2e/run.sh                                       # end-to-end: source, IL, Linux/Windows/macOS single-file formats, the standalone binary, real brotli builds
build/package.sh                                 # all six standalone downloads + SHA256SUMS, into dist/
RIDS="osx-arm64" build/package.sh                # just one platform
```

CI runs a format and analyzer check, then the tests and end-to-end checks on Windows, macOS and Linux. Pushing a `v*.*.*` tag reruns CI, builds the six downloads, attaches a signed build-provenance attestation, and publishes a GitHub release with the matching [CHANGELOG.md](CHANGELOG.md) section as its notes. See [CONTRIBUTING.md](CONTRIBUTING.md) to add a detection pattern.

# Disclaimer

This repository is not endorsed by my employer, organisation, clients, anyone, anything or any entity in any way, shape or form. This is released on the internet as a convenience only. A clean scan means the scanner found nothing, not that nothing is there - patch your runtimes regardless. No refunds, no "the scanner said not exposed but a rogue `Content-Encoding: br` header ate my production database" support here.
