# Contributing

## Setup

You need the [.NET 10 SDK](https://dotnet.microsoft.com/download). The end-to-end checks also need
`jq`, and `cmake` plus a C compiler for the real-brotli fingerprint check (it's skipped without them).
On Windows, run the shell scripts in Git Bash.

```sh
dotnet build BrotliScan.slnx
dotnet test BrotliScan.slnx -c Release                # unit and integration tests, offline
e2e/run.sh                                            # end-to-end against compiled fixtures
dotnet format BrotliScan.slnx --verify-no-changes     # style, as CI checks it
```

## Layout

| Path | What's there |
|---|---|
| `src/BrotliScan/` | The scanner. `Scanner.cs` walks files and decides verdicts; `SourceScanner.cs` (Roslyn), `AssemblyScanner.cs` (IL), `NativeScanner.cs` and `BundleReader.cs` (native decoders and single-file apps), `HostScanner.cs` (this machine's .NET installs) |
| `src/BrotliScan/AppService/` | Azure App Service and Functions: discovery, Kudu and blob downloads, safe extraction |
| `tests/BrotliScan.Tests/` | MSTest unit and integration tests. Azure endpoints are simulated |
| `e2e/` | `run.sh` and one minimal fixture project per pattern |
| `build/package.sh` | Builds the six standalone downloads |

## Adding a detection pattern

1. Add a rule ID in `Rules.cs`.
2. Detect it in source (`SourceScanner.cs`) and in IL (`AssemblyScanner.cs`), so it's caught whether
   someone scans code or a build.
3. Add a unit test, and a fixture in `e2e/fixtures` with its expected verdict in `e2e/run.sh` and
   `e2e/fixtures/README.md`.

## Ground rules

- Never load or execute scanned code, and never decode brotli in the tool itself.
- Treat everything downloaded or scanned as hostile: bound sizes and counts, and validate paths.
- New dependencies need a strong reason, and must be well-maintained packages from major vendors.
- Anything that sends data over the network uses identity-based auth only, never keys or secrets.
- Add a line to `CHANGELOG.md` under *Unreleased* for user-visible changes.

## Releasing

1. Move the *Unreleased* notes in `CHANGELOG.md` under a new version heading, and set `<Version>` in
   `src/BrotliScan/BrotliScan.csproj`.
2. Tag and push: `git tag v1.2.3 && git push origin v1.2.3`.

The release workflow runs CI on all three platforms, builds the downloads, attests their build
provenance and publishes the GitHub release with the changelog section as its notes.
