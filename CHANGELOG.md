# Changelog

All notable changes are listed here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [1.0.0] - 2026-10-26

First release.

### Added

- Scans C# source (Roslyn), VB.NET and F# source (text patterns), and compiled assemblies (IL) for code
  that decodes brotli: ASP.NET Core request decompression, `HttpClient` automatic decompression,
  `BrotliStream`/`BrotliDecoder`, and custom decompression providers.
- Identifies whether `request.Body` is fed into a brotli decoder, and whether the `br` provider was removed.
- Fingerprints native brotli decoders (shared runtimes, self-contained and single-file apps, Native AOT,
  third-party copies) as vulnerable, patched, unconfirmed or system-linked.
- Reads .NET single-file bundles (Windows PE, Linux ELF, macOS Mach-O), compressed or not.
- Inspects this machine's .NET runtimes, packs and NuGet cache on Windows, macOS and Linux.
- Scans Azure App Service and Azure Functions apps (Windows, Linux, Flex Consumption) using the Azure CLI
  login, with no keys or secrets.
- Text and JSON reports, and exit codes for CI. Remediation names the fixed .NET releases (10.0.14,
  9.0.22, 8.0.33) and the interim mitigations.
- Standalone downloads for Windows, macOS and Linux on x64 and Arm64, with SHA-256 checksums and build
  provenance attestations. Each embeds the fixed .NET 10 runtime; the release fails if it doesn't.

[Unreleased]: https://github.com/AdapptOnAzure/DotNetBrotliScan/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/AdapptOnAzure/DotNetBrotliScan/releases/tag/v1.0.0
