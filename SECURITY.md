# Security policy

## Reporting a vulnerability in brotli-scan

Please don't open a public issue. Report it privately through
[GitHub Security Advisories](https://github.com/AdapptOnAzure/CVE-2026-111497-DotNetBrotliScan/security/advisories/new)
with what you found, how to reproduce it, and the version and platform you used.

We aim to acknowledge reports within two working days and to agree a fix and disclosure date with you.

## Supported versions

Only the latest release gets fixes. The downloads embed the .NET runtime, so a new release is built
when .NET ships a security update, and the release workflow refuses to publish a build whose embedded
brotli decoder lacks the CVE-2026-111497 fix.

## What the scanner does with your data

- It reads files and never loads or executes what it scans.
- It makes no network calls unless you pass an `--azure` option. Then it talks only to Azure Resource
  Manager, your apps' Kudu (SCM) sites and, for Flex Consumption apps, their deployment storage, using
  short-lived tokens from your Azure CLI login. No keys, passwords or publish profiles are used.
- Downloaded app files are scanned in a private temporary folder and deleted afterwards.
- Reports stay on your machine unless you share them. They contain file paths and app names, so treat
  them as internal.

## About CVE-2026-111497 itself

The flaw is in brotli's decoder, not in this tool. Microsoft fixed it in .NET 10.0.14, 9.0.22 and 8.0.33
(2026-10-25); see the [.NET release notes](https://github.com/dotnet/core/tree/main/release-notes).
The README covers interim mitigations for apps you can't update yet.
