#!/usr/bin/env bash
# Release gate: scans every download in <dist> with the scanner itself and fails unless each binary
# embeds a brotli decoder with the CVE-2026-111497 fix and doesn't decode brotli itself.
#   build/verify-release.sh dist
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
dist="${1:?usage: build/verify-release.sh <dist>}"
work="$(mktemp -d)"
tar_opts=()
if command -v cygpath >/dev/null; then   # Git Bash: use Windows paths and stop it rewriting arguments
    repo="$(cygpath -m "$repo")"; work="$(cygpath -m "$work")"
    export MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*'
    tar_opts=(--force-local)   # GNU tar would read C:/... as host:path
fi
trap 'rm -rf "$work"' EXIT

dotnet build "$repo/src/BrotliScan" -c Release --nologo -v quiet >/dev/null
count=0
for archive in "$dist"/brotli-scan-*; do
    name="$(basename "$archive")"; name="${name%.zip}"; name="${name%.tar.gz}"
    mkdir -p "$work/$name"
    case "$archive" in
        *.zip) unzip -q "$archive" -d "$work/$name" ;;
        *.tar.gz) tar ${tar_opts[@]+"${tar_opts[@]}"} -xzf "$archive" -C "$work/$name" ;;
    esac
    count=$((count + 1))
done

report="$(dotnet "$repo/src/BrotliScan/bin/Release/net10.0/brotli-scan.dll" --no-host --json "$work" || [ $? -le 2 ])"
failures=0
for dir in "$work"/*/; do
    name="$(basename "$dir")"
    result="$(jq -r --arg n "$name" '[.targets[] | select(.path | gsub("\\\\"; "/") | contains("/" + $n + "/"))]
        | if length == 0 then "no scanner binary found"
          else (map(.verdict) | unique | join(",")) + " / " + ([.[].decoders[]?.status] | unique | join(",")) end' <<<"$report")"
    if [ "$result" = "notExposed / patched" ]; then
        printf '  ok    %-36s %s\n' "$name" "$result"
    else
        printf '  FAIL  %-36s %s (expected notExposed / patched)\n' "$name" "$result"
        failures=$((failures + 1))
    fi
done

if [ "$count" -eq 0 ]; then echo "No downloads in $dist"; exit 1; fi
if [ "$failures" -ne 0 ]; then echo "Refusing to release: $failures download(s) embed a decoder without the fix."; exit 1; fi
echo "All $count downloads embed a fixed brotli decoder."
