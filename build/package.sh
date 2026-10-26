#!/usr/bin/env bash
# Builds the standalone downloads: one self-contained executable per platform (nothing to install),
# archived as .zip (Windows) or .tar.gz, with a SHA256SUMS file.
#   build/package.sh                     all platforms, into dist/
#   RIDS="linux-x64" build/package.sh    just one
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
out="${1:-$repo/dist}"
tar_opts=()
if command -v cygpath >/dev/null; then   # Git Bash: use Windows paths and stop it rewriting arguments
    repo="$(cygpath -m "$repo")"; out="$(cygpath -m "$out")"
    export MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*'
    tar_opts=(--force-local)   # GNU tar would read C:/... as host:path
fi
read -r -a rids <<<"${RIDS:-win-x64 win-arm64 linux-x64 linux-arm64 osx-x64 osx-arm64}"
version="${VERSION:-$(sed -n 's:.*<Version>\(.*\)</Version>.*:\1:p' "$repo/src/BrotliScan/BrotliScan.csproj")}"

rm -rf "$out" && mkdir -p "$out/stage"
for rid in "${rids[@]}"; do
    echo "Building $rid"
    stage="$out/stage/$rid"
    dotnet publish "$repo/src/BrotliScan" -c Release -r "$rid" -o "$stage" --nologo -v quiet -p:Version="$version"
    cp "$repo/README.md" "$repo/LICENCE" "$stage/"
    name="brotli-scan-$version-$rid"
    case "$rid" in
        win-*) if command -v zip >/dev/null; then (cd "$stage" && zip -q -X -r "$out/$name.zip" .)
               else powershell -NoProfile -Command "Compress-Archive -Path '$stage/*' -DestinationPath '$out/$name.zip'"; fi ;;
        *)     tar ${tar_opts[@]+"${tar_opts[@]}"} -C "$stage" -czf "$out/$name.tar.gz" . ;;
    esac
done
rm -rf "$out/stage"

cd "$out"
if command -v sha256sum >/dev/null; then sha256sum brotli-scan-* > SHA256SUMS; else shasum -a 256 brotli-scan-* > SHA256SUMS; fi
ls -l
