#!/usr/bin/env bash
# End-to-end check, on Linux, macOS or Windows (Git Bash). Scans the fixtures as source, as build
# output and as published apps (Linux, Windows and macOS single-file formats), builds and runs the
# standalone binary for this platform, and checks real brotli 1.1.0 and 1.1.1 decoder builds.
# Needs the .NET 10 SDK, jq, network access to nuget.org, and cmake + a C compiler for the brotli check.
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
work="$(mktemp -d)"
# Git Bash on Windows rewrites anything that looks like a POSIX path (including jq patterns) before
# a native program sees it. Use Windows paths throughout and turn that rewriting off.
if command -v cygpath >/dev/null; then
    repo="$(cygpath -m "$repo")"; work="$(cygpath -m "$work")"
    export MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*'
fi
cleanup() { rm -rf "$work"; find "$repo/e2e/fixtures" -type d \( -name bin -o -name obj \) -prune -exec rm -rf {} +; }
trap cleanup EXIT

case "$(uname -s)-$(uname -m)" in
    Linux-x86_64) rid=linux-x64 ;;  Linux-aarch64) rid=linux-arm64 ;;
    Darwin-x86_64) rid=osx-x64 ;;   Darwin-arm64) rid=osx-arm64 ;;
    MINGW*-aarch64 | MSYS*-aarch64) rid=win-arm64 ;;
    MINGW* | MSYS* | CYGWIN*) rid=win-x64 ;;
    *) echo "Unsupported platform: $(uname -sm)"; exit 1 ;;
esac

dotnet build "$repo/src/BrotliScan" -c Release --nologo -v quiet >/dev/null
scanner=(dotnet "$repo/src/BrotliScan/bin/Release/net10.0/brotli-scan.dll")
scan() { "${scanner[@]}" --no-host --json "$@" || [ $? -le 2 ]; }

# Exposed covers affected, likely affected and patched: which one depends on the decoder, not the code.
# Paths are normalised to forward slashes so the same filters work on Windows.
bucket='if . == "notExposed" or . == "review" then . else "exposed" end'
failures=0
pass() { printf '  ok    %-44s %s\n' "$1" "$2"; }
fail() { printf '  FAIL  %-44s %s\n' "$1" "$2"; failures=$((failures + 1)); }
check() { # label, report, path regex, expected bucket
    local actual
    actual="$(jq -r --arg re "$3" "[.targets[] | select(.path | gsub(\"\\\\\\\\\"; \"/\") | test(\$re)) | .verdict | $bucket] | unique | join(\",\")" <<<"$2")"
    if [ "$actual" = "$4" ]; then pass "$1" "$4"; else
        fail "$1" "expected $4, got ${actual:-nothing}"
        jq -r '.targets[] | "        target: \(.path) = \(.verdict)"' <<<"$2" | head -5
    fi
}

expected="CompressOnly=notExposed ConfigDriven=review DirectDecode=exposed HelloApi=notExposed InboundApi=exposed
    ManualBodyApi=exposed CustomProviderApi=exposed MitigatedApi=notExposed OutboundClient=exposed SafeClient=notExposed VbClient=exposed"

echo "Source:"
report="$(scan "$repo/e2e/fixtures")"
for pair in $expected; do check "${pair%%=*}" "$report" "(^|/)${pair%%=*}/[^/]*proj$" "${pair##*=}"; done

echo "Build output (IL):"
for pair in $expected; do
    name="${pair%%=*}"
    dotnet build "$(ls "$repo/e2e/fixtures/$name/"*.*proj)" -c Release --nologo -v quiet -o "$work/bin/$name" >/dev/null
done
report="$(scan "$work/bin")"
for pair in $expected; do check "${pair%%=*}" "$report" "(^|/)bin/${pair%%=*}$" "${pair##*=}"; done
for name in InboundApi ManualBodyApi CustomProviderApi; do
    inbound="$(jq -r --arg re "(^|/)bin/$name$" '[.targets[] | select(.path | gsub("\\\\"; "/") | test($re)) | .findings[] | select(.kind == "inboundRequest")] | length' <<<"$report")"
    if [ "$inbound" -gt 0 ]; then pass "$name accepts brotli from clients" inbound; else fail "$name" "no inbound finding"; fi
done

echo "Published apps:"
publish() { dotnet publish "$repo/e2e/fixtures/$3/$3.csproj" -c Release -r "$2" --nologo -v quiet -o "$work/publish/$1" "${@:4}" >/dev/null; }
publish linux-singlefile linux-x64 InboundApi --self-contained -p:PublishSingleFile=true
publish linux-singlefile-zip linux-x64 OutboundClient --self-contained -p:PublishSingleFile=true -p:EnableCompressionInSingleFile=true
publish linux-folder linux-x64 DirectDecode --self-contained
publish linux-fd-singlefile linux-x64 HelloApi --no-self-contained -p:PublishSingleFile=true
publish windows-singlefile win-x64 InboundApi --self-contained -p:PublishSingleFile=true
publish macos-singlefile osx-arm64 ManualBodyApi --self-contained -p:PublishSingleFile=true -p:EnableCompressionInSingleFile=true
report="$(scan "$work/publish")"
check "Linux self-contained single-file" "$report" "linux-singlefile/" exposed
check "Linux compressed single-file" "$report" "linux-singlefile-zip/" exposed
check "Linux self-contained folder" "$report" "linux-folder$" exposed
check "Linux framework-dependent single-file" "$report" "linux-fd-singlefile/" notExposed
check "Windows single-file (PE)" "$report" "windows-singlefile/" exposed
check "macOS compressed single-file (Mach-O)" "$report" "macos-singlefile/" exposed
for app in linux-singlefile/InboundApi windows-singlefile/InboundApi.exe macos-singlefile/ManualBodyApi; do
    status="$(jq -r --arg re "$app$" '[.targets[] | select(.path | gsub("\\\\"; "/") | test($re)) | .decoders[0].status] | first' <<<"$report")"
    if [[ "$status" =~ ^(vulnerable|patched)$ ]]; then pass "decoder linked into $app" "$status"; else fail "decoder linked into $app" "$status"; fi
done

echo "Standalone binary ($rid):"
RIDS="$rid" "$repo/build/package.sh" "$work/dist" >/dev/null
mkdir -p "$work/standalone"
case "$rid" in
    win-*) unzip -q "$work"/dist/*.zip -d "$work/standalone" 2>/dev/null || powershell -NoProfile -Command "Expand-Archive '$(ls "$work"/dist/*.zip)' '$work/standalone'"; exe="$work/standalone/brotli-scan.exe" ;;
    *) tar -xzf "$work"/dist/*.tar.gz -C "$work/standalone"; exe="$work/standalone/brotli-scan" ;;
esac
if "$exe" --help | grep -q "Usage: brotli-scan"; then pass "runs" "--help"; else fail "runs" "--help failed"; fi
report="$("$exe" --no-host --json "$repo/e2e/fixtures" || [ $? -le 2 ])"
check "scans InboundApi from the standalone binary" "$report" "(^|/)InboundApi/[^/]*proj$" exposed
report="$("$exe" --no-host --json "$work/standalone" || [ $? -le 2 ])"
check "the scanner itself" "$report" "(^|/)standalone/brotli-scan(\\.exe)?$" notExposed
if "$exe" --host-only --json >/dev/null || [ $? -le 2 ]; then pass "inspects this machine" "--host-only"; else fail "inspects this machine" "--host-only failed"; fi

if command -v cmake >/dev/null && command -v git >/dev/null; then
    echo "Real brotli builds:"
    git clone -q --filter=blob:none https://github.com/google/brotli.git "$work/brotli"
    for v in v1.1.0 v1.1.1; do
        git -C "$work/brotli" -c advice.detachedHead=false checkout -q "$v"
        cmake -S "$work/brotli" -B "$work/build-$v" -DCMAKE_BUILD_TYPE=Release -DBROTLI_DISABLE_TESTS=ON -DBUILD_SHARED_LIBS=ON >/dev/null 2>&1
        cmake --build "$work/build-$v" --target brotlidec --config Release >/dev/null 2>&1
        lib="$(find "$work/build-$v" -type f \( -name 'libbrotlidec*.so*' -o -name 'libbrotlidec*.dylib' -o -name 'brotlidec*.dll' \) | head -1)"
        mkdir -p "$work/libs/$v" && cp "$lib" "$work/libs/$v/"
    done
    report="$(scan "$work/libs")"
    for pair in v1.1.0=vulnerable v1.1.1=patched; do
        actual="$(jq -r --arg v "${pair%%=*}" '.components[] | select(.path | gsub("\\\\"; "/") | contains("/" + $v + "/")) | .status' <<<"$report")"
        if [ "$actual" = "${pair##*=}" ]; then pass "brotli ${pair%%=*}" "$actual"; else fail "brotli ${pair%%=*}" "expected ${pair##*=}, got ${actual:-nothing}"; fi
    done
fi

echo
if [ "$failures" -eq 0 ]; then echo "All end-to-end checks passed."; else echo "$failures check(s) failed."; exit 1; fi
