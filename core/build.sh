#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"
OUT="../app/src/main/jniLibs"
LDFLAGS="-s -w -buildid= -checklinkname=0"
export CGO_ENABLED=0
export GOFLAGS=-mod=mod

build() {
  local abi="$1" os="$2" arch="$3" extra="${4:-}"
  mkdir -p "$OUT/$abi"
  echo "building $abi"
  env GOOS="$os" GOARCH="$arch" $extra go build -trimpath -ldflags="$LDFLAGS" -o "$OUT/$abi/libcore.so" .
}

targets="${*:-arm64-v8a armeabi-v7a x86_64}"
for t in $targets; do
  case "$t" in
    arm64-v8a) build arm64-v8a android arm64 ;;
    armeabi-v7a) build armeabi-v7a linux arm GOARM=7 ;;
    x86_64) build x86_64 linux amd64 ;;
    *) echo "unknown abi $t" >&2; exit 1 ;;
  esac
done
ls -la "$OUT"/*/libcore.so
