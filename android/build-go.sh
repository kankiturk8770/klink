#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
CORE="$ROOT/core"
OUT="$ROOT/app/libs/klink.aar"
ANDROID_HOME="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-}}"
if [[ -z "$ANDROID_HOME" && -f "$ROOT/local.properties" ]]; then
  ANDROID_HOME="$(sed -n 's/^sdk.dir=//p' "$ROOT/local.properties" | head -n1 | sed 's/\\:/:/g')"
fi
if [[ -z "$ANDROID_HOME" ]]; then
  echo "Set ANDROID_HOME or ANDROID_SDK_ROOT before building." >&2
  exit 1
fi
if [[ -z "${ANDROID_NDK_HOME:-}" ]]; then
  if [[ -d "$ANDROID_HOME/ndk/26.1.10909125" ]]; then
    export ANDROID_NDK_HOME="$ANDROID_HOME/ndk/26.1.10909125"
  else
    NDK_DIR="$(find "$ANDROID_HOME/ndk" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | sort -V | tail -n1)"
    [[ -n "$NDK_DIR" ]] || { echo "Install Android NDK 26.1.10909125." >&2; exit 1; }
    export ANDROID_NDK_HOME="$NDK_DIR"
  fi
fi
GO_BIN="${GO_BIN:-$(command -v go || true)}"
[[ -n "$GO_BIN" ]] || { echo "Go 1.26.3 or newer is required." >&2; exit 1; }
TOOLS_BIN="$ROOT/.gomobile/bin"
mkdir -p "$TOOLS_BIN"
GOMOBILE_BIN="$(command -v gomobile || true)"
if [[ -z "$GOMOBILE_BIN" ]]; then
  GOMOBILE_BIN="$TOOLS_BIN/gomobile"
  if [[ ! -x "$GOMOBILE_BIN" ]]; then
    GOBIN="$TOOLS_BIN" "$GO_BIN" install golang.org/x/mobile/cmd/gomobile@latest
  fi
fi
if ! command -v gobind >/dev/null 2>&1 && [[ ! -x "$TOOLS_BIN/gobind" ]]; then
  GOBIN="$TOOLS_BIN" "$GO_BIN" install golang.org/x/mobile/cmd/gobind@latest
fi
# gomobile starts gobind as a child process, so its directory must be in PATH.
export PATH="$TOOLS_BIN:$(dirname "$GOMOBILE_BIN"):$PATH"
mkdir -p "$ROOT/app/libs"
cd "$CORE"
"$GO_BIN" mod download
"$GO_BIN" test ./client
TMP_AAR="$ROOT/app/libs/klink.tmp.aar"
rm -f "$TMP_AAR"
# 16 KiB LOAD alignment keeps the same AAR compatible with both legacy 4 KiB
# devices and Android 15+ devices that use 16 KiB memory pages.
"$GOMOBILE_BIN" bind -v -androidapi 23 -target android/arm64,android/arm,android/amd64 \
  -ldflags '-extldflags=-Wl,-z,max-page-size=16384' -o "$TMP_AAR" ./mobile
mv "$TMP_AAR" "$OUT"
echo "Built $OUT"
