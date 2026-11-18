#!/usr/bin/env bash
# Builds the Gozar Go core into app/libs/gozar.aar via gomobile.
set -Eeuo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
CORE="$(cd "$ROOT/../core" && pwd)"
OUT="$ROOT/app/libs/gozar.aar"

ANDROID_HOME="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-}}"
if [[ -z "$ANDROID_HOME" && -f "$ROOT/local.properties" ]]; then
  ANDROID_HOME="$(sed -n 's/^sdk.dir=//p' "$ROOT/local.properties" | head -n1 | sed 's/\\:/:/g')"
fi
[[ -n "$ANDROID_HOME" ]] || { echo "Set ANDROID_HOME or ANDROID_SDK_ROOT." >&2; exit 1; }

if [[ -z "${ANDROID_NDK_HOME:-}" ]]; then
  NDK_DIR="$(find "$ANDROID_HOME/ndk" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | sort -V | tail -n1)"
  [[ -n "$NDK_DIR" ]] || { echo "Install an Android NDK under \$ANDROID_HOME/ndk." >&2; exit 1; }
  export ANDROID_NDK_HOME="$NDK_DIR"
fi

GO_BIN="${GO_BIN:-$(command -v go || true)}"
[[ -n "$GO_BIN" ]] || { echo "Go 1.26+ is required." >&2; exit 1; }

# gomobile runs `go mod tidy` in a temp module; gVisor's large indirect graph
# otherwise forces checksum-DB lookups to sum.golang.org that flake on CI
# (stream INTERNAL_ERROR). Our committed go.sum already pins everything, so turn
# off the sum DB and allow module graph updates in the temp module.
export GOSUMDB=off
export GOFLAGS="${GOFLAGS:-} -mod=mod"

TOOLS_BIN="$ROOT/.gomobile/bin"
mkdir -p "$TOOLS_BIN" "$ROOT/app/libs"
export PATH="$TOOLS_BIN:$PATH"
if [[ ! -x "$TOOLS_BIN/gomobile" ]]; then
  GOBIN="$TOOLS_BIN" "$GO_BIN" install golang.org/x/mobile/cmd/gomobile@latest
fi
if [[ ! -x "$TOOLS_BIN/gobind" ]]; then
  GOBIN="$TOOLS_BIN" "$GO_BIN" install golang.org/x/mobile/cmd/gobind@latest
fi

cd "$CORE"
"$GO_BIN" mod download
TMP="$ROOT/app/libs/gozar.tmp.aar"
rm -f "$TMP"
# 16 KiB page alignment keeps the AAR valid on Android 15+ 16 KiB-page devices.
"$TOOLS_BIN/gomobile" bind -v -androidapi 24 \
  -target android/arm64,android/arm,android/amd64 \
  -javapkg=com.gozar.core \
  -ldflags '-s -w -extldflags=-Wl,-z,max-page-size=16384' \
  -o "$TMP" ./mobile
mv "$TMP" "$OUT"
echo "Built $OUT"
