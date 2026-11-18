# Building Gozar

## Layout

```
gozar/
  core/                 Go module (gozar/core) — proxy, injection, link parser, xray engine
    cmd/gozar-helper/   root-mode packet-injection helper (built per-ABI as libgozarhelper.so)
    mobile/             gomobile-bound API → gozar.aar
  android/              Android app (Kotlin + Jetpack Compose)
    build-go.sh         builds gozar.aar from core/mobile via gomobile
```

## Prerequisites

- Go 1.26+
- Android SDK (platform 35, build-tools 35), NDK r27 (27.2.x)
- JDK 17

Set `ANDROID_HOME` (or put `sdk.dir=` in `android/local.properties`).

## One-shot: build the APK

```bash
cd gozar/core
# 1) Root helper for each ABI (optional; only needed for root mode)
NDK="$ANDROID_HOME/ndk/27.2.12479018/toolchains/llvm/prebuilt/linux-x86_64/bin"
JNI=../android/app/src/main/jniLibs
mkdir -p "$JNI"/{arm64-v8a,armeabi-v7a,x86_64}
env CGO_ENABLED=1 GOOS=android GOARCH=arm64 CC="$NDK/aarch64-linux-android24-clang" \
  go build -buildmode=pie -trimpath -ldflags="-s -w" -o "$JNI/arm64-v8a/libgozarhelper.so" ./cmd/gozar-helper
env CGO_ENABLED=1 GOOS=android GOARCH=arm GOARM=7 CC="$NDK/armv7a-linux-androideabi24-clang" \
  go build -buildmode=pie -trimpath -ldflags="-s -w" -o "$JNI/armeabi-v7a/libgozarhelper.so" ./cmd/gozar-helper
env CGO_ENABLED=1 GOOS=android GOARCH=amd64 CC="$NDK/x86_64-linux-android24-clang" \
  go build -buildmode=pie -trimpath -ldflags="-s -w" -o "$JNI/x86_64/libgozarhelper.so" ./cmd/gozar-helper

cd ../android
# 2) The gomobile AAR (preBuild also triggers this if libs/gozar.aar is missing)
bash build-go.sh
# 3) The APK
./gradlew :app:assembleDebug
# → app/build/outputs/apk/debug/app-debug.apk
```

CI does all of the above in `.github/workflows/gozar.yml`; push a `gozar-v*`
tag to publish a release APK.

## Testing the Go core

```bash
cd gozar/core
go test ./...
```

`engine` ships a full-chain end-to-end test (`TestFullChainVLESSXHTTPSelfSigned`)
that starts a real Xray VLESS/XHTTP/TLS server with a self-signed cert and drives
traffic through the spoof proxy into it, proving the whole data path.

## Notes

- `libgozarhelper.so` is a Go PIE executable shipped under `jniLibs` so Android
  extracts it with execute permission; the app `exec`s it via `su` in root mode.
  `android/app` sets `useLegacyPackaging = true` so the native libs are extracted.
- Behind a TLS-terminating proxy, point Gradle's JVM at the proxy CA truststore
  and set `systemProp.https.proxyHost/Port` in `~/.gradle/gradle.properties`
  (do not commit machine-specific proxy settings to the project file).
