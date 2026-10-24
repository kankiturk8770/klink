# کلاینت Android نسخه‌ی ۱

## استفاده

۱. روی سرور، پنل و core را مطابق `README.md` نصب و اجرا کنید.
۲. در پنل کاربر بسازید و لینک اشتراک را کپی کنید.
۳. APK را نصب کنید، دکمه‌ی `+` را بزنید و لینک را وارد کنید.
۴. دکمه‌ی اتصال را بزنید و درخواست مجوز VPN اندروید را تأیید کنید.
۵. نمایش «متصل» فقط پس از handshake معتبر و ساخت TUN انجام می‌شود. برای قطع، همان دکمه یا گزینه‌ی توقف در اعلان را بزنید.

لینک HTTP برای نصب‌های محلی پشتیبانی می‌شود، اما برای انتقال کلیدها روی شبکه‌ی عمومی حتماً HTTPS پنل را فعال کنید.

## معماری اتصال

- `KlinkVpnService.kt`: سرویس واقعی `VpnService`، ساخت TUN برای IPv4/IPv6، DNS، اعلان و لغو اتصال.
- `ConfigStore.kt`: رمزشده‌کردن JSON اشتراک با AES/GCM و کلید غیرقابل‌استخراج Android Keystore.
- `MainActivity.kt`: دریافت سابلینک، نمایش وضعیت واقعی و دکمه‌ی اتصال/قطع.
- `android/core/mobile`: مرز gomobile و مالکیت file descriptor مربوط به TUN.
- `android/core/client`: handshake Noise_XK، مسیر UDP/TCP، rekey، ping/pong، migration، reconnect و mux.
- `tun2socks/gVisor`: تبدیل بسته‌های TCP و UDP موجود در TUN به جریان‌های KLINK؛ بدون SOCKS واسطه.

برنامه با `addDisallowedApplication(packageName)` ترافیک socketهای خودش را از TUN خارج می‌کند تا حلقه‌ی VPN ایجاد نشود. اشتراک فقط در حالت قطع قابل تعویض است و لغو اتصال، handshake در حال انجام را نیز cancel می‌کند.

## ساخت

پیش‌نیاز: JDK 17، Android SDK 35، NDK 26.1.10909125 و برای بازسازی هسته Go 1.26 یا جدیدتر.

```bash
cd android
# مسیر SDK را در local.properties بنویسید:
# sdk.dir=/path/to/Android/Sdk

# AAR آماده در app/libs/klink.aar قرار دارد؛ ساخت معمولی:
./gradlew :app:assembleDebug

# بازسازی کامل AAR و سپس APK:
./build-go.sh
./gradlew :app:assembleDebug
```

خروجی:

```text
android/app/build/outputs/apk/debug/app-debug.apk
```

AAR شامل `arm64-v8a`، `armeabi-v7a` و `x86_64` است. بسته‌بندی native روی حالت غیر legacy است تا هر سه ABI در APK باقی بمانند. اسکریپت `build-go.sh` ابزارهای `gomobile` و `gobind` را در صورت نبودن نصب می‌کند و هنگام rebuild از alignment شانزده‌کیلوبایتی استفاده می‌کند.

## تست انجام‌شده و محدودیت بررسی

- `go test ./...` برای سرور و هسته‌ی Android موفق است.
- `go test -race ./...` و `go vet ./...` برای سرور و هسته‌ی Android موفق است.
- تست integration کلاینت با سرور واقعی KLINK، handshake، echo روی TCP/UDP، rekey مکرر، ping/pong و migration از UDP به TCP را پوشش می‌دهد.
- APK با Gradle کامپایل و امضای debug شده و حضور هر سه کتابخانه‌ی native داخل آن بررسی شده است.
- اجرای VpnService روی دستگاه فیزیکی یا emulator در محیط ساخت انجام نشده است؛ بنابراین تست نهایی مجوز VPN، تغییر Wi-Fi/mobile و عبور ترافیک دستگاه باید روی گوشی با سرور شما انجام شود.

این پروتکل هنوز ممیزی امنیتی مستقل نشده است. عبور تضمینی از DPI یا «غیرقابل‌شناسایی» بودن ادعا نمی‌شود.
