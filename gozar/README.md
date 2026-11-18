# Gozar — Android DPI bypass (SNI spoofing) + Xray client

Gozar (گذر) is a separate Android application that reproduces the full behaviour
of the desktop **SNI-Spoofing-Go** tool on the phone, and adds an embedded Xray
client so a subscription/config can be imported and used directly — the phone
itself plays the role the "Iran relay" plays in the desktop scenario.

Data path on the phone:

```
apps ─▶ VpnService TUN ─▶ tun2socks (gVisor) ─▶ SOCKS ─▶ Xray (your vless/xhttp/tls)
      ─▶ 127.0.0.1:spoofPort ─▶ SNI-spoofing proxy ─▶ real server abroad
```

The SNI-spoofing proxy injects a fake/fragmented ClientHello with a decoy SNI so
DPI sees an innocuous name, then relays the real encrypted handshake.

## Modes

- **Root** (`active`/`passive`/`raw`): true wrong-seq fake ClientHello via
  NFQUEUE / AF_PACKET + raw sockets, run in a root domain by `gozar-helper`
  over `su`. Bit-for-bit the desktop technique.
- **Non-root**: TTL-limited in-stream fake, TLS-record split across the SNI,
  ClientHello TCP fragmentation, disorder and OOB — all on the proxy's own
  socket, no special privileges.

This is an independent app from KLINK; it shares the repository only.

The Go core under `core/` is forked from SNI-Spoofing-Go (GPL-3.0); see
`core/LICENSE.sni-spoofing-go`.
