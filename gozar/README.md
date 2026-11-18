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

## Known limitations (v0.1)

- **TCP is fully tunnelled** through Xray (so HTTPS / DoH browsing is covered and
  the proxy connection itself gets the SNI-spoofing treatment). **UDP and plain
  DNS (:53)** currently egress via a VPN-protected direct socket rather than
  through Xray, so UDP apps keep working but DNS is not tunnelled; prefer DoH/DoT
  or a DNS the censor does not poison. Routing UDP through Xray's SOCKS UDP
  associate is planned.
- **Root mode is experimental.** The helper and its `su` wiring are implemented
  and build for every ABI, but on-device root was not validated on real hardware.
  Non-root mode is the tested default.
