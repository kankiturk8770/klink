// Package engine assembles and runs the full Gozar data path: a local SNI
// spoofing proxy (DPI bypass) in front of an Xray instance, optionally fed by
// a TUN device from the Android VpnService.
//
//	TUN fd ─▶ tun2socks ─▶ SOCKS(127.0.0.1) ─▶ Xray(user protocol) ─▶ 127.0.0.1:spoofPort ─▶ spoof proxy ─▶ real server
//
// Xray dials the local spoof listener instead of the server directly, so every
// outbound TCP connection carries the fake/fragmented ClientHello before the
// real TLS handshake reaches the censor.
package engine

import (
	"encoding/json"
	"fmt"

	"gozar/core/link"
)

// Settings is the full runtime configuration for one tunnel.
type Settings struct {
	// Links is one or more share-links / JSON outbounds. The first is used
	// as the active server; the rest are kept for the UI.
	Links []string

	// Spoof controls the DPI bypass layer.
	Spoof SpoofSettings

	// SocksPort is the local SOCKS inbound Xray exposes for tun2socks. 0 = auto.
	SocksPort int
	// DNS is the upstream resolver Xray uses (e.g. "1.1.1.1", "8.8.8.8").
	DNS string
	// LogLevel: debug, info, warning, error, none.
	LogLevel string
	// EnableSniffing routes by sniffed domain and enables domain rules.
	EnableSniffing bool

	// DialOverrideHost/Port, when set, makes Xray dial this address instead of
	// the real server or the in-process spoof listener. The root helper
	// (gozar-helper) runs the privileged spoof proxy at this address, so set it
	// together with Spoof.Enabled=false in root mode.
	DialOverrideHost string
	DialOverridePort int
}

// SpoofSettings mirrors proxy.Options but as a serialisable, UI-facing struct.
type SpoofSettings struct {
	// Enabled turns the spoof proxy on. When false Xray dials the server directly.
	Enabled bool
	// FakeSNI is the decoy SNI the censor sees. Empty = derive from the real SNI's apex.
	FakeSNI string
	// UTLS fingerprint for the fake ClientHello (firefox/chrome/.../none).
	UTLS string
	// Mode: "root-active", "root-passive", "root-raw", "non-root".
	Mode string

	FakeRepeat      int
	FakeDelayMS     int
	AckTimeoutMS    int
	EnableFragment  bool
	FragmentDelayMS int
	SNIChunk        int

	// Non-root knobs.
	FakeTTL        int
	FakeHoldMS     int
	TLSRecordSplit bool
	Disorder       bool
	DisorderTTL    int
	OOB            bool

	// ConnectTimeoutMS bounds each upstream dial.
	ConnectTimeoutMS int
}

// DefaultSettings returns sensible defaults (non-root, fragment on).
func DefaultSettings() Settings {
	return Settings{
		DNS:            "1.1.1.1",
		LogLevel:       "warning",
		EnableSniffing: true,
		Spoof: SpoofSettings{
			Enabled:         true,
			UTLS:            "chrome",
			Mode:            "non-root",
			FakeRepeat:      1,
			FakeDelayMS:     2,
			AckTimeoutMS:    2000,
			EnableFragment:  true,
			FragmentDelayMS: 2,
			SNIChunk:        3,
			// FakeTTL defaults OFF: the TTL-limited in-stream fake only works on
			// a multi-hop censored path and corrupts the handshake if the decoy
			// reaches the server. Fragmentation + TLS-record split are
			// reassembly-safe and defeat most SNI DPI on their own. Users can
			// enable the TTL fake from advanced settings.
			FakeTTL:          0,
			FakeHoldMS:       5,
			TLSRecordSplit:   true,
			Disorder:         false,
			DisorderTTL:      4,
			OOB:              false,
			ConnectTimeoutMS: 10000,
		},
	}
}

// dnsInboundPort is the loopback UDP port where Xray accepts DNS queries that
// tun2socks redirects to it. FakeDNS answers them, so no real resolver is hit.
const dnsInboundPort = 10853

// buildXrayConfig produces the Xray JSON config as bytes. dialHost/dialPort is
// where Xray dials the active profile (the spoof listener when spoofing is on,
// else the real server). socksPort is the local SOCKS inbound.
//
// DNS uses Xray FakeDNS: the TUN sends UDP:53 to a local dokodemo "dns-in"
// inbound, routed to the "dns-out" (protocol "dns") outbound, which answers
// from Xray's DNS. With a fakedns server first, queries get a fake IP from
// 198.18.0.0/15 immediately (no upstream resolver needed — critical on a
// censored network). Apps then connect to that fake IP over TCP; sniffing
// (destOverride "fakedns") maps it back to the real domain, and the proxy
// outbound sends the domain to the server for remote resolution. This also
// works over XHTTP, which cannot carry UDP.
func buildXrayConfig(active *link.Profile, dialHost string, dialPort, socksPort int, s Settings) ([]byte, error) {
	if active == nil {
		return nil, fmt.Errorf("no active profile")
	}
	outbound := active.Rewrite(dialHost, dialPort, "proxy")
	upstreamDNS := firstNonEmptyStr(s.DNS, "1.1.1.1")

	sniff := sniffing(s.EnableSniffing)

	inbounds := []any{
		map[string]any{
			"tag":      "socks-in",
			"listen":   "127.0.0.1",
			"port":     socksPort,
			"protocol": "socks",
			"settings": map[string]any{"udp": true, "auth": "noauth"},
			"sniffing": sniff,
		},
		// DNS catcher: tun2socks redirects UDP:53 here; dest is the configured
		// resolver but routing sends it to the "dns" outbound (FakeDNS answers).
		map[string]any{
			"tag":      "dns-in",
			"listen":   "127.0.0.1",
			"port":     dnsInboundPort,
			"protocol": "dokodemo-door",
			"settings": map[string]any{
				"address": upstreamDNS,
				"port":    53,
				"network": "tcp,udp",
			},
		},
	}

	cfg := map[string]any{
		"log": map[string]any{"loglevel": firstNonEmptyStr(s.LogLevel, "warning")},
		"fakedns": []any{
			map[string]any{"ipPool": "198.18.0.0/15", "poolSize": 65535},
		},
		"dns": map[string]any{
			"servers": []any{
				map[string]any{"address": "fakedns"},
				upstreamDNS,
			},
			"queryStrategy": "UseIPv4",
		},
		"inbounds": inbounds,
		"outbounds": []any{
			outbound,
			map[string]any{"tag": "direct", "protocol": "freedom", "settings": map[string]any{"domainStrategy": "UseIPv4"}},
			map[string]any{"tag": "dns-out", "protocol": "dns"},
			map[string]any{"tag": "block", "protocol": "blackhole"},
		},
		"routing": map[string]any{
			"domainStrategy": "IPIfNonMatch",
			"rules": []any{
				// DNS queries (the dns-in inbound, and any stray :53) -> dns-out.
				map[string]any{"type": "field", "inboundTag": []any{"dns-in"}, "outboundTag": "dns-out"},
				map[string]any{"type": "field", "port": 53, "outboundTag": "dns-out"},
				// Keep loopback direct so Xray's dial to the spoof proxy never loops.
				map[string]any{"type": "field", "ip": []any{"127.0.0.1/32"}, "outboundTag": "direct"},
				// Everything else through the proxy.
				map[string]any{"type": "field", "network": "tcp,udp", "outboundTag": "proxy"},
			},
		},
	}
	return json.MarshalIndent(cfg, "", "  ")
}

func sniffing(on bool) map[string]any {
	if !on {
		return map[string]any{"enabled": false}
	}
	// fakedns first so fake IPs map back to domains; then tls/http for SNI/Host.
	return map[string]any{"enabled": true, "destOverride": []any{"fakedns", "tls", "http", "quic"}, "routeOnly": false}
}

func firstNonEmptyStr(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
