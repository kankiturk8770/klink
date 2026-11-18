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
			Enabled:          true,
			UTLS:             "chrome",
			Mode:             "non-root",
			FakeRepeat:       1,
			FakeDelayMS:      2,
			AckTimeoutMS:     2000,
			EnableFragment:   true,
			FragmentDelayMS:  2,
			SNIChunk:         3,
			FakeTTL:          4,
			FakeHoldMS:       5,
			TLSRecordSplit:   true,
			Disorder:         false,
			DisorderTTL:      4,
			OOB:              false,
			ConnectTimeoutMS: 10000,
		},
	}
}

// buildXrayConfig produces the Xray JSON config as bytes. outboundDialAddr /
// outboundDialPort is where Xray should dial the active profile (the spoof
// listener when spoofing is on, else the real server). socksPort is the local
// SOCKS inbound. tunFd < 0 means no TUN inbound (SOCKS only, used for tests).
func buildXrayConfig(active *link.Profile, dialHost string, dialPort, socksPort int, s Settings) ([]byte, error) {
	if active == nil {
		return nil, fmt.Errorf("no active profile")
	}
	outbound := active.Rewrite(dialHost, dialPort, "proxy")

	dnsServers := []any{firstNonEmptyStr(s.DNS, "1.1.1.1"), "localhost"}

	inbounds := []any{
		map[string]any{
			"tag":      "socks-in",
			"listen":   "127.0.0.1",
			"port":     socksPort,
			"protocol": "socks",
			"settings": map[string]any{"udp": true, "auth": "noauth"},
			"sniffing": sniffing(s.EnableSniffing),
		},
	}

	cfg := map[string]any{
		"log":      map[string]any{"loglevel": firstNonEmptyStr(s.LogLevel, "warning")},
		"dns":      map[string]any{"servers": dnsServers, "queryStrategy": "UseIPv4"},
		"inbounds": inbounds,
		"outbounds": []any{
			outbound,
			map[string]any{"tag": "direct", "protocol": "freedom", "settings": map[string]any{"domainStrategy": "UseIPv4"}},
			map[string]any{"tag": "block", "protocol": "blackhole"},
		},
		"routing": map[string]any{
			"domainStrategy": "IPIfNonMatch",
			"rules": []any{
				// Keep the spoof listener / local traffic direct so Xray's own
				// dial to the spoof proxy never loops back through the tunnel.
				map[string]any{"type": "field", "ip": []any{"127.0.0.1/32"}, "outboundTag": "direct"},
			},
		},
	}
	return json.MarshalIndent(cfg, "", "  ")
}

func sniffing(on bool) map[string]any {
	if !on {
		return map[string]any{"enabled": false}
	}
	return map[string]any{"enabled": true, "destOverride": []any{"tls", "http", "quic"}, "routeOnly": false}
}

func firstNonEmptyStr(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
