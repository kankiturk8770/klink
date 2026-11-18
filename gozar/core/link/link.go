// Package link parses proxy subscription share-links (vless://, vmess://,
// trojan://, ss://) and raw Xray outbound JSON into a normalized Profile.
//
// The parser is deliberate about the fields Gozar needs to drive its DPI
// bypass: the real upstream host/port (so the spoof proxy knows where to
// connect) and the TLS serverName (so Xray keeps presenting the right SNI even
// though it dials the local spoof proxy).
package link

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// Profile is one normalized server definition.
type Profile struct {
	Protocol string // vless, vmess, trojan, shadowsocks
	Remark   string // display name

	// RealHost/RealPort is the actual upstream the spoof proxy connects to.
	RealHost string
	RealPort int

	// Security is the stream security: "tls", "reality", "none".
	Security string
	// SNI is the TLS serverName presented to the server.
	SNI string
	// AllowInsecure accepts self-signed / mismatched certs (XHTTP self-signed case).
	AllowInsecure bool
	// PinnedPeerCertSha256 pins the server leaf/CA certificate (preferred over AllowInsecure).
	PinnedPeerCertSha256 string
	// FingerprintUTLS is the uTLS fingerprint for Xray's own real handshake (e.g. "chrome").
	FingerprintUTLS string
	// Network is the transport: tcp, ws, grpc, xhttp, httpupgrade, h2.
	Network string

	// outbound holds the Xray outbound object (protocol settings + streamSettings),
	// with address/port still pointing at the real host; the engine rewrites them
	// to the local spoof listener.
	outbound map[string]any
}

// Outbound returns a deep-ish copy of the Xray outbound object for this profile.
func (p *Profile) Outbound() map[string]any {
	return cloneMap(p.outbound)
}

// Parse parses a single share-link or raw outbound JSON object.
func Parse(raw string) (*Profile, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("empty link")
	}
	switch {
	case strings.HasPrefix(raw, "vless://"):
		return parseVLESS(raw)
	case strings.HasPrefix(raw, "vmess://"):
		return parseVMess(raw)
	case strings.HasPrefix(raw, "trojan://"):
		return parseTrojan(raw)
	case strings.HasPrefix(raw, "ss://"):
		return parseShadowsocks(raw)
	case strings.HasPrefix(raw, "{"):
		return parseOutboundJSON(raw)
	default:
		return nil, fmt.Errorf("unsupported link scheme (want vless/vmess/trojan/ss or JSON)")
	}
}

// ParseSubscription parses a subscription body: either newline-separated links
// or a single base64 blob of newline-separated links. Blank/comment lines and
// un-parseable lines are skipped; it errors only when nothing parses.
func ParseSubscription(body string) ([]*Profile, error) {
	body = strings.TrimSpace(body)
	if body == "" {
		return nil, fmt.Errorf("empty subscription")
	}
	lines := splitLinks(body)
	if len(lines) <= 1 && !looksLikeLink(body) {
		if dec, ok := tryBase64(body); ok {
			lines = splitLinks(dec)
		}
	}
	var out []*Profile
	var firstErr error
	for _, ln := range lines {
		ln = strings.TrimSpace(ln)
		if ln == "" || strings.HasPrefix(ln, "#") || strings.HasPrefix(ln, "//") {
			continue
		}
		p, err := Parse(ln)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		out = append(out, p)
	}
	if len(out) == 0 {
		if firstErr != nil {
			return nil, firstErr
		}
		return nil, fmt.Errorf("no valid profiles in subscription")
	}
	return out, nil
}

func splitLinks(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool { return r == '\n' || r == '\r' })
}

func looksLikeLink(s string) bool {
	for _, p := range []string{"vless://", "vmess://", "trojan://", "ss://", "{"} {
		if strings.HasPrefix(strings.TrimSpace(s), p) {
			return true
		}
	}
	return false
}

func tryBase64(s string) (string, bool) {
	s = strings.TrimSpace(s)
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(s); err == nil && len(b) > 0 {
			t := strings.TrimSpace(string(b))
			if looksLikeLink(t) {
				return t, true
			}
		}
	}
	return "", false
}

func cloneMap(m map[string]any) map[string]any {
	b, _ := json.Marshal(m)
	var out map[string]any
	_ = json.Unmarshal(b, &out)
	return out
}

func atoiDefault(s string, def int) int {
	if v, err := strconv.Atoi(strings.TrimSpace(s)); err == nil {
		return v
	}
	return def
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// hostPort splits "host:port" (IPv4/host or [IPv6]) with a default port.
func hostPort(s string, defPort int) (string, int) {
	h, p, err := net.SplitHostPort(s)
	if err != nil {
		return strings.Trim(s, "[]"), defPort
	}
	return h, atoiDefault(p, defPort)
}

func qget(q url.Values, keys ...string) string {
	for _, k := range keys {
		if v := q.Get(k); v != "" {
			return v
		}
	}
	return ""
}
