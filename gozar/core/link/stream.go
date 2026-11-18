package link

import (
	"net/url"
	"strings"
)

// buildStreamSettings builds an Xray streamSettings object from the common
// query parameters shared by vless/trojan links, and fills the TLS fields on
// the profile. host/sni fall back to the real host when not specified.
func buildStreamSettings(p *Profile, q url.Values, realHost string) map[string]any {
	network := firstNonEmpty(qget(q, "type"), "tcp")
	security := firstNonEmpty(qget(q, "security"), "none")
	p.Network = network
	p.Security = security

	stream := map[string]any{
		"network":  network,
		"security": security,
	}

	sni := qget(q, "sni")
	host := qget(q, "host")
	fp := qget(q, "fp")
	alpn := qget(q, "alpn")
	p.FingerprintUTLS = fp

	switch security {
	case "tls":
		p.SNI = firstNonEmpty(sni, host, realHost)
		tls := map[string]any{"serverName": p.SNI}
		if fp != "" {
			tls["fingerprint"] = fp
		}
		if alpn != "" {
			tls["alpn"] = strings.Split(alpn, ",")
		}
		applyInsecure(p, q, tls)
		stream["tlsSettings"] = tls
	case "reality":
		p.SNI = firstNonEmpty(sni, realHost)
		reality := map[string]any{
			"serverName":  p.SNI,
			"fingerprint": firstNonEmpty(fp, "chrome"),
			"publicKey":   qget(q, "pbk"),
			"shortId":     qget(q, "sid"),
			"spiderX":     qget(q, "spx"),
		}
		stream["realitySettings"] = reality
	}

	applyTransport(stream, network, q, host)
	return stream
}

func applyInsecure(p *Profile, q url.Values, tls map[string]any) {
	if pin := qget(q, "pcs", "pinnedPeerCertSha256"); pin != "" {
		p.PinnedPeerCertSha256 = pin
		tls["pinnedPeerCertSha256"] = pin
	}
	ai := qget(q, "allowInsecure", "allowinsecure", "insecure")
	if ai == "1" || strings.EqualFold(ai, "true") {
		p.AllowInsecure = true
		tls["allowInsecure"] = true
	}
}

func applyTransport(stream map[string]any, network string, q url.Values, host string) {
	path := qget(q, "path")
	switch network {
	case "ws":
		ws := map[string]any{}
		if path != "" {
			ws["path"] = path
		}
		if host != "" {
			ws["host"] = host
		}
		stream["wsSettings"] = ws
	case "httpupgrade":
		hu := map[string]any{}
		if path != "" {
			hu["path"] = path
		}
		if host != "" {
			hu["host"] = host
		}
		stream["httpupgradeSettings"] = hu
	case "xhttp", "splithttp":
		stream["network"] = "xhttp"
		xh := map[string]any{}
		if path != "" {
			xh["path"] = path
		}
		if host != "" {
			xh["host"] = host
		}
		if mode := qget(q, "mode"); mode != "" {
			xh["mode"] = mode
		}
		stream["xhttpSettings"] = xh
	case "grpc":
		g := map[string]any{}
		if sn := qget(q, "serviceName"); sn != "" {
			g["serviceName"] = sn
		}
		stream["grpcSettings"] = g
	case "h2", "http":
		stream["network"] = "http"
		h := map[string]any{}
		if path != "" {
			h["path"] = path
		}
		if host != "" {
			h["host"] = strings.Split(host, ",")
		}
		stream["httpSettings"] = h
	case "tcp":
		if hdr := qget(q, "headerType"); hdr == "http" {
			tcp := map[string]any{"header": map[string]any{"type": "http"}}
			stream["tcpSettings"] = tcp
		}
	}
}
