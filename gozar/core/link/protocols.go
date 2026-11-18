package link

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

func parseVLESS(raw string) (*Profile, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("vless: %w", err)
	}
	host, port := hostPort(u.Host, 443)
	if host == "" || port == 0 {
		return nil, fmt.Errorf("vless: missing host/port")
	}
	id := u.User.Username()
	if id == "" {
		return nil, fmt.Errorf("vless: missing uuid")
	}
	q := u.Query()
	p := &Profile{Protocol: "vless", RealHost: host, RealPort: port}
	p.Remark = remark(u, host, port)

	stream := buildStreamSettings(p, q, host)
	user := map[string]any{"id": id, "encryption": firstNonEmpty(qget(q, "encryption"), "none")}
	if flow := qget(q, "flow"); flow != "" {
		user["flow"] = flow
	}
	p.outbound = map[string]any{
		"protocol": "vless",
		"settings": map[string]any{
			"vnext": []any{map[string]any{
				"address": host, "port": port,
				"users": []any{user},
			}},
		},
		"streamSettings": stream,
	}
	return p, nil
}

func parseTrojan(raw string) (*Profile, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("trojan: %w", err)
	}
	host, port := hostPort(u.Host, 443)
	pass := u.User.Username()
	if host == "" || pass == "" {
		return nil, fmt.Errorf("trojan: missing host or password")
	}
	q := u.Query()
	p := &Profile{Protocol: "trojan", RealHost: host, RealPort: port}
	p.Remark = remark(u, host, port)
	if p.Security = firstNonEmpty(qget(q, "security"), "tls"); q.Get("security") == "" {
		q.Set("security", "tls") // trojan defaults to TLS
	}
	stream := buildStreamSettings(p, q, host)
	p.outbound = map[string]any{
		"protocol": "trojan",
		"settings": map[string]any{
			"servers": []any{map[string]any{"address": host, "port": port, "password": pass}},
		},
		"streamSettings": stream,
	}
	return p, nil
}

// vmessJSON is the standard base64-JSON vmess share format.
type vmessJSON struct {
	V    any    `json:"v"`
	PS   string `json:"ps"`
	Add  string `json:"add"`
	Port any    `json:"port"`
	ID   string `json:"id"`
	Aid  any    `json:"aid"`
	Scy  string `json:"scy"`
	Net  string `json:"net"`
	Type string `json:"type"`
	Host string `json:"host"`
	Path string `json:"path"`
	TLS  string `json:"tls"`
	SNI  string `json:"sni"`
	ALPN string `json:"alpn"`
	FP   string `json:"fp"`
}

func asInt(v any, def int) int {
	switch t := v.(type) {
	case float64:
		return int(t)
	case string:
		return atoiDefault(t, def)
	case int:
		return t
	}
	return def
}

func parseVMess(raw string) (*Profile, error) {
	b64 := strings.TrimPrefix(raw, "vmess://")
	var dec []byte
	var err error
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if dec, err = enc.DecodeString(strings.TrimSpace(b64)); err == nil {
			break
		}
	}
	if err != nil {
		return nil, fmt.Errorf("vmess: base64: %w", err)
	}
	var v vmessJSON
	if err := json.Unmarshal(dec, &v); err != nil {
		return nil, fmt.Errorf("vmess: json: %w", err)
	}
	port := asInt(v.Port, 443)
	if v.Add == "" || port == 0 || v.ID == "" {
		return nil, fmt.Errorf("vmess: missing add/port/id")
	}
	q := url.Values{}
	q.Set("type", firstNonEmpty(v.Net, "tcp"))
	q.Set("security", firstNonEmpty(v.TLS, "none"))
	q.Set("sni", v.SNI)
	q.Set("host", v.Host)
	q.Set("path", v.Path)
	q.Set("fp", v.FP)
	q.Set("alpn", v.ALPN)
	if v.Type == "http" {
		q.Set("headerType", "http")
	}
	p := &Profile{Protocol: "vmess", RealHost: v.Add, RealPort: port}
	p.Remark = firstNonEmpty(v.PS, fmt.Sprintf("%s:%d", v.Add, port))
	stream := buildStreamSettings(p, q, v.Add)
	user := map[string]any{"id": v.ID, "alterId": asInt(v.Aid, 0), "security": firstNonEmpty(v.Scy, "auto")}
	p.outbound = map[string]any{
		"protocol": "vmess",
		"settings": map[string]any{
			"vnext": []any{map[string]any{"address": v.Add, "port": port, "users": []any{user}}},
		},
		"streamSettings": stream,
	}
	return p, nil
}

func parseShadowsocks(raw string) (*Profile, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("ss: %w", err)
	}
	var method, pass string
	if u.User != nil && u.User.Username() != "" {
		if pw, ok := u.User.Password(); ok {
			method, pass = u.User.Username(), pw
		} else {
			// userinfo is base64(method:password)
			if dec, derr := decodeB64(u.User.Username()); derr == nil {
				method, pass, _ = strings.Cut(dec, ":")
			}
		}
	}
	host, port := hostPort(u.Host, 8388)
	if method == "" {
		// Whole authority may be base64: ss://base64(method:pass@host:port)
		if dec, derr := decodeB64(strings.TrimPrefix(raw, "ss://")); derr == nil {
			body, _, _ := strings.Cut(dec, "#")
			up, hp, ok := strings.Cut(body, "@")
			if ok {
				method, pass, _ = strings.Cut(up, ":")
				host, port = hostPort(hp, 8388)
			}
		}
	}
	if host == "" || method == "" || pass == "" {
		return nil, fmt.Errorf("ss: missing host/method/password")
	}
	p := &Profile{Protocol: "shadowsocks", RealHost: host, RealPort: port, Network: "tcp", Security: "none"}
	p.Remark = firstNonEmpty(decodeFragment(u.Fragment), fmt.Sprintf("%s:%d", host, port))
	p.outbound = map[string]any{
		"protocol": "shadowsocks",
		"settings": map[string]any{
			"servers": []any{map[string]any{"address": host, "port": port, "method": method, "password": pass}},
		},
		"streamSettings": map[string]any{"network": "tcp"},
	}
	return p, nil
}

func parseOutboundJSON(raw string) (*Profile, error) {
	var ob map[string]any
	if err := json.Unmarshal([]byte(raw), &ob); err != nil {
		return nil, fmt.Errorf("json outbound: %w", err)
	}
	// Accept a full config and pull the first outbound.
	if obs, ok := ob["outbounds"].([]any); ok && len(obs) > 0 {
		if m, ok := obs[0].(map[string]any); ok {
			ob = m
		}
	}
	proto, _ := ob["protocol"].(string)
	if proto == "" {
		return nil, fmt.Errorf("json outbound: missing protocol")
	}
	p := &Profile{Protocol: proto, outbound: ob}
	p.RealHost, p.RealPort = outboundServer(ob)
	if p.RealHost == "" {
		return nil, fmt.Errorf("json outbound: cannot find server address")
	}
	p.SNI, p.Security, p.Network = outboundStreamInfo(ob, p.RealHost)
	p.Remark = firstNonEmpty(strOf(ob["tag"]), fmt.Sprintf("%s %s:%d", proto, p.RealHost, p.RealPort))
	return p, nil
}

func decodeB64(s string) (string, error) {
	for _, enc := range []*base64.Encoding{base64.RawURLEncoding, base64.StdEncoding, base64.URLEncoding, base64.RawStdEncoding} {
		if b, err := enc.DecodeString(strings.TrimSpace(s)); err == nil {
			return string(b), nil
		}
	}
	return "", fmt.Errorf("not base64")
}

func decodeFragment(f string) string {
	if dec, err := url.QueryUnescape(f); err == nil {
		return dec
	}
	return f
}

func remark(u *url.URL, host string, port int) string {
	if u.Fragment != "" {
		return decodeFragment(u.Fragment)
	}
	return host + ":" + strconv.Itoa(port)
}

func strOf(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}
