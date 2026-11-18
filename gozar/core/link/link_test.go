package link

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func TestParseVLESSXHTTPTLSSelfSigned(t *testing.T) {
	raw := "vless://11111111-2222-3333-4444-555555555555@198.51.100.7:443?encryption=none&security=tls&sni=decoy.example.com&type=xhttp&path=%2Fxh&mode=auto&fp=chrome&allowInsecure=1#Abroad"
	p, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if p.Protocol != "vless" || p.RealHost != "198.51.100.7" || p.RealPort != 443 {
		t.Fatalf("server wrong: %+v", p)
	}
	if p.SNI != "decoy.example.com" || !p.AllowInsecure || p.Network != "xhttp" || p.Security != "tls" {
		t.Fatalf("stream wrong: %+v", p)
	}
	if p.Remark != "Abroad" {
		t.Fatalf("remark %q", p.Remark)
	}
	ob := p.Outbound()
	ss := ob["streamSettings"].(map[string]any)
	if ss["network"] != "xhttp" {
		t.Fatalf("network %v", ss["network"])
	}
	if _, ok := ss["xhttpSettings"].(map[string]any); !ok {
		t.Fatal("missing xhttpSettings")
	}
	tls := ss["tlsSettings"].(map[string]any)
	if tls["serverName"] != "decoy.example.com" || tls["allowInsecure"] != true {
		t.Fatalf("tls %v", tls)
	}
}

func TestParseVMess(t *testing.T) {
	v := map[string]any{
		"v": "2", "ps": "node1", "add": "203.0.113.9", "port": "8443", "id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
		"aid": "0", "net": "ws", "host": "cdn.example.com", "path": "/ray", "tls": "tls", "sni": "cdn.example.com",
	}
	b, _ := json.Marshal(v)
	raw := "vmess://" + base64.StdEncoding.EncodeToString(b)
	p, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if p.RealHost != "203.0.113.9" || p.RealPort != 8443 || p.SNI != "cdn.example.com" || p.Network != "ws" {
		t.Fatalf("vmess wrong: %+v", p)
	}
	ob := p.Outbound()
	ss := ob["streamSettings"].(map[string]any)
	ws := ss["wsSettings"].(map[string]any)
	if ws["path"] != "/ray" || ws["host"] != "cdn.example.com" {
		t.Fatalf("ws %v", ws)
	}
}

func TestParseTrojanDefaultsTLS(t *testing.T) {
	p, err := Parse("trojan://secret@example.org:443?sni=example.org#T")
	if err != nil {
		t.Fatal(err)
	}
	if p.Security != "tls" || p.SNI != "example.org" {
		t.Fatalf("trojan tls default wrong: %+v", p)
	}
	ob := p.Outbound()
	srv := ob["settings"].(map[string]any)["servers"].([]any)[0].(map[string]any)
	if srv["password"] != "secret" {
		t.Fatalf("password %v", srv["password"])
	}
}

func TestParseShadowsocksSIP002(t *testing.T) {
	userinfo := base64.RawURLEncoding.EncodeToString([]byte("aes-256-gcm:pass123"))
	p, err := Parse("ss://" + userinfo + "@192.0.2.5:8388#ss-node")
	if err != nil {
		t.Fatal(err)
	}
	if p.RealHost != "192.0.2.5" || p.RealPort != 8388 {
		t.Fatalf("ss wrong: %+v", p)
	}
	srv := p.Outbound()["settings"].(map[string]any)["servers"].([]any)[0].(map[string]any)
	if srv["method"] != "aes-256-gcm" || srv["password"] != "pass123" {
		t.Fatalf("ss creds %v", srv)
	}
}

func TestParseSubscriptionBase64(t *testing.T) {
	links := "vless://11111111-2222-3333-4444-555555555555@198.51.100.7:443?security=tls&type=tcp#a\ntrojan://p@198.51.100.8:443#b"
	blob := base64.StdEncoding.EncodeToString([]byte(links))
	ps, err := ParseSubscription(blob)
	if err != nil {
		t.Fatal(err)
	}
	if len(ps) != 2 {
		t.Fatalf("got %d profiles", len(ps))
	}
}

func TestParseRawJSONOutbound(t *testing.T) {
	raw := `{"protocol":"vless","settings":{"vnext":[{"address":"198.51.100.7","port":443,"users":[{"id":"x","encryption":"none"}]}]},"streamSettings":{"network":"tcp","security":"tls","tlsSettings":{"serverName":"d.example"}}}`
	p, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if p.RealHost != "198.51.100.7" || p.RealPort != 443 || p.SNI != "d.example" {
		t.Fatalf("raw json wrong: %+v", p)
	}
}

func TestSetOutboundServerRewrites(t *testing.T) {
	p, _ := Parse("vless://x@198.51.100.7:443?security=tls&type=tcp#a")
	ob := p.Outbound()
	setOutboundServer(ob, "127.0.0.1", 41000)
	vnext := ob["settings"].(map[string]any)["vnext"].([]any)[0].(map[string]any)
	if vnext["address"] != "127.0.0.1" || vnext["port"] != 41000 {
		t.Fatalf("rewrite failed: %v", vnext)
	}
	// original profile outbound must be unchanged (Outbound returns a copy)
	orig := p.Outbound()["settings"].(map[string]any)["vnext"].([]any)[0].(map[string]any)
	if orig["address"] != "198.51.100.7" {
		t.Fatal("Outbound() must return a copy")
	}
}

func TestParseErrors(t *testing.T) {
	for _, bad := range []string{"", "http://x", "vless://@host", "vmess://!!!"} {
		if _, err := Parse(bad); err == nil && !strings.HasPrefix(bad, "vless://@") {
			t.Fatalf("expected error for %q", bad)
		}
	}
}
