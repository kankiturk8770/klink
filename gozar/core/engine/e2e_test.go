package engine

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"testing"
	"time"

	xcore "github.com/xtls/xray-core/core"
	_ "github.com/xtls/xray-core/main/distro/all"
	"golang.org/x/net/proxy"
)

// This is the whole-chain verification I can run without a device:
//
//	curl ─▶ SOCKS(client xray) ─▶ VLESS/XHTTP/TLS(self-signed) ─▶ spoof proxy ─▶ server xray ─▶ echo
//
// A real xray server with an XHTTP+TLS inbound (self-signed cert) is started on
// a random port; a real xray client built by the engine dials it THROUGH the
// SNI-spoofing proxy. If the fake/fragmented ClientHello, the self-signed TLS
// trust (allowInsecure), the XHTTP transport and the relay all work together,
// the HTTP GET returns the echo body. Any broken link in the chain fails it.
func TestFullChainVLESSXHTTPSelfSigned(t *testing.T) {
	if testing.Short() {
		t.Skip("short")
	}
	// Plain HTTP echo target the server-side xray will forward to (freedom).
	echo := make(chan string, 1)
	target := startTCPEcho(t, echo)

	certPEM, keyPEM, certDER := selfSigned(t, "server.gozar.test")

	uuid := "b831381d-6324-4d53-ad4f-8cda48b30811"
	serverPort := freePortT(t)
	serverCfg := serverXrayConfig(uuid, serverPort, "/xh", string(certPEM), string(keyPEM), target)
	srv, err := xcore.StartInstance("json", serverCfg)
	if err != nil {
		t.Fatalf("server xray: %v", err)
	}
	defer srv.Close()
	time.Sleep(300 * time.Millisecond)

	// SHA-256 pin of the server leaf cert (colon-free hex) for the client.
	pin := sha256HexOf(certDER)

	link := fmt.Sprintf("vless://%s@127.0.0.1:%d?encryption=none&security=tls&type=xhttp&path=%%2Fxh&sni=server.gozar.test&pcs=%s#srv",
		uuid, serverPort, pin)

	e := New()
	s := DefaultSettings()
	s.Links = []string{link}
	s.LogLevel = "warning"
	s.Spoof.Mode = "non-root"
	s.Spoof.FakeTTL = 0 // on loopback the TTL fake can't be dropped; use only reassembly-safe steps
	s.Spoof.TLSRecordSplit = true
	s.Spoof.EnableFragment = true
	s.Spoof.SNIChunk = 2
	s.Spoof.Disorder = false
	s.Spoof.OOB = false
	s.Spoof.FakeSNI = "www.cloudflare.com"

	if err := e.Start(s, nil); err != nil {
		t.Fatalf("engine start: %v", err)
	}
	defer e.Stop()

	// Drive traffic through the SOCKS inbound the engine exposes.
	dialer, err := proxy.SOCKS5("tcp", fmt.Sprintf("127.0.0.1:%d", e.SocksPort()), nil, &net.Dialer{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	conn, err := dialer.Dial("tcp", "10.55.55.55:80") // arbitrary; server forwards everything to echo
	if err != nil {
		t.Fatalf("dial through chain: %v\nlogs:\n%s", err, e.Logs())
	}
	defer conn.Close()
	msg := "hello-through-gozar\n"
	if _, err := conn.Write([]byte(msg)); err != nil {
		t.Fatalf("write: %v", err)
	}
	select {
	case got := <-echo:
		if got != msg {
			t.Fatalf("echo mismatch: %q != %q", got, msg)
		}
	case <-time.After(8 * time.Second):
		t.Fatalf("no data reached the server through the chain\nlogs:\n%s", e.Logs())
	}

	snap := e.Snapshot()
	if snap.Total == 0 {
		t.Fatalf("spoof proxy saw no connections; chain bypassed it\nlogs:\n%s", e.Logs())
	}
	t.Logf("full chain ok: total=%d bytesUp=%d bytesDn=%d fakeSent=%d\n%s",
		snap.Total, snap.BytesUp, snap.BytesDn, snap.FakeSent, e.Logs())
}

func startTCPEcho(t *testing.T, got chan<- string) string {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 1024)
				n, _ := c.Read(buf)
				if n > 0 {
					select {
					case got <- string(buf[:n]):
					default:
					}
					c.Write(buf[:n])
				}
			}(c)
		}
	}()
	return ln.Addr().String()
}

func serverXrayConfig(uuid string, port int, path, certPEM, keyPEM, echoAddr string) []byte {
	host, p, _ := net.SplitHostPort(echoAddr)
	var echoPort int
	fmt.Sscanf(p, "%d", &echoPort)
	cfg := map[string]any{
		"log": map[string]any{"loglevel": "warning"},
		"inbounds": []any{map[string]any{
			"tag": "in", "listen": "127.0.0.1", "port": port, "protocol": "vless",
			"settings": map[string]any{"clients": []any{map[string]any{"id": uuid}}, "decryption": "none"},
			"streamSettings": map[string]any{
				"network":       "xhttp",
				"security":      "tls",
				"xhttpSettings": map[string]any{"path": path},
				"tlsSettings": map[string]any{
					"certificates": []any{map[string]any{
						"certificate": splitPEMLines(certPEM),
						"key":         splitPEMLines(keyPEM),
					}},
				},
			},
		}},
		// Everything the client sends is forwarded to the fixed echo target.
		"outbounds": []any{map[string]any{
			"tag": "out", "protocol": "freedom",
			"settings": map[string]any{"redirect": fmt.Sprintf("%s:%d", host, echoPort)},
		}},
	}
	b, _ := json.Marshal(cfg)
	return b
}

// xray's JSON cert accepts an array of lines; keep it simple with one string.
func splitPEMLines(pem string) []any {
	var out []any
	start := 0
	for i := 0; i < len(pem); i++ {
		if pem[i] == '\n' {
			out = append(out, pem[start:i])
			start = i + 1
		}
	}
	if start < len(pem) {
		out = append(out, pem[start:])
	}
	return out
}

func selfSigned(t *testing.T, cn string) (certPEM, keyPEM []byte, der []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{cn},
	}
	der, err = x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return
}

func sha256HexOf(der []byte) string {
	h := sha256Sum(der)
	const hexd = "0123456789abcdef"
	out := make([]byte, 0, 64)
	for _, b := range h {
		out = append(out, hexd[b>>4], hexd[b&0xf])
	}
	return string(out)
}

func freePortT(t *testing.T) int {
	t.Helper()
	p, err := freePort()
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// avoid extra import churn
func sha256Sum(b []byte) [32]byte {
	return sha256SumImpl(b)
}

var _ = io.Discard
var _ = os.Getenv
var _ = tls.VersionTLS13
var _ = context.Background
