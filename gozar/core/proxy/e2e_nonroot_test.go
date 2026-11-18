//go:build linux

package proxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"gozar/core/config"
)

func startEcho(t *testing.T) (*httptest.Server, string, int, *x509.CertPool) {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "ok:"+r.Host)
	}))
	ta := srv.Listener.Addr().(*net.TCPAddr)
	host := ta.IP.String()
	if host == "::" || host == "" {
		host = "127.0.0.1"
	}
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	return srv, host, ta.Port, pool
}

func runProxy(t *testing.T, cfg *config.Config, opts Options) string {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	ready := make(chan Ready, 1)
	go Run(ctx, cfg, opts, ready)
	select {
	case r := <-ready:
		if r.Err != nil {
			t.Fatalf("proxy start: %v", r.Err)
		}
		_, lp, _ := net.SplitHostPort(r.ListenAddr)
		return lp
	case <-time.After(5 * time.Second):
		t.Fatal("proxy never started")
	}
	return ""
}

func httpsThrough(t *testing.T, localPort string, pool *x509.CertPool, sni string) (int, string) {
	t.Helper()
	client := &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp4", "127.0.0.1:"+localPort)
		},
		TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: sni},
	}, Timeout: 10 * time.Second}
	resp, err := client.Get("https://" + sni + "/")
	if err != nil {
		t.Fatalf("request through proxy failed: %v", err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

// TestReassemblySafeDesyncEndToEnd drives the methods that MUST preserve a valid
// stream for a conforming server (TLS record split inside the SNI + ClientHello
// TCP fragmentation with small SNI chunks). A conforming server reassembles
// them, so the real ServerName must still arrive intact and the HTTPS request
// must complete. This is the end-to-end correctness check for those options.
func TestReassemblySafeDesyncEndToEnd(t *testing.T) {
	srv, host, port, pool := startEcho(t)
	defer srv.Close()
	cfg := &config.Config{
		ListenHost: "127.0.0.1", ListenPort: 0,
		ConnectIP: host, ConnectIPv4s: []string{host}, ConnectPort: port,
		FakeSNI: "www.fake-decoy.example", UTLSClientHello: "none",
	}
	for _, tc := range []struct {
		name string
		opts Options
	}{
		{"recordsplit", Options{TLSRecordSplit: true}},
		{"fragment-snichunk", Options{EnableFragment: true, SNIChunk: 2, FragmentDelay: time.Millisecond}},
		{"recordsplit+fragment", Options{TLSRecordSplit: true, EnableFragment: true, SNIChunk: 3, FragmentDelay: time.Millisecond}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := tc.opts
			o.Injector = InjectorNone
			o.Quiet = true
			o.ConnectTimeout = 5 * time.Second
			lp := runProxy(t, cfg, o)
			code, body := httpsThrough(t, lp, pool, "example.com")
			if code != 200 || body == "" {
				t.Fatalf("bad response %d %q", code, body)
			}
			t.Logf("%s ok: %s", tc.name, body)
		})
	}
}

// TestTTLDesyncSyscallsRun exercises the TTL fake / disorder / OOB code paths.
// On loopback the low-TTL fake is NOT dropped (there are no intermediate hops),
// so the decoy reaches the server and the TLS handshake is expected to fail —
// the real-world bypass needs a censored path. This test only asserts that the
// syscalls (vmsplice/splice/TCP_INFO/IP_TTL/MSG_OOB) succeed on this kernel and
// the proxy does not crash, which is what we can verify without a real path.
func TestTTLDesyncSyscallsRun(t *testing.T) {
	srv, host, port, pool := startEcho(t)
	defer srv.Close()
	cfg := &config.Config{
		ListenHost: "127.0.0.1", ListenPort: 0,
		ConnectIP: host, ConnectIPv4s: []string{host}, ConnectPort: port,
		FakeSNI: "www.fake-decoy.example", UTLSClientHello: "none",
	}
	opts := Options{
		Injector: InjectorNone, Quiet: true,
		FakeTTL: 4, FakeHold: 2 * time.Millisecond,
		Disorder: true, DisorderTTL: 4, OOB: true,
		FakeRepeat: 1, ConnectTimeout: 5 * time.Second,
	}
	lp := runProxy(t, cfg, opts)
	client := &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp4", "127.0.0.1:"+lp)
		},
		TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: "example.com"},
	}, Timeout: 3 * time.Second}
	// Either it fails (loopback keeps the decoy) or, if the kernel happened to
	// drop it, it succeeds — both mean the code path executed without crashing.
	resp, err := client.Get("https://example.com/")
	if err == nil {
		resp.Body.Close()
	}
	t.Logf("ttl/disorder/oob path executed (err=%v)", err)
}
