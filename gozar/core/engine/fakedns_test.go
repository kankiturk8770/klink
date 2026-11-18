package engine

import (
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

// Verifies the FakeDNS path: with the engine running, a DNS A-query sent to the
// local DNS inbound must be answered with a fake IP from 198.18.0.0/15 (no real
// resolver is contacted). This is what makes name resolution work on a censored
// network — the earlier version let DNS leak out un-tunnelled and fail.
func TestFakeDNSAnswersFakeIP(t *testing.T) {
	if testing.Short() {
		t.Skip("short")
	}
	// A dummy VLESS profile with a literal IP (no resolve needed, never dialed).
	// FakeDNS answers the query locally, so the proxy outbound is irrelevant.
	uuid := "b831381d-6324-4d53-ad4f-8cda48b30811"
	link := fmt.Sprintf("vless://%s@198.51.100.7:443?encryption=none&security=none&type=tcp#srv", uuid)

	e := New()
	s := DefaultSettings()
	s.Links = []string{link}
	s.Spoof.Enabled = false // isolate DNS; spoofing is irrelevant here
	if err := e.Start(s, nil); err != nil {
		t.Fatalf("engine start: %v\n%s", err, e.Logs())
	}
	defer e.Stop()

	if e.DNSPort() == 0 {
		t.Fatal("DNSPort is 0 while running")
	}

	// Build a minimal DNS query for example.com A.
	query := buildDNSQuery("example.com")
	conn, err := net.Dial("udp4", fmt.Sprintf("127.0.0.1:%d", e.DNSPort()))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write(query); err != nil {
		t.Fatal(err)
	}
	resp := make([]byte, 512)
	n, err := conn.Read(resp)
	if err != nil {
		t.Fatalf("no DNS answer from FakeDNS inbound: %v\n%s", err, e.Logs())
	}
	ips := parseDNSAnswers(resp[:n])
	if len(ips) == 0 {
		t.Fatalf("FakeDNS returned no A records\n%s", e.Logs())
	}
	_, fakeNet, _ := net.ParseCIDR("198.18.0.0/15")
	for _, ip := range ips {
		if !fakeNet.Contains(ip) {
			t.Fatalf("expected fake IP in 198.18.0.0/15, got %s", ip)
		}
	}
	t.Logf("FakeDNS ok: example.com -> %v", ips)
}

func buildDNSQuery(name string) []byte {
	// header: id=0x1234, flags=0x0100 (RD), qd=1
	msg := []byte{0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	for _, label := range splitDomain(name) {
		msg = append(msg, byte(len(label)))
		msg = append(msg, label...)
	}
	msg = append(msg, 0x00)       // root
	msg = append(msg, 0x00, 0x01) // QTYPE A
	msg = append(msg, 0x00, 0x01) // QCLASS IN
	return msg
}

func splitDomain(name string) [][]byte {
	var out [][]byte
	cur := []byte{}
	for i := 0; i < len(name); i++ {
		if name[i] == '.' {
			out = append(out, cur)
			cur = []byte{}
			continue
		}
		cur = append(cur, name[i])
	}
	if len(cur) > 0 {
		out = append(out, cur)
	}
	return out
}

// parseDNSAnswers extracts A-record IPs from a DNS response (minimal parser).
func parseDNSAnswers(msg []byte) []net.IP {
	if len(msg) < 12 {
		return nil
	}
	qd := int(msg[4])<<8 | int(msg[5])
	an := int(msg[6])<<8 | int(msg[7])
	pos := 12
	skipName := func() {
		for pos < len(msg) {
			l := int(msg[pos])
			if l == 0 {
				pos++
				return
			}
			if l&0xc0 == 0xc0 { // compression pointer
				pos += 2
				return
			}
			pos += 1 + l
		}
	}
	for i := 0; i < qd && pos < len(msg); i++ {
		skipName()
		pos += 4 // qtype+qclass
	}
	var ips []net.IP
	for i := 0; i < an && pos+10 <= len(msg); i++ {
		skipName()
		if pos+10 > len(msg) {
			break
		}
		typ := int(msg[pos])<<8 | int(msg[pos+1])
		rdlen := int(msg[pos+8])<<8 | int(msg[pos+9])
		pos += 10
		if pos+rdlen > len(msg) {
			break
		}
		if typ == 1 && rdlen == 4 {
			ips = append(ips, net.IPv4(msg[pos], msg[pos+1], msg[pos+2], msg[pos+3]))
		}
		pos += rdlen
	}
	return ips
}

// The app resolves the server via Android's system DNS and passes ServerIP; the
// engine must then start without doing any DNS itself (the old code failed here
// on Android with "lookup <host> on [::1]:53").
func TestServerIPOverrideSkipsResolve(t *testing.T) {
	uuid := "b831381d-6324-4d53-ad4f-8cda48b30811"
	link := fmt.Sprintf("vless://%s@unresolvable-host.gozar.invalid:8443?encryption=none&security=tls&sni=unresolvable-host.gozar.invalid&type=xhttp&path=%%2Fx#t", uuid)
	e := New()
	s := DefaultSettings()
	s.Links = []string{link}
	s.ServerIP = "198.51.100.7"
	if err := e.Start(s, nil); err != nil {
		t.Fatalf("start with ServerIP failed: %v\n%s", err, e.Logs())
	}
	defer e.Stop()
	if !strings.Contains(e.Logs(), "198.51.100.7") {
		t.Fatalf("expected ServerIP in log:\n%s", e.Logs())
	}
}

// A start failure must leave an ERROR line in the log the UI shows.
func TestStartFailureIsLogged(t *testing.T) {
	e := New()
	s := DefaultSettings()
	s.Links = []string{"vless://not-a-valid-link"}
	if err := e.Start(s, nil); err == nil {
		t.Fatal("expected failure")
	}
	if !strings.Contains(e.Logs(), "ERROR") {
		t.Fatalf("failure not logged:\n%s", e.Logs())
	}
}
