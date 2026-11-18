package engine

import (
	"context"
	"fmt"
	"net"
	"strings"
	"syscall"
	"time"
)

// freePort asks the kernel for an unused TCP port on loopback.
func freePort() (int, error) {
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

// resolveIPv4 resolves host to a single IPv4 address. If host is already an
// IPv4 literal it is returned as-is. protect (if set) is applied to the
// resolver's UDP socket so DNS does not loop through the VPN.
func resolveIPv4(ctx context.Context, host string, protect func(fd uintptr)) (string, error) {
	host = strings.Trim(host, "[]")
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			return v4.String(), nil
		}
		return "", fmt.Errorf("only IPv4 upstreams are supported, got %q", host)
	}
	r := &net.Resolver{}
	if protect != nil {
		r.PreferGo = true
		r.Dial = func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Control: func(_, _ string, c syscall.RawConn) error {
				return c.Control(func(fd uintptr) { protect(fd) })
			}}
			return d.DialContext(ctx, network, address)
		}
	}
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	ips, err := r.LookupIP(cctx, "ip4", host)
	if err != nil {
		return "", err
	}
	for _, ip := range ips {
		if v4 := ip.To4(); v4 != nil {
			return v4.String(), nil
		}
	}
	return "", fmt.Errorf("no IPv4 address for %q", host)
}

// deriveFakeSNI picks a decoy SNI. We reuse a benign, widely-allow-listed
// hostname rather than the real SNI so the censor sees an innocuous name.
func deriveFakeSNI(realSNI, realHost string) string {
	// A CDN hostname that is almost always reachable works well as a decoy.
	const defaultDecoy = "www.cloudflare.com"
	if realSNI != "" && !isIP(realSNI) {
		// Keep the apex of the real SNI's unrelated decoy; default is safer.
		return defaultDecoy
	}
	return defaultDecoy
}

func isIP(s string) bool { return net.ParseIP(s) != nil }
