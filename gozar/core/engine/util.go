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

// fallbackDNSServers are queried directly when the platform resolver fails.
// Android has no /etc/resolv.conf, so Go's pure resolver would otherwise fall
// back to 127.0.0.1:53 / [::1]:53 and fail ("lookup host on [::1]:53: ...").
var fallbackDNSServers = []string{"1.1.1.1", "8.8.8.8", "9.9.9.9", "208.67.222.222", "1.0.0.1", "8.8.4.4"}

// resolveIPv4 resolves host to a single IPv4 address. If host is already an
// IPv4 literal it is returned as-is.
//
// Order: (1) the platform resolver (cgo getaddrinfo on Android → netd, which
// uses the phone's real network DNS); (2) explicit public DNS servers, over UDP
// then TCP, with every socket passed through protect (VpnService.protect) so the
// query never loops into our own TUN. extraDNS (e.g. the user's DNS setting) is
// tried first in step 2.
func resolveIPv4(ctx context.Context, host string, protect func(fd uintptr), extraDNS ...string) (string, error) {
	host = strings.Trim(host, "[]")
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			return v4.String(), nil
		}
		return "", fmt.Errorf("only IPv4 upstreams are supported, got %q", host)
	}

	var errs []string

	// (1) Platform resolver.
	{
		cctx, cancel := context.WithTimeout(ctx, 6*time.Second)
		ips, err := net.DefaultResolver.LookupIP(cctx, "ip4", host)
		cancel()
		if ip := firstV4(ips); err == nil && ip != "" {
			return ip, nil
		}
		if err != nil {
			errs = append(errs, "system: "+err.Error())
		}
	}

	// (2) Explicit servers, ignoring whatever address Go derived from resolv.conf.
	servers := append([]string{}, extraDNS...)
	servers = append(servers, fallbackDNSServers...)
	seen := map[string]bool{}
	for _, srv := range servers {
		srv = strings.TrimSpace(srv)
		if srv == "" || seen[srv] || net.ParseIP(srv) == nil {
			continue
		}
		seen[srv] = true
		target := net.JoinHostPort(srv, "53")
		r := &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
				d := net.Dialer{Timeout: 3 * time.Second}
				if protect != nil {
					d.Control = func(_, _ string, c syscall.RawConn) error {
						return c.Control(func(fd uintptr) { protect(fd) })
					}
				}
				return d.DialContext(ctx, network, target)
			},
		}
		cctx, cancel := context.WithTimeout(ctx, 4*time.Second)
		ips, err := r.LookupIP(cctx, "ip4", host)
		cancel()
		if ip := firstV4(ips); err == nil && ip != "" {
			return ip, nil
		}
		if err != nil {
			errs = append(errs, srv+": "+err.Error())
		}
	}
	return "", fmt.Errorf("could not resolve %q (%s)", host, strings.Join(errs, "; "))
}

func firstV4(ips []net.IP) string {
	for _, ip := range ips {
		if v4 := ip.To4(); v4 != nil {
			return v4.String()
		}
	}
	return ""
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

// ResolveServerIPv4 resolves a profile link's server host to an IPv4 literal.
// Exposed for the root-helper path (which needs a concrete IP). protect may be nil.
func ResolveServerIPv4(host string, protect func(fd uintptr)) (string, error) {
	return resolveIPv4(context.Background(), host, protect)
}

// DeriveFakeSNI is the exported decoy-SNI chooser used by the helper path.
func DeriveFakeSNI(realSNI, realHost string) string { return deriveFakeSNI(realSNI, realHost) }
