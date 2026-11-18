//go:build linux

package tun

import (
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"syscall"

	"golang.org/x/net/proxy"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	gudp "gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

// socksDialer builds a SOCKS5 dialer whose own TCP socket is protected from the
// VPN (so it reaches Xray's loopback inbound rather than looping into the TUN).
func (t *Tunnel) baseDialer() *net.Dialer {
	d := &net.Dialer{Timeout: 10 * time.Second}
	if t.protect != nil {
		d.Control = func(_, _ string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) { t.protect(fd) })
		}
	}
	return d
}

func (t *Tunnel) socksDialer() (proxy.Dialer, error) {
	// 127.0.0.1 never routes through the TUN, so no protect is needed here;
	// keep the base dialer for consistency and timeouts.
	return proxy.SOCKS5("tcp", t.socks, nil, &net.Dialer{Timeout: 10 * time.Second})
}

func (t *Tunnel) handleTCP(r *tcp.ForwarderRequest) {
	id := r.ID()
	dst := net.JoinHostPort(addrString(id.LocalAddress), fmt.Sprintf("%d", id.LocalPort))

	dialer, err := t.socksDialer()
	if err != nil {
		r.Complete(true)
		return
	}
	upstream, err := dialer.Dial("tcp", dst)
	if err != nil {
		r.Complete(true) // send RST
		return
	}

	var wq waiter.Queue
	gep, tcpErr := r.CreateEndpoint(&wq)
	if tcpErr != nil {
		upstream.Close()
		r.Complete(true)
		return
	}
	r.Complete(false)
	local := gonet.NewTCPConn(&wq, gep)
	go relayTCP(local, upstream)
}

func relayTCP(a, b net.Conn) {
	var once sync.Once
	closeBoth := func() { a.Close(); b.Close() }
	var wg sync.WaitGroup
	wg.Add(2)
	cp := func(dst, src net.Conn) {
		defer wg.Done()
		buf := make([]byte, 32*1024)
		io.CopyBuffer(dst, src, buf)
		once.Do(closeBoth) // first EOF tears down both directions
	}
	go cp(a, b)
	go cp(b, a)
	wg.Wait()
	closeBoth()
}

func (t *Tunnel) handleUDP(r *gudp.ForwarderRequest) bool {
	id := r.ID()
	dst := net.JoinHostPort(addrString(id.LocalAddress), fmt.Sprintf("%d", id.LocalPort))

	var wq waiter.Queue
	gep, uErr := r.CreateEndpoint(&wq)
	if uErr != nil {
		return true
	}
	local := gonet.NewUDPConn(&wq, gep)

	// DNS (:53) is redirected to Xray's FakeDNS inbound over loopback so name
	// resolution happens through the tunnel (critical on a censored network
	// where the real resolver is poisoned). Loopback needs no VPN protection.
	if id.LocalPort == 53 && t.dnsPort > 0 {
		raddr, err := net.ResolveUDPAddr("udp4", fmt.Sprintf("127.0.0.1:%d", t.dnsPort))
		if err != nil {
			local.Close()
			return true
		}
		upstream, err := net.DialUDP("udp4", nil, raddr)
		if err != nil {
			local.Close()
			return true
		}
		go relayUDP(local, upstream)
		return true
	}

	// Other UDP (QUIC, etc.): a direct protected socket to the destination so
	// UDP apps keep working when the VPN is the default route.
	raddr, err := net.ResolveUDPAddr("udp", dst)
	if err != nil {
		local.Close()
		return true
	}
	upstream, err := t.dialProtectedUDP(raddr)
	if err != nil {
		local.Close()
		return true
	}
	go relayUDP(local, upstream)
	return true
}

func (t *Tunnel) dialProtectedUDP(raddr *net.UDPAddr) (*net.UDPConn, error) {
	lc := net.ListenConfig{}
	if t.protect != nil {
		lc.Control = func(_, _ string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) { t.protect(fd) })
		}
	}
	pc, err := lc.ListenPacket(contextTODO(), "udp4", ":0")
	if err != nil {
		return nil, err
	}
	uc := pc.(*net.UDPConn)
	laddr := uc.LocalAddr().(*net.UDPAddr)
	uc.Close()
	// Re-dial from the same protected local port, now connected to raddr.
	return net.DialUDP("udp4", laddr, raddr)
}

func relayUDP(local, upstream net.Conn) {
	var once sync.Once
	closeBoth := func() { local.Close(); upstream.Close() }
	go func() {
		buf := make([]byte, 64*1024)
		for {
			upstream.SetReadDeadline(time.Now().Add(60 * time.Second))
			n, err := upstream.Read(buf)
			if n > 0 {
				local.Write(buf[:n])
			}
			if err != nil {
				once.Do(closeBoth)
				return
			}
		}
	}()
	buf := make([]byte, 64*1024)
	for {
		local.SetReadDeadline(time.Now().Add(60 * time.Second))
		n, err := local.Read(buf)
		if n > 0 {
			upstream.Write(buf[:n])
		}
		if err != nil {
			once.Do(closeBoth)
			return
		}
	}
}

func addrString(a tcpip.Address) string {
	return net.IP(a.AsSlice()).String()
}

// avoid importing context in two files; a tiny helper.
func contextTODO() ctx { return ctx{} }

type ctx struct{}

func (ctx) Deadline() (time.Time, bool) { return time.Time{}, false }
func (ctx) Done() <-chan struct{}       { return nil }
func (ctx) Err() error                  { return nil }
func (ctx) Value(any) any               { return nil }

var _ = unix.Dup
