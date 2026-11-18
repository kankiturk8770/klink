//go:build linux

// Package tun bridges an Android VpnService TUN file descriptor to the local
// SOCKS inbound, reusing the same gVisor networking stack Xray already vendors
// (no second userspace TCP/IP implementation, no version skew).
//
//	TUN fd ──▶ gVisor stack ──▶ TCP/UDP forwarders ──▶ SOCKS5 127.0.0.1:port ──▶ Xray
//
// gVisor terminates the client TCP/UDP flows and we relay their payloads over
// SOCKS to Xray, which applies the user's proxy protocol and the DPI bypass.
package tun

import (
	"fmt"
	"sync"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/link/fdbased"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

const nicID = 1

// Tunnel owns the gVisor stack and the dup'd TUN fd.
type Tunnel struct {
	stack   *stack.Stack
	fd      int
	logf    func() string
	socks   string
	dnsPort int
	protect func(fd uintptr)

	mu     sync.Mutex
	closed bool
}

// Start builds the stack on a dup of tunFd and starts forwarding to
// 127.0.0.1:socksPort. dnsPort, when > 0, is a loopback UDP port (Xray's
// FakeDNS inbound) that all UDP:53 traffic is redirected to so DNS resolves
// through the tunnel; 0 falls back to a direct protected UDP socket.
func Start(tunFd, mtu, socksPort, dnsPort int, protect func(fd uintptr), logs func() string) (*Tunnel, error) {
	if socksPort <= 0 {
		return nil, fmt.Errorf("invalid socks port %d", socksPort)
	}
	if mtu <= 0 {
		mtu = 1500
	}
	// Dup the fd so our Close is independent of the caller's ParcelFileDescriptor.
	dup, err := unix.Dup(tunFd)
	if err != nil {
		return nil, fmt.Errorf("dup tun fd: %w", err)
	}
	if err := unix.SetNonblock(dup, true); err != nil {
		unix.Close(dup)
		return nil, fmt.Errorf("set nonblock: %w", err)
	}

	ep, err := fdbased.New(&fdbased.Options{
		FDs: []int{dup},
		MTU: uint32(mtu),
		// Android TUN carries bare IP packets (no link header).
		EthernetHeader: false,
	})
	if err != nil {
		unix.Close(dup)
		return nil, fmt.Errorf("fdbased endpoint: %w", err)
	}

	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})
	if tcpErr := s.CreateNIC(nicID, ep); tcpErr != nil {
		unix.Close(dup)
		return nil, fmt.Errorf("create nic: %v", tcpErr)
	}
	// Accept packets for any address (we are the gateway for the TUN subnet).
	s.SetPromiscuousMode(nicID, true)
	s.SetSpoofing(nicID, true)
	s.SetRouteTable([]tcpip.Route{
		{Destination: header4(), NIC: nicID},
		{Destination: header6(), NIC: nicID},
	})
	// Tune the stack for throughput.
	sndBuf := tcpip.TCPSendBufferSizeRangeOption{Min: 4 << 10, Default: 256 << 10, Max: 2 << 20}
	s.SetTransportProtocolOption(tcp.ProtocolNumber, &sndBuf)
	rcvBuf := tcpip.TCPReceiveBufferSizeRangeOption{Min: 4 << 10, Default: 256 << 10, Max: 2 << 20}
	s.SetTransportProtocolOption(tcp.ProtocolNumber, &rcvBuf)
	sack := tcpip.TCPSACKEnabled(true)
	s.SetTransportProtocolOption(tcp.ProtocolNumber, &sack)

	t := &Tunnel{
		stack:   s,
		fd:      dup,
		logf:    logs,
		socks:   fmt.Sprintf("127.0.0.1:%d", socksPort),
		dnsPort: dnsPort,
		protect: protect,
	}

	tcpFwd := tcp.NewForwarder(s, 0, 2048, t.handleTCP)
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpFwd.HandlePacket)
	udpFwd := udp.NewForwarder(s, t.handleUDP)
	s.SetTransportProtocolHandler(udp.ProtocolNumber, udpFwd.HandlePacket)

	return t, nil
}

// Stop closes the stack and the dup'd fd.
func (t *Tunnel) Stop() {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return
	}
	t.closed = true
	t.mu.Unlock()
	if t.stack != nil {
		t.stack.Close()
	}
	if t.fd >= 0 {
		unix.Close(t.fd)
		t.fd = -1
	}
}

func header4() tcpip.Subnet {
	sn, _ := tcpip.NewSubnet(tcpip.AddrFrom4([4]byte{}), tcpip.MaskFromBytes(make([]byte, 4)))
	return sn
}

func header6() tcpip.Subnet {
	sn, _ := tcpip.NewSubnet(tcpip.AddrFrom16([16]byte{}), tcpip.MaskFromBytes(make([]byte, 16)))
	return sn
}
