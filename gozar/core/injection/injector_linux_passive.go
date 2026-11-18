//go:build linux

package injection

import (
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"gozar/core/connection"
	"gozar/core/packet"
)

const ethernetHeaderLen = 14

type passiveFakeTcpInjector struct {
	fd      int
	ifindex int

	// cooked: AF_PACKET SOCK_DGRAM tap (no link header, any link type) and
	// injection through a raw IP socket (rawFd) bound to the device.
	cooked bool
	rawFd  int

	linkHdr   []byte
	linkHdrMu sync.RWMutex

	Connections sync.Map
	byLocalPort sync.Map
	localIP     string
	connectIP   string
	connectPort uint16
	nicMTU      int

	ctx    context.Context
	cancel context.CancelFunc

	injectorReady chan struct{}
	closeOnce     sync.Once
	sendMu        sync.Mutex
}

func newPassiveFakeTcpInjector(p Params, connectIPv4s []string, connectPort uint16, cooked bool) (TCPInjector, error) {
	if len(connectIPv4s) == 0 {
		return nil, fmt.Errorf("no upstream IPv4 addresses")
	}
	interfaceIP := p.InterfaceIP
	var iface *net.Interface
	var err error
	if p.InterfaceName != "" {
		iface, err = net.InterfaceByName(p.InterfaceName)
	} else {
		iface, err = interfaceByIPv4(interfaceIP)
	}
	if err != nil {
		return nil, err
	}

	sockType, proto := unix.SOCK_RAW, int(htons(unix.ETH_P_ALL))
	if cooked {
		sockType, proto = unix.SOCK_DGRAM, int(htons(unix.ETH_P_IP))
	}
	fd, err := unix.Socket(unix.AF_PACKET, sockType, proto)
	if err != nil {
		return nil, fmt.Errorf("AF_PACKET socket: %w", err)
	}
	rawFd := -1
	cleanup := func(e error) (TCPInjector, error) {
		_ = unix.Close(fd)
		if rawFd >= 0 {
			_ = unix.Close(rawFd)
		}
		return nil, e
	}

	if err := unix.Bind(fd, &unix.SockaddrLinklayer{
		Protocol: uint16(proto),
		Ifindex:  iface.Index,
	}); err != nil {
		return cleanup(fmt.Errorf("bind AF_PACKET %s: %w", iface.Name, err))
	}
	if !cooked && len(iface.HardwareAddr) != 6 {
		return cleanup(fmt.Errorf("passive injector supports Ethernet-like interfaces only; %s has hardware address length %d (use the raw injector)", iface.Name, len(iface.HardwareAddr)))
	}

	if cooked {
		rawFd, err = openRawSendSocket(iface.Name, p.FwMark)
		if err != nil {
			return cleanup(err)
		}
	}

	tv := unix.NsecToTimeval((100 * time.Millisecond).Nanoseconds())
	_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv)
	if err := attachPassiveHostFilter(fd, connectIPv4s[0], cooked); err != nil {
		log.Printf("passive: filter not installed (%v); filtering in userspace", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	mtu := p.MTU
	if mtu <= 0 {
		mtu = iface.MTU
	}
	if mtu <= 0 {
		mtu = nicMTUForLocalIPv4(interfaceIP)
	}
	if mtu == 0 {
		log.Printf("injector: fallback MSS %d", fallbackTCPPayloadMax)
	}
	kind := "passive"
	if cooked {
		kind = "raw"
	}
	log.Printf("%s: AF_PACKET iface=%s mtu=%d", kind, iface.Name, mtu)

	return &passiveFakeTcpInjector{
		fd:            fd,
		ifindex:       iface.Index,
		cooked:        cooked,
		rawFd:         rawFd,
		localIP:       interfaceIP,
		connectIP:     connectIPv4s[0],
		connectPort:   connectPort,
		nicMTU:        mtu,
		ctx:           ctx,
		cancel:        cancel,
		injectorReady: make(chan struct{}),
	}, nil
}

// openRawSendSocket opens an IPv4 raw socket (IP_HDRINCL) optionally bound to a
// device and marked, used to inject crafted TCP segments.
func openRawSendSocket(device string, mark int) (int, error) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_RAW)
	if err != nil {
		return -1, fmt.Errorf("raw socket: %w", err)
	}
	fail := func(e error) (int, error) {
		_ = unix.Close(fd)
		return -1, e
	}
	if err := unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_HDRINCL, 1); err != nil {
		return fail(fmt.Errorf("IP_HDRINCL: %w", err))
	}
	if err := unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_MTU_DISCOVER, unix.IP_PMTUDISC_DONT); err != nil {
		return fail(fmt.Errorf("IP_MTU_DISCOVER: %w", err))
	}
	if device != "" {
		if err := unix.SetsockoptString(fd, unix.SOL_SOCKET, unix.SO_BINDTODEVICE, device); err != nil {
			return fail(fmt.Errorf("SO_BINDTODEVICE %s: %w", device, err))
		}
	}
	if mark != 0 {
		if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_MARK, mark|injectorOwnMarkBit); err != nil {
			return fail(fmt.Errorf("SO_MARK: %w", err))
		}
	}
	return fd, nil
}

func htons(v uint16) uint16 {
	return v<<8 | v>>8
}

func interfaceByIPv4(localIPv4 string) (*net.Interface, error) {
	ip := net.ParseIP(localIPv4).To4()
	if ip == nil {
		return nil, fmt.Errorf("local address is not IPv4: %q", localIPv4)
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	for i := range ifaces {
		addrs, err := ifaces[i].Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			var cand net.IP
			switch v := a.(type) {
			case *net.IPNet:
				cand = v.IP
			case *net.IPAddr:
				cand = v.IP
			}
			if cand.To4() != nil && cand.Equal(ip) {
				return &ifaces[i], nil
			}
		}
	}
	return nil, fmt.Errorf("no interface found for local IPv4 %q", localIPv4)
}

func (f *passiveFakeTcpInjector) Start() error {
	close(f.injectorReady)
	buf := make([]byte, 65536)
	for {
		if f.ctx.Err() != nil {
			return nil
		}
		n, _, err := unix.Recvfrom(f.fd, buf, 0)
		if err != nil {
			if err == unix.EINTR || err == unix.EAGAIN || err == unix.EWOULDBLOCK {
				continue
			}
			if f.ctx.Err() != nil {
				return nil
			}
			log.Printf("passive recv: %v", err)
			continue
		}
		if n <= 0 {
			continue
		}
		f.onFrame(buf[:n])
	}
}

func (f *passiveFakeTcpInjector) WaitInjectorReady() error {
	<-f.injectorReady
	return nil
}

func (f *passiveFakeTcpInjector) Close() {
	f.closeOnce.Do(func() {
		f.cancel()
		if f.fd >= 0 {
			_ = unix.Close(f.fd)
			f.fd = -1
		}
		if f.rawFd >= 0 {
			_ = unix.Close(f.rawFd)
			f.rawFd = -1
		}
	})
}

func (f *passiveFakeTcpInjector) RegisterConn(conn *FakeInjectiveConnection) {
	f.Connections.Store(conn.ID, conn)
	f.byLocalPort.Store(conn.SrcPort, conn)
}

func (f *passiveFakeTcpInjector) UnregisterConn(conn *FakeInjectiveConnection) {
	f.Connections.Delete(conn.ID)
	f.byLocalPort.Delete(conn.SrcPort)
}

func (f *passiveFakeTcpInjector) onFrame(frame []byte) {
	var raw []byte
	if f.cooked {
		if len(frame) < 40 {
			return
		}
		raw = frame
	} else {
		if len(frame) < ethernetHeaderLen+40 {
			return
		}
		if frame[12] != 0x08 || frame[13] != 0x00 {
			return
		}
		raw = frame[ethernetHeaderLen:]
	}
	if len(raw) < 40 || raw[9] != 6 {
		return
	}
	if packet.IPVersion(raw) != 4 {
		return
	}

	src := packet.IPv4SrcAddr(raw)
	dst := packet.IPv4DstAddr(raw)
	if src == nil || dst == nil {
		return
	}
	srcIP := src.String()
	dstIP := dst.String()
	srcPort := packet.TCPSrcPort(raw)
	dstPort := packet.TCPDstPort(raw)

	conn, outbound, ok := f.lookupConnQuad(srcIP, srcPort, dstIP, dstPort)
	if !ok {
		return
	}
	if outbound && !f.cooked {
		f.captureLinkHeader(frame)
	}

	conn.Mu.Lock()
	defer conn.Mu.Unlock()
	if !conn.Monitor {
		return
	}
	if outbound {
		f.onOutboundPacket(raw, conn)
	} else {
		f.onInboundPacket(raw, conn)
	}
}

func attachPassiveHostFilter(fd int, connectIP string, cooked bool) error {
	ip := net.ParseIP(connectIP).To4()
	if ip == nil {
		return fmt.Errorf("connect IP is not IPv4: %q", connectIP)
	}
	host := binary.BigEndian.Uint32(ip)
	const accept = 0x40000
	if cooked {
		// Packets start at the IPv4 header (SOCK_DGRAM, ETH_P_IP).
		filter := []syscall.SockFilter{
			{Code: 0x30, K: 0},           // ldb [0] version/IHL
			{Code: 0x54, K: 0xf0},        // and #0xf0
			{Code: 0x15, Jf: 7, K: 0x40}, // IPv4
			{Code: 0x30, K: 9},           // ldb [9] protocol
			{Code: 0x15, Jf: 5, K: 6},    // TCP
			{Code: 0x20, K: 12},          // ldw [12] src
			{Code: 0x15, Jt: 2, K: host}, // src == host
			{Code: 0x20, K: 16},          // ldw [16] dst
			{Code: 0x15, Jf: 1, K: host}, // dst == host
			{Code: 0x06, K: accept},
			{Code: 0x06, K: 0},
		}
		return syscall.AttachLsf(fd, filter)
	}
	filter := []syscall.SockFilter{
		{Code: 0x28, K: 12},            // ldh [12] EtherType
		{Code: 0x15, Jf: 7, K: 0x0800}, // IPv4
		{Code: 0x30, K: 23},            // ldb [23] protocol
		{Code: 0x15, Jf: 5, K: 6},      // TCP
		{Code: 0x20, K: 26},            // ldw [26] src IPv4
		{Code: 0x15, Jt: 2, K: host},   // src == host -> accept
		{Code: 0x20, K: 30},            // ldw [30] dst IPv4
		{Code: 0x15, Jf: 1, K: host},   // dst == host -> accept
		{Code: 0x06, K: accept},        // accept
		{Code: 0x06, K: 0},             // drop
	}
	return syscall.AttachLsf(fd, filter)
}

func (f *passiveFakeTcpInjector) captureLinkHeader(frame []byte) {
	f.linkHdrMu.RLock()
	have := f.linkHdr != nil
	f.linkHdrMu.RUnlock()
	if have {
		return
	}
	hdr := make([]byte, ethernetHeaderLen)
	copy(hdr, frame[:ethernetHeaderLen])
	f.linkHdrMu.Lock()
	if f.linkHdr == nil {
		f.linkHdr = hdr
	}
	f.linkHdrMu.Unlock()
}

func (f *passiveFakeTcpInjector) lookupConnQuad(srcIP string, srcPort uint16, dstIP string, dstPort uint16) (conn *FakeInjectiveConnection, outbound bool, ok bool) {
	idOut := connection.ConnID{SrcIP: srcIP, SrcPort: srcPort, DstIP: dstIP, DstPort: dstPort}
	if v, ok := f.Connections.Load(idOut); ok {
		return v.(*FakeInjectiveConnection), true, true
	}
	idIn := connection.ConnID{SrcIP: dstIP, SrcPort: dstPort, DstIP: srcIP, DstPort: srcPort}
	if v, ok := f.Connections.Load(idIn); ok {
		return v.(*FakeInjectiveConnection), false, true
	}
	if v, ok := f.byLocalPort.Load(srcPort); ok {
		c := v.(*FakeInjectiveConnection)
		if ipv4Equal(dstIP, c.DstIP) && dstPort == c.DstPort {
			return c, true, true
		}
	}
	if v, ok := f.byLocalPort.Load(dstPort); ok {
		c := v.(*FakeInjectiveConnection)
		if ipv4Equal(srcIP, c.DstIP) && srcPort == c.DstPort {
			return c, false, true
		}
	}
	return nil, false, false
}

func (f *passiveFakeTcpInjector) onUnexpectedPacket(raw []byte, conn *FakeInjectiveConnection, info string) {
	log.Printf("injector: %s %s", info, packet.PacketSummary(raw))
	if conn.Sock != nil {
		conn.Sock.Close()
	}
	if conn.PeerSock != nil {
		conn.PeerSock.Close()
	}
	conn.Monitor = false
	select {
	case conn.T2aChan <- "unexpected_close":
	default:
	}
}

func (f *passiveFakeTcpInjector) onInboundPacket(raw []byte, conn *FakeInjectiveConnection) {
	if conn.SynSeq == -1 {
		f.onUnexpectedPacket(raw, conn, "unexpected inbound packet, no syn sent!")
		return
	}

	flags := packet.GetTCPFlags(raw)
	payloadLen := packet.TCPPayloadLen(raw)
	seqNum := packet.TCPSeqNum(raw)
	ackNum := packet.TCPAckNum(raw)

	if flags.ACK && flags.SYN && !flags.RST && !flags.FIN && payloadLen == 0 {
		if conn.SynAckSeq != -1 && conn.SynAckSeq != int64(seqNum) {
			f.onUnexpectedPacket(raw, conn, fmt.Sprintf("unexpected inbound syn-ack, seq change! %d %d", seqNum, conn.SynAckSeq))
			return
		}
		expectedAck := uint32((uint32(conn.SynSeq) + 1) & 0xffffffff)
		if ackNum != expectedAck {
			f.onUnexpectedPacket(raw, conn, fmt.Sprintf("unexpected inbound syn-ack, ack not matched! %d %d", ackNum, conn.SynSeq))
			return
		}
		conn.SynAckSeq = int64(seqNum)
		return
	}

	if flags.ACK && !flags.SYN && !flags.RST && conn.FakeInjectInProgress.Load() && !conn.FakeSent.Load() {
		conn.PostFakeAckObserved.Store(true)
		return
	}

	if flags.ACK && !flags.SYN && !flags.RST && conn.FakeSent.Load() && conn.SynAckSeq != -1 {
		strict := postFakeInboundStrictOK(seqNum, ackNum, conn)
		if !strict && !postFakeInboundPermissiveOK(flags) {
			f.onUnexpectedPacket(raw, conn, fmt.Sprintf("unexpected inbound after fake seq=%d ack=%d synAck=%d syn=%d strict=%v", seqNum, ackNum, conn.SynAckSeq, conn.SynSeq, strict))
			return
		}
		conn.Monitor = false
		select {
		case conn.T2aChan <- "fake_data_ack_recv":
		default:
		}
		return
	}

	f.onUnexpectedPacket(raw, conn, "unexpected inbound packet")
}

func (f *passiveFakeTcpInjector) onOutboundPacket(raw []byte, conn *FakeInjectiveConnection) {
	if conn.FakeSent.Load() || conn.FakeInjectInProgress.Load() {
		return
	}

	flags := packet.GetTCPFlags(raw)
	payloadLen := packet.TCPPayloadLen(raw)
	seqNum := packet.TCPSeqNum(raw)
	ackNum := packet.TCPAckNum(raw)

	if flags.SYN && !flags.ACK && !flags.RST && !flags.FIN && payloadLen == 0 {
		if ackNum != 0 {
			f.onUnexpectedPacket(raw, conn, "unexpected outbound syn, ack_num is not zero!")
			return
		}
		if conn.SynSeq != -1 && conn.SynSeq != int64(seqNum) {
			f.onUnexpectedPacket(raw, conn, fmt.Sprintf("unexpected outbound syn, seq not matched! %d %d", seqNum, conn.SynSeq))
			return
		}
		conn.SynSeq = int64(seqNum)
		return
	}

	if flags.ACK && !flags.SYN && !flags.RST && !flags.FIN && payloadLen == 0 {
		expectedSeq := uint32((uint32(conn.SynSeq) + 1) & 0xffffffff)
		if conn.SynSeq == -1 || expectedSeq != seqNum {
			f.onUnexpectedPacket(raw, conn, fmt.Sprintf("unexpected outbound ack, seq not matched! %d %d", seqNum, conn.SynSeq))
			return
		}
		expectedAck := uint32((uint32(conn.SynAckSeq) + 1) & 0xffffffff)
		if conn.SynAckSeq == -1 || ackNum != expectedAck {
			f.onUnexpectedPacket(raw, conn, fmt.Sprintf("unexpected outbound ack, ack not matched! %d %d", ackNum, conn.SynAckSeq))
			return
		}
		rawCopy := make([]byte, len(raw))
		copy(rawCopy, raw)
		conn.FakeInjectInProgress.Store(true)
		go f.runFakeInjection(rawCopy, conn)
		return
	}

	f.onUnexpectedPacket(raw, conn, "unexpected outbound packet")
}

func (f *passiveFakeTcpInjector) runFakeInjection(rawCopy []byte, conn *FakeInjectiveConnection) {
	defer conn.FakeInjectInProgress.Store(false)

	time.Sleep(1 * time.Millisecond)

	conn.Mu.Lock()
	if !conn.Monitor {
		conn.Mu.Unlock()
		return
	}
	if conn.BypassMethod != "wrong_seq" {
		log.Printf("not implemented bypass method: %s", conn.BypassMethod)
		conn.AbortUnexpectedCloseLocked()
		conn.Mu.Unlock()
		return
	}
	conn.Mu.Unlock()

	repeat := conn.FakeRepeat
	if repeat < 1 {
		repeat = 1
	}
	total := len(conn.FakeData)
	mss := segmentMSS(f.nicMTU, rawCopy)
	segPerInject := (total + mss - 1) / mss
	if segPerInject < 1 {
		segPerInject = 1
	}
	for i := 0; i < repeat; i++ {
		if !conn.IsMonitoring() {
			return
		}
		if err := injectWrongSeqClientHello(f.nicMTU, rawCopy, conn, conn.IsMonitoring, f.sendRawPacket); err != nil {
			if err == errInjectionCanceled {
				return
			}
			log.Printf("inject fake ClientHello: %v", err)
			conn.Mu.Lock()
			conn.AbortUnexpectedCloseLocked()
			conn.Mu.Unlock()
			return
		}
		log.Printf("injector: fake ClientHello sent (%d/%d, %d bytes, %d segment(s))", i+1, repeat, total, segPerInject)
		if i+1 < repeat && conn.FakeDelay > 0 && !sleepWhileContinue(conn.FakeDelay, conn.IsMonitoring) {
			return
		}
	}
	conn.FakeSent.Store(true)
	if conn.PostFakeAckObserved.Load() {
		conn.Mu.Lock()
		if conn.Monitor {
			conn.Monitor = false
			select {
			case conn.T2aChan <- "fake_data_ack_recv":
			default:
			}
		}
		conn.Mu.Unlock()
	}
}

func (f *passiveFakeTcpInjector) sendRawPacket(rawIP []byte) error {
	if f.cooked {
		dst := packet.IPv4DstAddr(rawIP)
		if dst == nil || dst.To4() == nil {
			return fmt.Errorf("raw packet has no IPv4 destination")
		}
		sa := &unix.SockaddrInet4{}
		copy(sa.Addr[:], dst.To4())
		f.sendMu.Lock()
		defer f.sendMu.Unlock()
		return unix.Sendto(f.rawFd, rawIP, 0, sa)
	}
	f.linkHdrMu.RLock()
	hdr := f.linkHdr
	f.linkHdrMu.RUnlock()
	if len(hdr) < ethernetHeaderLen {
		return fmt.Errorf("no observed Ethernet header yet for injection")
	}
	frame := make([]byte, ethernetHeaderLen+len(rawIP))
	copy(frame, hdr)
	copy(frame[ethernetHeaderLen:], rawIP)

	var addr [8]byte
	copy(addr[:], hdr[:6])
	f.sendMu.Lock()
	defer f.sendMu.Unlock()
	return unix.Sendto(f.fd, frame, 0, &unix.SockaddrLinklayer{
		Protocol: htons(unix.ETH_P_IP),
		Ifindex:  f.ifindex,
		Halen:    6,
		Addr:     addr,
	})
}
