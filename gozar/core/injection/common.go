package injection

import (
	"net"
	"sync/atomic"
	"time"

	"gozar/core/connection"
)

type ConnID = connection.ConnID

type TCPInjector interface {
	Start() error
	WaitInjectorReady() error
	Close()
	RegisterConn(conn *FakeInjectiveConnection)
	UnregisterConn(conn *FakeInjectiveConnection)
}

type InjectorMode string

const (
	// InjectorModeActive: nfqueue verdicts + raw IP socket (needs NFQUEUE kernel support).
	InjectorModeActive InjectorMode = "active"
	// InjectorModePassive: AF_PACKET tap + link-layer writes (Ethernet-like interfaces only).
	InjectorModePassive InjectorMode = "passive"
	// InjectorModeRaw: AF_PACKET cooked tap (any link type, incl. Android rmnet/ccmni) + raw IP socket writes.
	InjectorModeRaw InjectorMode = "raw"
)

// Params describes where the injector observes and sends packets.
// InterfaceName and FwMark are optional; on Android (root helper) they are
// required so injected packets leave through the physical network instead of
// the VPN (TUN) interface.
type Params struct {
	InterfaceIP   string
	InterfaceName string
	// FwMark is applied with SO_MARK to the raw sending socket. On Android it is
	// netId|0x30000 (explicitly selected + protected from VPN).
	FwMark int
	// MTU overrides interface MTU detection when > 0.
	MTU int
}

// injectorOwnMarkBit tags packets we inject ourselves so nfqueue rules can skip them
// without disturbing Android's netId bits (low 21 bits) in the same mark.
const injectorOwnMarkBit = 0x10000000

type FakeInjectiveConnection struct {
	*connection.MonitorConnection

	FakeData      []byte
	FakeSent      atomic.Bool
	T2aChan       chan string
	BypassMethod  string
	PeerSock      net.Conn
	FakeRepeat    int
	FakeDelay     time.Duration
	FragmentDelay time.Duration

	// FakeInjectInProgress is set while wrong-seq fake ClientHello is being sent (async off the nfqueue/WinDivert recv path).
	FakeInjectInProgress atomic.Bool
	PostFakeAckObserved  atomic.Bool
}

func NewFakeInjectiveConnection(
	sock net.Conn, srcIP, dstIP string, srcPort, dstPort uint16,
	fakeData []byte, bypassMethod string, peerSock net.Conn,
	fakeRepeat int,
	fakeDelay, fragmentDelay time.Duration,
) *FakeInjectiveConnection {
	if fakeRepeat < 1 {
		fakeRepeat = 1
	}
	return &FakeInjectiveConnection{
		MonitorConnection: connection.NewMonitorConnection(sock, srcIP, dstIP, srcPort, dstPort),
		FakeData:          fakeData,
		// Buffer 2 so a rare second signal (e.g. unexpected + ack) is not dropped before the proxy reads.
		T2aChan:       make(chan string, 2),
		BypassMethod:  bypassMethod,
		PeerSock:      peerSock,
		FakeRepeat:    fakeRepeat,
		FakeDelay:     fakeDelay,
		FragmentDelay: fragmentDelay,
	}
}

func (conn *FakeInjectiveConnection) AbortUnexpectedCloseLocked() {
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

func (conn *FakeInjectiveConnection) IsMonitoring() bool {
	conn.Mu.Lock()
	defer conn.Mu.Unlock()
	return conn.Monitor
}
