// Package proxy is the SNI-spoofing TCP proxy core. It accepts local TCP
// connections (from Xray) and relays them to the real upstream after a DPI
// desynchronisation step:
//
//   - root (wrong-seq): a crafted fake ClientHello with an out-of-window
//     sequence number is injected right after the TCP handshake (raw sockets);
//   - non-root: a TTL-limited in-stream fake, ClientHello fragmentation,
//     TLS record splitting, disorder and OOB, all on the proxy's own socket.
//
// Forked from SNI-Spoofing-Go (GPL-3.0) and extended for Android.
package proxy

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"sync/atomic"
	"time"

	"gozar/core/config"
	"gozar/core/injection"
	"gozar/core/network"
	"gozar/core/packet"
)

const firstClientHelloTimeout = 10 * time.Second

const StartReadyTimeout = 15 * time.Second

// InjectorNone selects the non-root path (no packet injection).
const InjectorNone injection.InjectorMode = "none"

// Options controls one proxy run.
type Options struct {
	FakeRepeat     int
	FakeDelay      time.Duration
	EnableFragment bool
	FragmentDelay  time.Duration
	SNIChunk       int
	AckTimeout     time.Duration
	Quiet          bool
	Injector       injection.InjectorMode

	// Android / explicit network selection (root helper). Empty = autodetect.
	InterfaceName string
	LocalIP       string
	FwMark        int
	MTU           int

	// Non-root fake: TTL of the in-stream fake ClientHello; 0 disables it.
	FakeTTL int
	// FakeHold keeps the fake in place this long before swapping in real data.
	FakeHold time.Duration
	// TLSRecordSplit re-frames the real ClientHello into two TLS records cut inside the SNI.
	TLSRecordSplit bool
	// Disorder sends the first real fragment with TTL DisorderTTL so it is retransmitted later.
	Disorder    bool
	DisorderTTL int
	// OOB inserts one urgent byte after the first real fragment.
	OOB bool

	ConnectTimeout time.Duration

	// Control, if set, is applied to each upstream socket before connect. On
	// Android non-root this is VpnService.protect(fd) so the tunnelled app's
	// own upstream does not loop back into the TUN.
	Control func(fd uintptr)

	// Stats, if non-nil, receives connection and byte counters.
	Stats *Stats

	Logger *log.Logger
}

// Stats are live counters shared with the UI.
type Stats struct {
	Active   atomic.Int64
	Total    atomic.Int64
	Failed   atomic.Int64
	BytesUp  atomic.Int64
	BytesDn  atomic.Int64
	LastErr  atomic.Value // string
	FakeSent atomic.Int64
}

func (o *Options) logger() *log.Logger {
	if o.Logger != nil {
		return o.Logger
	}
	return log.Default()
}

func (o *Options) rootMode() bool {
	return o.Injector != "" && o.Injector != InjectorNone
}

// needsClientHello reports whether the first TLS record must be read and
// rewritten before relaying.
func (o *Options) needsClientHello() bool {
	return o.EnableFragment || o.TLSRecordSplit || o.Disorder || o.OOB || (!o.rootMode() && o.FakeTTL > 0)
}

// Ready is sent once when the listener is up, or with Err on start-up failure.
type Ready struct {
	ListenAddr string
	Err        error
}

// Run is the accept loop. It blocks until ctx is cancelled or a fatal injector error occurs.
func Run(ctx context.Context, cfg *config.Config, opts Options, ready chan<- Ready) error {
	logger := opts.logger()
	fail := func(err error) error {
		if ready != nil {
			ready <- Ready{Err: err}
		}
		return err
	}

	var fakeInjector injection.TCPInjector
	interfaceIPv4 := opts.LocalIP
	injectorErr := make(chan error, 1)
	if opts.rootMode() {
		if interfaceIPv4 == "" {
			interfaceIPv4 = network.GetDefaultInterfaceIPv4(cfg.ConnectIP)
		}
		if interfaceIPv4 == "" {
			return fail(fmt.Errorf("failed to detect local interface IPv4 address"))
		}
		if !opts.Quiet {
			logger.Printf("iface: %s %s mark=0x%x injector=%s", opts.InterfaceName, interfaceIPv4, opts.FwMark, opts.Injector)
		}
		params := injection.Params{
			InterfaceIP:   interfaceIPv4,
			InterfaceName: opts.InterfaceName,
			FwMark:        opts.FwMark,
			MTU:           opts.MTU,
		}
		inj, err := injection.NewFakeTcpInjector(params, cfg.ConnectIPv4s, uint16(cfg.ConnectPort), opts.Injector)
		if err != nil {
			return fail(fmt.Errorf("failed to create injector: %w", err))
		}
		fakeInjector = inj
		defer fakeInjector.Close()
		go func() {
			if err := fakeInjector.Start(); err != nil {
				injectorErr <- err
			}
		}()
		if err := fakeInjector.WaitInjectorReady(); err != nil {
			return fail(fmt.Errorf("injector: %w", err))
		}
	} else if !opts.Quiet {
		logger.Printf("mode: non-root (fake-ttl=%d fragment=%v tlsrec=%v disorder=%v oob=%v)",
			opts.FakeTTL, opts.EnableFragment, opts.TLSRecordSplit, opts.Disorder, opts.OOB)
	}

	listenAddr := net.JoinHostPort(cfg.ListenHost, strconv.Itoa(cfg.ListenPort))
	listener, err := net.Listen("tcp4", listenAddr)
	if err != nil {
		return fail(fmt.Errorf("failed to listen: %w", err))
	}
	defer listener.Close()
	go func() {
		<-ctx.Done()
		_ = listener.Close()
		if fakeInjector != nil {
			fakeInjector.Close()
		}
	}()

	if !opts.Quiet {
		logger.Printf("listen: %s -> %s:%d (fake SNI %s)", listener.Addr().String(), cfg.ConnectIP, cfg.ConnectPort, cfg.FakeSNI)
	}
	if ready != nil {
		ready <- Ready{ListenAddr: listener.Addr().String()}
	}

	for {
		incomingSock, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			select {
			case err := <-injectorErr:
				return fmt.Errorf("injector: %w", err)
			default:
			}
			if !opts.Quiet {
				logger.Printf("error: accept error: %v", err)
			}
			time.Sleep(50 * time.Millisecond)
			continue
		}
		if tc, ok := incomingSock.(*net.TCPConn); ok {
			tc.SetKeepAlive(true)
			tc.SetKeepAlivePeriod(11 * time.Second)
		}
		go handleConnection(ctx, incomingSock, cfg, interfaceIPv4, fakeInjector, opts)
	}
}

func handleConnection(
	ctx context.Context,
	incomingSock net.Conn,
	cfg *config.Config,
	interfaceIPv4 string,
	fakeInjector injection.TCPInjector,
	opts Options,
) {
	logger := opts.logger()
	st := opts.Stats
	if st != nil {
		st.Total.Add(1)
		st.Active.Add(1)
		defer st.Active.Add(-1)
	}
	failed := func(format string, args ...any) {
		msg := fmt.Sprintf(format, args...)
		if st != nil {
			st.Failed.Add(1)
			st.LastErr.Store(msg)
		}
		if !opts.Quiet {
			logger.Print(msg)
		}
	}
	defer func() {
		if r := recover(); r != nil {
			failed("error: panic in handle: %v", r)
		}
	}()

	fakeData, err := buildFakeClientHello(cfg.FakeSNI, cfg.UTLSClientHello)
	if err != nil {
		failed("error: ClientHello build: %v", err)
		incomingSock.Close()
		return
	}

	var outgoingSock net.Conn
	if opts.rootMode() {
		var conn *injection.FakeInjectiveConnection
		outgoingSock, conn, _, err = dialOutgoing(
			interfaceIPv4, cfg.ConnectIP, cfg.ConnectPort,
			fakeData, "wrong_seq", opts.FakeRepeat, opts.FakeDelay, opts.FragmentDelay, incomingSock, fakeInjector,
			opts.InterfaceName, opts.FwMark, opts.ConnectTimeout, opts.Control,
		)
		if err != nil {
			failed("error: failed to connect to %s:%d: %v", cfg.ConnectIP, cfg.ConnectPort, err)
			incomingSock.Close()
			return
		}
		conn.Mu.Lock()
		conn.Sock = outgoingSock
		conn.Mu.Unlock()

		timer := time.NewTimer(opts.AckTimeout)
		defer timer.Stop()
		select {
		case msg := <-conn.T2aChan:
			if msg != "fake_data_ack_recv" {
				stopMonitoring(fakeInjector, conn)
				closePair(outgoingSock, incomingSock)
				failed("warn: injector aborted handshake (%s)", msg)
				return
			}
		case <-timer.C:
			stopMonitoring(fakeInjector, conn)
			closePair(outgoingSock, incomingSock)
			failed("warn: ACK timeout after %v (injection not observed; try another injector)", opts.AckTimeout)
			return
		case <-ctx.Done():
			stopMonitoring(fakeInjector, conn)
			closePair(outgoingSock, incomingSock)
			return
		}
		stopMonitoring(fakeInjector, conn)
		if st != nil {
			st.FakeSent.Add(1)
		}
		if opts.FakeDelay > 0 {
			time.Sleep(opts.FakeDelay)
		}
	} else {
		outgoingSock, err = dialPlain(cfg.ConnectIP, cfg.ConnectPort, opts.ConnectTimeout, opts.InterfaceName, opts.FwMark, opts.Control)
		if err != nil {
			failed("error: failed to connect to %s:%d: %v", cfg.ConnectIP, cfg.ConnectPort, err)
			incomingSock.Close()
			return
		}
	}

	if tc, ok := outgoingSock.(*net.TCPConn); ok {
		tc.SetKeepAlive(true)
		tc.SetKeepAlivePeriod(11 * time.Second)
	}

	if opts.needsClientHello() {
		if err := forwardClientHello(incomingSock, outgoingSock, cfg.FakeSNI, fakeData, opts, logger); err != nil {
			failed("error: ClientHello desync: %v", err)
			closePair(outgoingSock, incomingSock)
			return
		}
		if st != nil && !opts.rootMode() && opts.FakeTTL > 0 {
			st.FakeSent.Add(1)
		}
	}

	done := make(chan struct{}, 2)
	go func() {
		defer func() { done <- struct{}{} }()
		n := relay(outgoingSock, incomingSock)
		if st != nil {
			st.BytesUp.Add(n)
		}
	}()
	go func() {
		defer func() { done <- struct{}{} }()
		n := relay(incomingSock, outgoingSock)
		if st != nil {
			st.BytesDn.Add(n)
		}
	}()
	<-done
	closePair(outgoingSock, incomingSock)
	<-done
}

func buildFakeClientHello(fakeSNI, utlsName string) ([]byte, error) {
	if packet.IsLegacyUTLS(utlsName) {
		return packet.BuildLegacyClientHelloRecord(fakeSNI)
	}
	clientHelloID, err := packet.ParseClientHelloID(utlsName)
	if err != nil {
		return nil, err
	}
	return packet.BuildClientHelloRecord(fakeSNI, clientHelloID)
}

// forwardClientHello reads the client's first TLS record and sends it upstream
// using the configured desync steps, in this order:
// TLS record split -> (non-root) TTL fake over the leading bytes -> TCP
// fragmentation of the rest (SNI chunks) with optional disorder / OOB.
func forwardClientHello(incoming, outgoing net.Conn, fakeSNI string, fakeData []byte, opts Options, logger *log.Logger) error {
	if err := incoming.SetReadDeadline(time.Now().Add(firstClientHelloTimeout)); err != nil {
		return err
	}
	rec, err := packet.ReadFirstTLSRecord(incoming)
	_ = incoming.SetReadDeadline(time.Time{})
	if err != nil {
		return err
	}
	tc, _ := outgoing.(*net.TCPConn)
	if tc != nil {
		_ = tc.SetNoDelay(true)
		defer func() { _ = tc.SetNoDelay(false) }()
	}

	sniStart, sniEnd, hasSNI := packet.SNIRange(rec)
	data := rec
	if opts.TLSRecordSplit {
		data = packet.SplitTLSRecordsAtSNI(rec)
		if hasSNI {
			// Record header inserted before the SNI tail shifts the end by 5.
			sniEnd += 5
		}
	}

	// Non-root fake: the first L bytes are first sent as a TTL-limited fake and
	// silently replaced with the real bytes on retransmission.
	if !opts.rootMode() && opts.FakeTTL > 0 {
		if tc == nil {
			return fmt.Errorf("fake-ttl needs a TCP connection")
		}
		l := len(fakeData)
		if l > len(data) {
			l = len(data)
		}
		fake, err := packet.FitFakeToLength(fakeData, l, fakeSNI)
		if err != nil {
			return err
		}
		repeat := opts.FakeRepeat
		if repeat < 1 {
			repeat = 1
		}
		if err := sendFakeThenReal(tc, fake, data[:l], opts.FakeTTL, opts.FakeHold); err != nil {
			return fmt.Errorf("fake-ttl: %w", err)
		}
		if !opts.Quiet {
			logger.Printf("fake: ttl=%d %d bytes (SNI %s)", opts.FakeTTL, l, fakeSNI)
		}
		data = data[l:]
		if len(data) == 0 {
			return nil
		}
		if opts.FakeDelay > 0 {
			time.Sleep(opts.FakeDelay)
		}
		// SNI already covered by the fake segment.
		hasSNI = false
	}

	var frags [][]byte
	switch {
	case opts.EnableFragment && hasSNI && !opts.TLSRecordSplit:
		frags = packet.SplitClientHelloRecord(data, opts.SNIChunk)
	case opts.EnableFragment && hasSNI:
		frags = chunkRange(data, sniStart, sniEnd, opts.SNIChunk)
	case opts.EnableFragment:
		frags = chunkRange(data, 0, len(data), 0)
	case opts.Disorder || opts.OOB:
		cut := len(data) / 2
		if hasSNI {
			cut = sniStart + (sniEnd-sniStart)/2
		}
		frags = [][]byte{data[:cut], data[cut:]}
	default:
		frags = [][]byte{data}
	}

	sent := 0
	for i, p := range frags {
		if len(p) == 0 {
			continue
		}
		if sent > 0 && opts.FragmentDelay > 0 {
			time.Sleep(opts.FragmentDelay)
		}
		firstReal := sent == 0
		// Disorder: send the first fragment with a low TTL so it is dropped
		// on-path and retransmitted after the later fragments, reordering the
		// stream as DPI sees it.
		if opts.Disorder && firstReal && opts.rootMode() == false && tc != nil && opts.DisorderTTL > 0 {
			if err := writeWithTTL(tc, p, opts.DisorderTTL); err != nil {
				return fmt.Errorf("disorder write: %w", err)
			}
		} else if _, err := outgoing.Write(p); err != nil {
			return err
		}
		if opts.OOB && firstReal && tc != nil && i+1 < len(frags) {
			if err := sendOOB(tc, 0x00); err != nil && !opts.Quiet {
				logger.Printf("warn: oob: %v", err)
			}
		}
		sent++
	}
	if !opts.Quiet {
		logger.Printf("clienthello: %d segment(s) sent (fragment=%v tlsrec=%v disorder=%v oob=%v)",
			sent, opts.EnableFragment, opts.TLSRecordSplit, opts.Disorder, opts.OOB)
	}
	return nil
}

// chunkRange copies data, emitting it as a prefix [0:start), chunks of
// chunkBytes across [start:end), then a suffix [end:len). chunkBytes <= 0
// keeps [start:end) whole.
func chunkRange(data []byte, start, end, chunkBytes int) [][]byte {
	if start < 0 {
		start = 0
	}
	if end > len(data) {
		end = len(data)
	}
	if end < start {
		end = start
	}
	var out [][]byte
	if start > 0 {
		out = append(out, data[:start])
	}
	if chunkBytes <= 0 {
		out = append(out, data[start:end])
	} else {
		for i := start; i < end; i += chunkBytes {
			j := i + chunkBytes
			if j > end {
				j = end
			}
			out = append(out, data[i:j])
		}
	}
	if end < len(data) {
		out = append(out, data[end:])
	}
	if len(out) == 0 {
		return [][]byte{data}
	}
	return out
}

func relay(dst, src net.Conn) int64 {
	buf := make([]byte, 64*1024)
	n, _ := io.CopyBuffer(dst, src, buf)
	return n
}

func stopMonitoring(fakeInjector injection.TCPInjector, conn *injection.FakeInjectiveConnection) {
	conn.Mu.Lock()
	conn.Monitor = false
	conn.Mu.Unlock()
	fakeInjector.UnregisterConn(conn)
}

func closePair(a, b net.Conn) {
	if a != nil {
		a.Close()
	}
	if b != nil {
		b.Close()
	}
}
