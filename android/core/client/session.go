package client

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	kcrypto "github.com/kankipro/klink/internal/crypto"
	"github.com/kankipro/klink/internal/mux"
	"github.com/kankipro/klink/internal/obfuscation"
)

const (
	wireVersion   = 1
	wireHello1    = 1
	wireHello2    = 2
	wireHello3    = 3
	wireHelloAck  = 4
	wireData      = 16
	wireKeepalive = 0
	wirePing      = 5
	wirePong      = 6
	// wireClose به سرور می‌گوید این نشست عمداً بسته شد تا سهمیه‌ی دستگاه فوراً
	// آزاد شود و اتصال دوباره‌ی همان گوشی رد نشود.
	wireClose = 7
)

const (
	StateDisconnected = 0
	StateConnecting   = 1
	StateConnected    = 2
	StateReconnecting = 3
)

type connector struct {
	cfg          *Config
	profile      obfuscation.Profile
	key          kcrypto.KeyPair
	serverPublic [32]byte
}

type handshakeResult struct {
	transport clientTransport
	secret    []byte
	sessionID [16]byte
	inbound   *kcrypto.Channel
	outbound  *kcrypto.Channel
}

func newConnector(cfg *Config) (*connector, error) {
	key, err := kcrypto.KeyFromBase64(cfg.ClientPrivateKey)
	if err != nil {
		return nil, err
	}
	serverPublic, err := kcrypto.PublicFromBase64(cfg.ServerPublicKey)
	if err != nil {
		return nil, err
	}
	profile, err := obfuscation.ByName(cfg.Obfuscation)
	if err != nil {
		return nil, err
	}
	return &connector{cfg: cfg, profile: profile, key: key, serverPublic: serverPublic}, nil
}

func (c *connector) handshake(ctx context.Context, network string) (*handshakeResult, error) {
	t, err := dialTransport(ctx, c.cfg, network, c.profile)
	if err != nil {
		return nil, err
	}
	ok := false
	defer func() {
		if !ok {
			_ = t.Close()
		}
	}()
	_ = t.SetDeadline(time.Now().Add(10 * time.Second))
	stopDeadline := context.AfterFunc(ctx, func() { _ = t.SetDeadline(time.Now()) })
	defer stopDeadline()

	hs, err := kcrypto.NewInitiator(c.key, c.serverPublic)
	if err != nil {
		return nil, err
	}
	var hello [16]byte
	if _, err := rand.Read(hello[:]); err != nil {
		return nil, err
	}
	m1, _, _, err := hs.WriteMessage(nil)
	if err != nil {
		return nil, err
	}
	if err := t.Write(handshakePacket(wireHello1, hello, m1)); err != nil {
		return nil, err
	}
	response, err := t.Read()
	if err != nil {
		return nil, err
	}
	if !validHandshakeResponse(response, wireHello2, hello) {
		return nil, errors.New("پاسخ handshake سرور معتبر نیست")
	}
	if _, _, finished, err := hs.ReadMessage(response[18:]); err != nil || finished {
		return nil, errors.New("بررسی پیام دوم Noise ناموفق بود")
	}
	m3, secret, finished, err := hs.WriteMessage(nil)
	if err != nil || !finished {
		return nil, errors.New("ساخت پیام سوم Noise ناموفق بود")
	}
	if err := t.Write(handshakePacket(wireHello3, hello, m3)); err != nil {
		return nil, err
	}
	// Server upgrades its TCP mask immediately after authenticating message 3.
	t.Upgrade(secret)
	ack, err := t.Read()
	if err != nil {
		return nil, err
	}
	if len(ack) != 34 || !validHandshakeResponse(ack, wireHelloAck, hello) {
		return nil, errors.New("کاربر توسط سرور پذیرفته نشد؛ حجم، انقضا و دستگاه را بررسی کنید")
	}
	var sid [16]byte
	copy(sid[:], ack[18:34])
	k1, k2, err := kcrypto.ChannelKeys(secret)
	if err != nil {
		return nil, err
	}
	outbound, err := kcrypto.NewChannel(k1)
	if err != nil {
		return nil, err
	}
	inbound, err := kcrypto.NewChannel(k2)
	if err != nil {
		return nil, err
	}
	_ = t.SetDeadline(time.Time{})
	result := &handshakeResult{transport: t, secret: secret, sessionID: sid, inbound: inbound, outbound: outbound}
	ok = true
	return result, nil
}

func handshakePacket(kind byte, hello [16]byte, payload []byte) []byte {
	packet := make([]byte, 18+len(payload))
	packet[0], packet[1] = wireVersion, kind
	copy(packet[2:18], hello[:])
	copy(packet[18:], payload)
	return packet
}

func validHandshakeResponse(packet []byte, kind byte, hello [16]byte) bool {
	return len(packet) > 18 && packet[0] == wireVersion && packet[1] == kind &&
		subtle.ConstantTimeCompare(packet[2:18], hello[:]) == 1
}

type Session struct {
	cfg       *Config
	connector *connector
	ctx       context.Context
	cancel    context.CancelFunc

	mu        sync.RWMutex
	transport clientTransport
	secret    []byte
	sessionID [16]byte
	closed    bool
	streams   map[uint32]*clientStream

	sendMu      sync.Mutex
	outbound    *kcrypto.Channel
	lastRekey   time.Time
	sentPackets uint64

	recvMu      sync.Mutex
	inbound     *kcrypto.Channel
	replay      kcrypto.ReplayWindow
	replayEpoch uint64

	nextStream atomic.Uint32
	state      atomic.Int32
	lastError  atomic.Value
	pongs      chan struct{}
	reconnect  chan struct{}
	stop       chan struct{}
}

func Connect(ctx context.Context, subscriptionJSON string) (*Session, error) {
	cfg, err := ParseSubscription([]byte(subscriptionJSON))
	if err != nil {
		return nil, err
	}
	connector, err := newConnector(cfg)
	if err != nil {
		return nil, err
	}
	var result *handshakeResult
	var errs []error
	for _, network := range configuredNetworks(cfg, "") {
		attemptCtx, cancel := context.WithTimeout(ctx, 12*time.Second)
		result, err = connector.handshake(attemptCtx, network)
		cancel()
		if err == nil {
			break
		}
		errs = append(errs, fmt.Errorf("%s: %w", network, err))
	}
	if result == nil {
		return nil, fmt.Errorf("اتصال به هیچ‌یک از مسیرها برقرار نشد: %w", errors.Join(errs...))
	}
	sessionCtx, cancel := context.WithCancel(context.Background())
	s := &Session{cfg: cfg, connector: connector, ctx: sessionCtx, cancel: cancel,
		transport: result.transport, secret: result.secret, sessionID: result.sessionID,
		inbound: result.inbound, outbound: result.outbound, lastRekey: time.Now(),
		streams: make(map[uint32]*clientStream), pongs: make(chan struct{}, 8),
		reconnect: make(chan struct{}, 1), stop: make(chan struct{})}
	s.lastError.Store("")
	s.state.Store(StateConnected)
	go s.readLoop(result.transport)
	go s.watchdog()
	return s, nil
}

func configuredNetworks(cfg *Config, current string) []string {
	networks := make([]string, 0, len(cfg.Transports))
	for _, t := range cfg.Transports {
		if t.Network != current {
			networks = append(networks, t.Network)
		}
	}
	if current != "" {
		for _, t := range cfg.Transports {
			if t.Network == current {
				networks = append(networks, t.Network)
			}
		}
	}
	return networks
}

func (s *Session) State() int { return int(s.state.Load()) }
func (s *Session) LastError() string {
	if value := s.lastError.Load(); value != nil {
		return value.(string)
	}
	return ""
}
func (s *Session) Network() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.transport == nil {
		return ""
	}
	return s.transport.Network()
}
func (s *Session) IDString() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return base64.RawURLEncoding.EncodeToString(s.sessionID[:])
}

func (s *Session) currentTransport() clientTransport {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.transport
}

func (s *Session) readLoop(t clientTransport) {
	for {
		raw, err := t.Read()
		if err != nil {
			if s.currentTransport() == t && s.State() != StateDisconnected {
				s.lastError.Store("مسیر " + t.Network() + " قطع شد")
				s.requestReconnect()
			}
			return
		}
		if s.currentTransport() != t {
			return
		}
		if len(raw) <= 18 || raw[0] != wireVersion || raw[1] != wireData {
			continue
		}
		s.mu.RLock()
		sid := s.sessionID
		s.mu.RUnlock()
		if subtle.ConstantTimeCompare(raw[2:18], sid[:]) != 1 {
			continue
		}
		s.recvMu.Lock()
		plaintext, sequence, epoch, err := s.inbound.Open(raw[18:])
		if err == nil {
			if epoch != s.replayEpoch {
				s.replay.Reset()
				s.replayEpoch = epoch
			}
			err = s.replay.Check(sequence)
		}
		s.recvMu.Unlock()
		if err != nil || len(plaintext) == 0 {
			continue
		}
		switch plaintext[0] {
		case wireKeepalive:
			continue
		case wirePong:
			select {
			case s.pongs <- struct{}{}:
			default:
			}
			continue
		case wirePing:
			_ = s.sendOn(t, []byte{wirePong}, false)
			continue
		}
		s.dispatch(plaintext)
	}
}

func (s *Session) Send(plaintext []byte) error {
	t := s.currentTransport()
	if t == nil {
		return errors.New("اتصال برقرار نیست")
	}
	return s.sendOn(t, plaintext, false)
}

func (s *Session) sendOn(t clientTransport, plaintext []byte, upgradeAfter bool) error {
	if len(plaintext) > 65000 {
		return errors.New("payload is too large")
	}
	s.sendMu.Lock()
	defer s.sendMu.Unlock()
	s.mu.RLock()
	closed := s.closed
	sid := s.sessionID
	s.mu.RUnlock()
	if closed {
		return errors.New("نشست بسته شده است")
	}
	if s.sentPackets >= s.cfg.RekeyPackets || time.Since(s.lastRekey) >= s.cfg.RekeyInterval() {
		s.outbound.Rekey()
		s.sentPackets = 0
		s.lastRekey = time.Now()
	}
	sealed, _, err := s.outbound.Seal(plaintext)
	if err != nil {
		return err
	}
	s.sentPackets++
	packet := make([]byte, 18+len(sealed))
	packet[0], packet[1] = wireVersion, wireData
	copy(packet[2:18], sid[:])
	copy(packet[18:], sealed)
	if err := t.Write(packet); err != nil {
		return err
	}
	if upgradeAfter {
		t.Upgrade(s.secret)
	}
	return nil
}

func (s *Session) dispatch(frame []byte) {
	if len(frame) < 5 {
		return
	}
	id := uint32(frame[1])<<24 | uint32(frame[2])<<16 | uint32(frame[3])<<8 | uint32(frame[4])
	s.mu.RLock()
	stream := s.streams[id]
	s.mu.RUnlock()
	if stream == nil {
		return
	}
	switch frame[0] {
	case mux.FrameStatus:
		if len(frame) == 6 {
			select {
			case stream.status <- frame[5]:
			default:
			}
		}
	case mux.FrameData:
		stream.deliver(frame[5:])
	case mux.FrameClose:
		stream.remoteClose()
	}
}

func (s *Session) clearPongs() {
	for {
		select {
		case <-s.pongs:
		default:
			return
		}
	}
}

func (s *Session) waitPong(timeout time.Duration) bool {
	select {
	case <-s.pongs:
		return true
	case <-time.After(timeout):
		return false
	case <-s.stop:
		return false
	}
}

func (s *Session) probeCurrent() bool {
	t := s.currentTransport()
	if t == nil {
		return false
	}
	s.clearPongs()
	if err := s.sendOn(t, []byte{wirePing}, false); err != nil {
		return false
	}
	return s.waitPong(4 * time.Second)
}

func (s *Session) watchdog() {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-s.stop:
			return
		case <-s.reconnect:
			s.reconnectLoop()
		case <-ticker.C:
			if s.State() == StateConnected && !s.probeCurrent() {
				s.lastError.Store("پاسخ سلامت نشست دریافت نشد")
				s.reconnectLoop()
			}
		}
	}
}

func (s *Session) requestReconnect() {
	select {
	case s.reconnect <- struct{}{}:
	default:
	}
}

func (s *Session) drainReconnect() {
	select {
	case <-s.reconnect:
	default:
	}
}

func (s *Session) reconnectLoop() {
	if s.State() == StateDisconnected {
		return
	}
	s.state.Store(StateReconnecting)
	for cycle := 1; ; cycle++ {
		for _, network := range configuredNetworks(s.cfg, s.Network()) {
			ctx, cancel := context.WithTimeout(s.ctx, 8*time.Second)
			err := s.tryMigrate(ctx, network)
			cancel()
			if err == nil {
				s.drainReconnect()
				s.state.Store(StateConnected)
				s.lastError.Store("")
				return
			}
			s.lastError.Store(err.Error())
			select {
			case <-s.stop:
				return
			default:
			}
		}
		if cycle%3 == 0 {
			if err := s.rehandshake(); err == nil {
				s.state.Store(StateConnected)
				s.lastError.Store("")
				return
			} else {
				s.lastError.Store(err.Error())
			}
		}
		select {
		case <-time.After(2 * time.Second):
		case <-s.stop:
			return
		}
	}
}

func (s *Session) tryMigrate(ctx context.Context, network string) error {
	old := s.currentTransport()
	if old != nil && old.Network() == network {
		// Re-dial even on the same network: Wi-Fi/mobile source addresses and
		// broken TCP connections cannot be repaired by reusing the old socket.
	}
	t, err := dialTransport(ctx, s.cfg, network, s.connector.profile)
	if err != nil {
		return fmt.Errorf("مسیر %s در دسترس نیست: %w", network, err)
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		t.Close()
		return errors.New("نشست بسته شده است")
	}
	s.transport = t
	s.mu.Unlock()
	go s.readLoop(t)
	s.clearPongs()
	if err := s.sendOn(t, []byte{wirePing}, network == "tcp"); err != nil {
		t.Close()
		s.restoreTransport(t, old)
		return fmt.Errorf("ارسال نشست روی %s ناموفق بود: %w", network, err)
	}
	if !s.waitPong(4 * time.Second) {
		t.Close()
		s.restoreTransport(t, old)
		return fmt.Errorf("سرور نشست را روی مسیر %s تأیید نکرد", network)
	}
	if old != nil && old != t {
		_ = old.Close()
	}
	return nil
}

func (s *Session) restoreTransport(candidate, previous clientTransport) {
	s.mu.Lock()
	if s.transport == candidate {
		s.transport = previous
	}
	s.mu.Unlock()
}

func (s *Session) rehandshake() error {
	var errs []error
	for _, network := range configuredNetworks(s.cfg, "") {
		ctx, cancel := context.WithTimeout(s.ctx, 12*time.Second)
		result, err := s.connector.handshake(ctx, network)
		cancel()
		if err != nil {
			errs = append(errs, err)
			continue
		}
		old := s.currentTransport()
		s.sendMu.Lock()
		s.recvMu.Lock()
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			s.recvMu.Unlock()
			s.sendMu.Unlock()
			result.transport.Close()
			return errors.New("نشست بسته شده است")
		}
		s.transport = result.transport
		s.secret = result.secret
		s.sessionID = result.sessionID
		s.outbound = result.outbound
		s.inbound = result.inbound
		s.replay.Reset()
		s.replayEpoch = 0
		s.sentPackets = 0
		s.lastRekey = time.Now()
		s.mu.Unlock()
		s.recvMu.Unlock()
		s.sendMu.Unlock()
		if old != nil {
			old.Close()
		}
		s.closeAllStreams(errors.New("نشست جدید ایجاد شد؛ جریان‌ها دوباره باز می‌شوند"))
		go s.readLoop(result.transport)
		return nil
	}
	return fmt.Errorf("handshake مجدد ناموفق بود: %w", errors.Join(errs...))
}

func (s *Session) Close() {
	if t := s.currentTransport(); t != nil {
		// Best effort: a lost goodbye only means the server frees the slot later.
		_ = s.sendOn(t, []byte{wireClose}, false)
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	t := s.transport
	s.mu.Unlock()
	s.state.Store(StateDisconnected)
	s.cancel()
	close(s.stop)
	if t != nil {
		_ = t.Close()
	}
	s.closeAllStreams(errors.New("نشست بسته شد"))
}

func (s *Session) closeAllStreams(err error) {
	s.mu.Lock()
	streams := make([]*clientStream, 0, len(s.streams))
	for _, stream := range s.streams {
		streams = append(streams, stream)
	}
	s.mu.Unlock()
	for _, stream := range streams {
		stream.abort(err)
	}
}
