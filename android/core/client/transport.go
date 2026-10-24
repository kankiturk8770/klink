package client

import (
	"context"
	"errors"
	"net"
	"time"

	kcrypto "github.com/kankipro/klink/internal/crypto"
	"github.com/kankipro/klink/internal/obfuscation"
	baseTransport "github.com/kankipro/klink/internal/transport"
)

type clientTransport interface {
	Network() string
	Read() ([]byte, error)
	Write([]byte) error
	Upgrade([]byte)
	SetDeadline(time.Time) error
	Close() error
}

type udpTransport struct {
	conn    *net.UDPConn
	profile obfuscation.Profile
}

func newUDPTransport(ctx context.Context, endpoint string, profile obfuscation.Profile) (clientTransport, error) {
	dialer := net.Dialer{Timeout: 8 * time.Second}
	conn, err := dialer.DialContext(ctx, "udp", endpoint)
	if err != nil {
		return nil, err
	}
	udp, ok := conn.(*net.UDPConn)
	if !ok {
		conn.Close()
		return nil, errors.New("UDP socket type mismatch")
	}
	_ = udp.SetReadBuffer(4 << 20)
	_ = udp.SetWriteBuffer(4 << 20)
	return &udpTransport{conn: udp, profile: profile}, nil
}

func (t *udpTransport) Network() string               { return "udp" }
func (t *udpTransport) Upgrade([]byte)                {}
func (t *udpTransport) SetDeadline(v time.Time) error { return t.conn.SetDeadline(v) }
func (t *udpTransport) Close() error                  { return t.conn.Close() }
func (t *udpTransport) Write(raw []byte) error {
	_ = t.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	_, err := t.conn.Write(t.profile.Wrap(raw))
	return err
}
func (t *udpTransport) Read() ([]byte, error) {
	buffer := make([]byte, 65535)
	n, err := t.conn.Read(buffer)
	if err != nil {
		return nil, err
	}
	return t.profile.Unwrap(buffer[:n])
}

type tcpTransport struct {
	conn    net.Conn
	profile obfuscation.Profile
	framer  *baseTransport.Framer
	reads   uint64
}

func newTCPTransport(ctx context.Context, endpoint string, profile obfuscation.Profile) (clientTransport, error) {
	dialer := net.Dialer{Timeout: 8 * time.Second, KeepAlive: 30 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", endpoint)
	if err != nil {
		return nil, err
	}
	if tcp, ok := conn.(*net.TCPConn); ok {
		_ = tcp.SetNoDelay(true)
		_ = tcp.SetKeepAlive(true)
		_ = tcp.SetKeepAlivePeriod(30 * time.Second)
	}
	return &tcpTransport{conn: conn, profile: profile, framer: baseTransport.NewFramer(kcrypto.Prologue)}, nil
}

func (t *tcpTransport) Network() string               { return "tcp" }
func (t *tcpTransport) Upgrade(secret []byte)         { t.framer.Upgrade(secret) }
func (t *tcpTransport) SetDeadline(v time.Time) error { return t.conn.SetDeadline(v) }
func (t *tcpTransport) Close() error                  { return t.conn.Close() }
func (t *tcpTransport) Write(raw []byte) error {
	_ = t.conn.SetWriteDeadline(time.Now().Add(15 * time.Second))
	return t.framer.WriteFrame(t.conn, t.profile.Wrap(raw))
}
func (t *tcpTransport) Read() ([]byte, error) {
	packet, err := t.framer.ReadFrame(t.conn, &t.reads)
	if err != nil {
		return nil, err
	}
	return t.profile.Unwrap(packet)
}

func dialTransport(ctx context.Context, cfg *Config, network string, profile obfuscation.Profile) (clientTransport, error) {
	for _, endpoint := range cfg.Transports {
		if endpoint.Network != network {
			continue
		}
		switch network {
		case "udp":
			return newUDPTransport(ctx, endpoint.Endpoint, profile)
		case "tcp":
			return newTCPTransport(ctx, endpoint.Endpoint, profile)
		}
	}
	return nil, errors.New("این نوع انتقال در اشتراک وجود ندارد")
}
