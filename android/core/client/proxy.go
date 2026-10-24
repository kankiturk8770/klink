package client

import (
	"context"
	"errors"
	"net"
	"time"

	"github.com/kankipro/klink/internal/mux"
	M "github.com/xjasonlyu/tun2socks/v2/metadata"
)

// Proxy connects tun2socks directly to KLINK; no local SOCKS listener or
// unencrypted loopback hop is required.
type Proxy struct {
	Session *Session
}

func (p *Proxy) DialContext(ctx context.Context, metadata *M.Metadata) (net.Conn, error) {
	if p == nil || p.Session == nil || metadata == nil || metadata.Network != M.TCP || !metadata.DstIP.IsValid() {
		return nil, errors.New("invalid TCP metadata")
	}
	return p.Session.openStream(ctx, mux.NetworkTCP, metadata.DstIP.String(), metadata.DstPort)
}

func (p *Proxy) DialUDP(metadata *M.Metadata) (net.PacketConn, error) {
	if p == nil || p.Session == nil || metadata == nil || metadata.Network != M.UDP || !metadata.DstIP.IsValid() {
		return nil, errors.New("invalid UDP metadata")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	stream, err := p.Session.openStream(ctx, mux.NetworkUDP, metadata.DstIP.String(), metadata.DstPort)
	if err != nil {
		return nil, err
	}
	return &packetConn{stream: stream}, nil
}

type packetConn struct{ stream *clientStream }

func (p *packetConn) ReadFrom(buffer []byte) (int, net.Addr, error) {
	n, err := p.stream.Read(buffer)
	return n, p.stream.RemoteAddr(), err
}
func (p *packetConn) WriteTo(buffer []byte, addr net.Addr) (int, error) {
	if addr != nil && p.stream.RemoteAddr() != nil && addr.String() != p.stream.RemoteAddr().String() {
		return 0, errors.New("KLINK UDP association has a fixed destination")
	}
	return p.stream.Write(buffer)
}
func (p *packetConn) Close() error                       { return p.stream.Close() }
func (p *packetConn) LocalAddr() net.Addr                { return p.stream.LocalAddr() }
func (p *packetConn) SetDeadline(t time.Time) error      { return p.stream.SetDeadline(t) }
func (p *packetConn) SetReadDeadline(t time.Time) error  { return p.stream.SetReadDeadline(t) }
func (p *packetConn) SetWriteDeadline(t time.Time) error { return p.stream.SetWriteDeadline(t) }
