package client

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"github.com/kankipro/klink/internal/mux"
)

type clientStream struct {
	id      uint32
	network byte
	session *Session
	local   net.Addr
	remote  net.Addr

	incoming  chan []byte
	status    chan byte
	done      chan struct{}
	closeOnce sync.Once
	writeMu   sync.Mutex
	readBuf   []byte

	errMu         sync.RWMutex
	err           error
	deadlineMu    sync.RWMutex
	readDeadline  time.Time
	writeDeadline time.Time
}

func (s *Session) openStream(ctx context.Context, network byte, host string, port uint16) (*clientStream, error) {
	if s.State() == StateDisconnected {
		return nil, errors.New("VPN متصل نیست")
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil, errors.New("نشست بسته شده است")
	}
	var id uint32
	for {
		id = s.nextStream.Add(1)
		if id != 0 && s.streams[id] == nil {
			break
		}
	}
	var local, remote net.Addr
	if network == mux.NetworkTCP {
		local = &net.TCPAddr{}
		remote = &net.TCPAddr{IP: net.ParseIP(host), Port: int(port)}
	} else {
		local = &net.UDPAddr{}
		remote = &net.UDPAddr{IP: net.ParseIP(host), Port: int(port)}
	}
	stream := &clientStream{id: id, network: network, session: s, local: local, remote: remote,
		incoming: make(chan []byte, 256), status: make(chan byte, 1), done: make(chan struct{})}
	s.streams[id] = stream
	s.mu.Unlock()

	open, err := mux.BuildOpen(id, network, host, port)
	if err != nil {
		stream.abort(err)
		return nil, err
	}
	if err := s.Send(open); err != nil {
		stream.abort(err)
		return nil, err
	}
	select {
	case status := <-stream.status:
		if status != mux.StatusOK {
			stream.abort(errors.New("server rejected stream"))
			return nil, errors.New("سرور مقصد را باز نکرد؛ آدرس یا پورت در دسترس نیست")
		}
		return stream, nil
	case <-ctx.Done():
		stream.abort(ctx.Err())
		return nil, ctx.Err()
	case <-stream.done:
		return nil, stream.closeError()
	case <-s.stop:
		return nil, errors.New("نشست بسته شد")
	}
}

func (s *Session) removeStream(id uint32) {
	s.mu.Lock()
	delete(s.streams, id)
	s.mu.Unlock()
}

func (s *clientStream) closeError() error {
	s.errMu.RLock()
	defer s.errMu.RUnlock()
	if s.err != nil {
		return s.err
	}
	return net.ErrClosed
}

func (s *clientStream) abort(err error) {
	s.closeOnce.Do(func() {
		s.errMu.Lock()
		s.err = err
		s.errMu.Unlock()
		close(s.done)
		s.session.removeStream(s.id)
	})
}

func (s *clientStream) remoteClose() { s.abort(io.EOF) }

func (s *clientStream) Close() error {
	select {
	case <-s.done:
		return nil
	default:
	}
	_ = s.session.Send(mux.BuildClose(s.id))
	s.abort(net.ErrClosed)
	return nil
}

func (s *clientStream) deliver(payload []byte) {
	if len(payload) == 0 {
		return
	}
	data := append([]byte(nil), payload...)
	if s.network == mux.NetworkUDP {
		select {
		case s.incoming <- data:
		default: // UDP is allowed to drop under receiver backpressure.
		}
		return
	}
	select {
	case s.incoming <- data:
	case <-s.done:
	case <-time.After(5 * time.Second):
		s.abort(errors.New("stream receive queue is full"))
	}
}

func (s *clientStream) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	for {
		if len(s.readBuf) > 0 {
			n := copy(p, s.readBuf)
			s.readBuf = s.readBuf[n:]
			return n, nil
		}
		s.deadlineMu.RLock()
		deadline := s.readDeadline
		s.deadlineMu.RUnlock()
		var timeout <-chan time.Time
		var timer *time.Timer
		if !deadline.IsZero() {
			remaining := time.Until(deadline)
			if remaining <= 0 {
				return 0, os.ErrDeadlineExceeded
			}
			timer = time.NewTimer(remaining)
			timeout = timer.C
		}
		select {
		case data := <-s.incoming:
			if timer != nil {
				timer.Stop()
			}
			s.readBuf = data
		case <-s.done:
			if timer != nil {
				timer.Stop()
			}
			// Drain already authenticated data before reporting EOF.
			select {
			case data := <-s.incoming:
				s.readBuf = data
				continue
			default:
			}
			return 0, s.closeError()
		case <-timeout:
			return 0, os.ErrDeadlineExceeded
		}
	}
}

func (s *clientStream) Write(p []byte) (int, error) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	s.deadlineMu.RLock()
	deadline := s.writeDeadline
	s.deadlineMu.RUnlock()
	if !deadline.IsZero() && !time.Now().Before(deadline) {
		return 0, os.ErrDeadlineExceeded
	}
	select {
	case <-s.done:
		return 0, s.closeError()
	default:
	}
	if s.network == mux.NetworkUDP {
		if len(p) > mux.MaxUDPPayload {
			return 0, errors.New("UDP datagram is too large")
		}
		if err := s.session.Send(mux.BuildData(s.id, p)); err != nil {
			return 0, err
		}
		return len(p), nil
	}
	written := 0
	for len(p) > 0 {
		n := len(p)
		if n > mux.MaxTCPPayload {
			n = mux.MaxTCPPayload
		}
		if err := s.session.Send(mux.BuildData(s.id, p[:n])); err != nil {
			return written, err
		}
		written += n
		p = p[n:]
	}
	return written, nil
}

func (s *clientStream) LocalAddr() net.Addr  { return s.local }
func (s *clientStream) RemoteAddr() net.Addr { return s.remote }
func (s *clientStream) SetDeadline(t time.Time) error {
	_ = s.SetReadDeadline(t)
	return s.SetWriteDeadline(t)
}
func (s *clientStream) SetReadDeadline(t time.Time) error {
	s.deadlineMu.Lock()
	s.readDeadline = t
	s.deadlineMu.Unlock()
	return nil
}
func (s *clientStream) SetWriteDeadline(t time.Time) error {
	s.deadlineMu.Lock()
	s.writeDeadline = t
	s.deadlineMu.Unlock()
	return nil
}
