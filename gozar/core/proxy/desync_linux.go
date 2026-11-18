//go:build linux

package proxy

import (
	"errors"
	"fmt"
	"net"
	"time"

	"golang.org/x/sys/unix"
)

// These primitives work without root on Linux/Android: they only use
// setsockopt on the proxy's own TCP socket plus zero-copy splice.

func rawFD(c *net.TCPConn, fn func(fd int) error) error {
	rc, err := c.SyscallConn()
	if err != nil {
		return err
	}
	var inner error
	if err := rc.Control(func(fd uintptr) { inner = fn(int(fd)) }); err != nil {
		return err
	}
	return inner
}

func isIPv6Conn(c *net.TCPConn) bool {
	if a, ok := c.RemoteAddr().(*net.TCPAddr); ok {
		return a.IP.To4() == nil
	}
	return false
}

func getTTL(fd int, v6 bool) (int, error) {
	if v6 {
		return unix.GetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_UNICAST_HOPS)
	}
	return unix.GetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_TTL)
}

func setTTL(fd int, v6 bool, ttl int) error {
	if v6 {
		return unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_UNICAST_HOPS, ttl)
	}
	return unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_TTL, ttl)
}

// waitUnsent polls TCP_INFO until the kernel has handed every queued byte to
// the network (notsent == 0) or the timeout expires.
func waitUnsent(fd int, timeout time.Duration) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		info, err := unix.GetsockoptTCPInfo(fd, unix.IPPROTO_TCP, unix.TCP_INFO)
		if err != nil || info.Notsent_bytes == 0 {
			return
		}
		time.Sleep(time.Millisecond)
	}
}

// writeWithTTL writes p with a temporary TTL/hop-limit and restores the
// original value once the segment has left. Used for "disorder": the segment
// dies before reaching the server and the kernel retransmits it later with
// the normal TTL, so on-path DPI sees the stream out of order.
func writeWithTTL(c *net.TCPConn, p []byte, ttl int) error {
	v6 := isIPv6Conn(c)
	var orig int
	err := rawFD(c, func(fd int) error {
		var e error
		if orig, e = getTTL(fd, v6); e != nil {
			return e
		}
		return setTTL(fd, v6, ttl)
	})
	if err != nil {
		return fmt.Errorf("set ttl: %w", err)
	}
	_, werr := c.Write(p)
	_ = rawFD(c, func(fd int) error {
		waitUnsent(fd, 200*time.Millisecond)
		return setTTL(fd, v6, orig)
	})
	return werr
}

// sendOOB sends one urgent byte. Receivers without SO_OOBINLINE (Linux
// default, Go servers) drop it from the stream; DPI that reassembles naively
// sees a corrupted record.
func sendOOB(c *net.TCPConn, b byte) error {
	return rawFD(c, func(fd int) error {
		return unix.Sendto(fd, []byte{b}, unix.MSG_OOB, nil)
	})
}

// sendFakeThenReal implements the TTL-limited in-stream fake without root:
//
//  1. fake (len == len(real)) is placed in an anonymous page and spliced into
//     the socket zero-copy with a low TTL, so it reaches on-path DPI but expires
//     before the server;
//  2. once the segment has left, the same page is overwritten with the real
//     bytes and the TTL restored;
//  3. the server never ACKs the lost segment, so the kernel retransmits the
//     same sequence range from the same page — now carrying the real data.
//
// The caller must not write further data on c until this returns.
func sendFakeThenReal(c *net.TCPConn, fake, real []byte, ttl int, hold time.Duration) error {
	if len(fake) != len(real) {
		return fmt.Errorf("fake/real length mismatch %d != %d", len(fake), len(real))
	}
	n := len(real)
	if n == 0 {
		return nil
	}
	pageSize := unix.Getpagesize()
	size := (n + pageSize - 1) / pageSize * pageSize
	mem, err := unix.Mmap(-1, 0, size, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED|unix.MAP_ANONYMOUS)
	if err != nil {
		return fmt.Errorf("mmap: %w", err)
	}
	copy(mem, fake)

	var p [2]int
	if err := unix.Pipe2(p[:], unix.O_CLOEXEC); err != nil {
		_ = unix.Munmap(mem)
		return fmt.Errorf("pipe: %w", err)
	}
	defer unix.Close(p[0])
	defer unix.Close(p[1])
	// Make sure the pipe can hold the whole fake.
	_, _ = unix.FcntlInt(uintptr(p[1]), unix.F_SETPIPE_SZ, size)

	v6 := isIPv6Conn(c)
	var orig int
	sendErr := rawFD(c, func(fd int) error {
		var e error
		if orig, e = getTTL(fd, v6); e != nil {
			return e
		}
		if e = setTTL(fd, v6, ttl); e != nil {
			return e
		}
		_ = unix.SetsockoptInt(fd, unix.IPPROTO_TCP, unix.TCP_NODELAY, 1)

		iov := []unix.Iovec{{Base: &mem[0]}}
		iov[0].SetLen(n)
		if _, e = unix.Vmsplice(p[1], iov, unix.SPLICE_F_GIFT); e != nil {
			return fmt.Errorf("vmsplice: %w", e)
		}
		left := n
		for left > 0 {
			m, e := unix.Splice(p[0], nil, fd, nil, left, 0)
			if e != nil {
				if errors.Is(e, unix.EAGAIN) || errors.Is(e, unix.EINTR) {
					time.Sleep(time.Millisecond)
					continue
				}
				return fmt.Errorf("splice: %w", e)
			}
			left -= int(m)
		}
		waitUnsent(fd, 500*time.Millisecond)
		if hold > 0 {
			time.Sleep(hold)
		}
		copy(mem, real)
		return setTTL(fd, v6, orig)
	})
	// Pages stay referenced by the socket buffer until ACKed; unmapping our
	// view is safe and does not free them.
	go func() {
		time.Sleep(5 * time.Second)
		_ = unix.Munmap(mem)
	}()
	return sendErr
}
