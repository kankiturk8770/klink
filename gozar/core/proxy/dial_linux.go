//go:build linux

package proxy

import (
	"fmt"
	"net"
	"syscall"
	"time"

	"gozar/core/injection"
)

func dialOutgoing(
	interfaceIPv4, connectIP string, connectPort int,
	fakeData []byte, bypassMethod string,
	fakeRepeat int,
	fakeDelay, fragmentDelay time.Duration,
	incomingSock net.Conn,
	fakeInjector injection.TCPInjector,
	interfaceName string, fwMark int, connectTimeout time.Duration, control func(fd uintptr),
) (outgoingSock net.Conn, conn *injection.FakeInjectiveConnection, srcPort uint16, err error) {
	targetAddr := net.JoinHostPort(connectIP, fmt.Sprintf("%d", connectPort))

	var registered bool
	if connectTimeout <= 0 {
		connectTimeout = 10 * time.Second
	}

	dialer := net.Dialer{
		Timeout:   connectTimeout,
		KeepAlive: 11 * time.Second,
		Control: func(netw, addr string, c syscall.RawConn) error {
			var bindErr error
			c.Control(func(fd uintptr) {
				syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
				syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_KEEPALIVE, 1)
				if interfaceName != "" {
					_ = syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, interfaceName)
				}
				if fwMark != 0 {
					_ = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, fwMark)
				}
				if control != nil {
					control(fd)
				}

				sa := &syscall.SockaddrInet4{Port: 0}
				ip4 := net.ParseIP(interfaceIPv4).To4()
				if ip4 == nil {
					bindErr = fmt.Errorf("local address is not IPv4: %q", interfaceIPv4)
					return
				}
				copy(sa.Addr[:], ip4)
				bindErr = syscall.Bind(int(fd), sa)
				if bindErr != nil {
					return
				}

				localSA, gsErr := syscall.Getsockname(int(fd))
				if gsErr != nil {
					bindErr = gsErr
					return
				}
				switch la := localSA.(type) {
				case *syscall.SockaddrInet4:
					srcPort = uint16(la.Port)
				default:
					bindErr = fmt.Errorf("getsockname: unexpected address type %T", localSA)
				}
			})
			if bindErr != nil {
				return bindErr
			}

			conn = injection.NewFakeInjectiveConnection(
				nil, interfaceIPv4, connectIP, srcPort, uint16(connectPort),
				fakeData, bypassMethod, incomingSock, fakeRepeat, fakeDelay, fragmentDelay,
			)
			fakeInjector.RegisterConn(conn)
			registered = true
			return nil
		},
	}

	outgoingSock, err = dialer.Dial("tcp4", targetAddr)
	if err != nil {
		if registered && conn != nil {
			conn.Mu.Lock()
			conn.Monitor = false
			conn.Mu.Unlock()
			fakeInjector.UnregisterConn(conn)
		}
		return nil, nil, 0, err
	}

	return outgoingSock, conn, srcPort, nil
}

// dialPlain opens a normal TCP connection (non-root mode), optionally bound to
// a device/mark for Android VPN bypass.
func dialPlain(connectIP string, connectPort int, timeout time.Duration, interfaceName string, fwMark int, control func(fd uintptr)) (net.Conn, error) {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	d := net.Dialer{Timeout: timeout, KeepAlive: 11 * time.Second,
		Control: func(_, _ string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				if interfaceName != "" {
					_ = syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, interfaceName)
				}
				if fwMark != 0 {
					_ = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, fwMark)
				}
				if control != nil {
					control(fd)
				}
			})
		},
	}
	return d.Dial("tcp4", net.JoinHostPort(connectIP, fmt.Sprintf("%d", connectPort)))
}
