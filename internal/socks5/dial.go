package socks5

import (
	"net"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// Dial is a helper function to dial a tcp or udp connection
func dial(network, addr string, outIface *net.Interface, timeout int) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: time.Duration(timeout) * time.Second}
	if outIface != nil {
		dialer.Control = func(network, address string, c syscall.RawConn) (err error) {
			return c.Control(func(fd uintptr) {
				unix.BindToDevice(int(fd), outIface.Name)
			})
		}
	}

	c, err := dialer.Dial(network, addr)
	if err != nil {
		return nil, err
	}

	if c, ok := c.(*net.TCPConn); ok {
		c.SetKeepAlive(true)
	}

	c.SetDeadline(time.Now().Add(time.Duration(timeout) * time.Second))
	return c, err
}
