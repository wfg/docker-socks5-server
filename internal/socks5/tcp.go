package socks5

import (
	"encoding/binary"
	"io"
	"log"
	"net"
	"strconv"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// Tcp server struct
type TCPServer struct {
	log               *log.Logger
	config            Config
	udpConn           *net.UDPConn
	publicIP          string
	externalInterface *net.Interface
}

func (t *TCPServer) Start() {
	l, err := net.Listen("tcp", t.config.InboundAddress)
	if err != nil {
		t.log.Fatalf("failed to listen: %v", err)
	}
	t.log.Printf("listening on %s", t.config.InboundAddress)
	for {
		conn, err := l.Accept()
		if err != nil {
			t.log.Printf("failed to accept: %v", err)
			continue
		}
		go t.handle(conn)
	}
}

func (t *TCPServer) handle(srcConn net.Conn) {
	defer srcConn.Close()
	clientSocksVer := make([]byte, 1)
	n, err := srcConn.Read(clientSocksVer)
	if err != nil || n == 0 {
		t.log.Printf("failed to read socks version: %v", err)
		return
	}
	if clientSocksVer[0] != SocksVersion {
		t.log.Printf("invalid socks version: %d", clientSocksVer[0])
		return
	}
	numClientAuthMethods := make([]byte, 1)
	n, err = srcConn.Read(numClientAuthMethods)
	if err != nil || n == 0 {
		t.log.Printf("failed to read number of client auth methods: %v", err)
		return
	}
	clientAuthMethods := make([]byte, numClientAuthMethods[0])
	n, err = srcConn.Read(clientAuthMethods)
	if err != nil || n == 0 {
		t.log.Printf("failed to read client auth methods: %v", err)
		return
	}

	var authMethod byte
	if t.config.Username != "" && t.config.Password != "" {
		authMethod = UserAuth
		if !contains(clientAuthMethods, UserAuth) {
			t.log.Printf("client does not support user/pass auth")
			_, err = srcConn.Write([]byte{SocksVersion, NoAcceptableMethods})
			if err != nil {
				t.log.Printf("failed to write no acceptable methods: %v", err)
			}
			return
		}
		_, err = srcConn.Write([]byte{SocksVersion, authMethod})
		if err != nil {
			t.log.Printf("failed to write selected auth method: %v", err)
			return
		}

		clientUserAuthVersion := make([]byte, 1)
		n, err = srcConn.Read(clientUserAuthVersion)
		if err != nil || n == 0 {
			t.log.Printf("failed to read user/pass auth version: %v", err)
			return
		}
		if clientUserAuthVersion[0] != UserAuthVersion {
			t.log.Printf("invalid user/pass auth version: %d", clientUserAuthVersion[0])
			return
		}
		usernameLen := make([]byte, 1)
		n, err = srcConn.Read(usernameLen)
		if err != nil || n == 0 {
			t.log.Printf("failed to read client username length: %v", err)
			return
		}
		username := make([]byte, usernameLen[0])
		n, err = srcConn.Read(username)
		if err != nil || n == 0 {
			t.log.Printf("failed to read client username: %v", err)
			return
		}
		passwordLen := make([]byte, 1)
		n, err = srcConn.Read(passwordLen)
		if err != nil || n == 0 {
			t.log.Printf("failed to read client password length: %v", err)
			return
		}
		password := make([]byte, passwordLen[0])
		n, err = srcConn.Read(password)
		if err != nil || n == 0 {
			t.log.Printf("failed to read client password: %v", err)
			return
		}
		if string(username) != t.config.Username || string(password) != t.config.Password {
			t.log.Printf("invalid username or password")
			_, err = srcConn.Write([]byte{UserAuthVersion, Failure})
			if err != nil {
				t.log.Printf("failed to write auth failure status: %v", err)
				return
			}
			return
		}
		_, err = srcConn.Write([]byte{UserAuthVersion, Success})
		if err != nil {
			t.log.Printf("failed to write auth success status: %v", err)
			return
		}
	} else {
		authMethod = NoAuth
		if !contains(clientAuthMethods, NoAuth) {
			t.log.Printf("client does not support no auth")
			_, err = srcConn.Write([]byte{SocksVersion, NoAcceptableMethods})
			if err != nil {
				t.log.Printf("failed to write no acceptable methods: %v", err)
			}
			return
		}
		_, err = srcConn.Write([]byte{SocksVersion, authMethod})
		if err != nil {
			t.log.Printf("failed to write selected auth method: %v", err)
			return
		}
	}

	clientSocksVer = make([]byte, 1)
	n, err = srcConn.Read(clientSocksVer)
	if err != nil || n == 0 {
		t.log.Printf("failed to read socks version: %v", err)
		return
	}
	if clientSocksVer[0] != SocksVersion {
		t.log.Printf("invalid socks version: %d", clientSocksVer[0])
		return
	}
	command := make([]byte, 1)
	n, err = srcConn.Read(command)
	if err != nil || n == 0 {
		t.log.Printf("failed to read command: %v", err)
		return
	}
	// ignore the reserved byte
	_, err = srcConn.Read(make([]byte, 1))
	if err != nil {
		t.log.Printf("failed to read reserved byte: %v", err)
		return
	}
	clientDstAddrType := make([]byte, 1)
	n, err = srcConn.Read(clientDstAddrType)
	if err != nil || n == 0 {
		t.log.Printf("failed to read client destination address type: %v", err)
		return
	}
	var clientDstAddr []byte
	switch clientDstAddrType[0] {
	case IPv4:
		clientDstAddr = make([]byte, net.IPv4len)
	case IPv6:
		clientDstAddr = make([]byte, net.IPv6len)
	case DomainName:
		domainNameLen := make([]byte, 1)
		n, err = srcConn.Read(domainNameLen)
		if err != nil || n == 0 {
			t.log.Printf("failed to read domain name length: %v", err)
			return
		}
		clientDstAddr = make([]byte, domainNameLen[0])
	default:
		t.log.Printf("invalid client destination address type: %d", clientDstAddrType[0])
		return
	}
	n, err = srcConn.Read(clientDstAddr)
	if err != nil || n == 0 {
		t.log.Printf("failed to read client destination address: %v", err)
		return
	}
	clientDstPort := make([]byte, 2)
	n, err = srcConn.Read(clientDstPort)
	if err != nil || n == 0 {
		t.log.Printf("failed to read client destination port: %v", err)
		return
	}
	switch command[0] {
	case Connect:
		dialer := &net.Dialer{
			Timeout: time.Duration(t.config.Timeout) * time.Second,
		}
		if t.externalInterface != nil {
			dialer.Control = func(network, address string, c syscall.RawConn) error {
				return c.Control(func(fd uintptr) {
					unix.BindToDevice(int(fd), t.externalInterface.Name)
				})
			}
		}

		clientDst := net.JoinHostPort(string(clientDstAddr), strconv.Itoa(int(binary.BigEndian.Uint16(clientDstPort))))
		// t.log.Printf("connecting to %s", clientDst)
		dstConn, err := dialer.Dial("tcp", clientDst)
		if err != nil {
			// t.log.Printf("failed to connect to %s: %v", clientDst, err)
			_, err = srcConn.Write([]byte{SocksVersion, Failure, 0, IPv4, 0, 0, 0, 0, 0, 0})
			if err != nil {
				t.log.Printf("failed to write connect failure reply: %v", err)
				return
			}
			return
		}
		_, err = srcConn.Write([]byte{SocksVersion, Success, 0, IPv4, 0, 0, 0, 0, 0, 0})
		if err != nil {
			t.log.Printf("failed to write connect success reply: %v", err)
			return
		}
		t.proxy(srcConn, dstConn)
	case Bind:
		// TODO
		t.log.Printf("bind not implemented")
		return
	case UDPAssociate:
		// TODO
		t.log.Printf("udp associate not implemented")
		return
	default:
		t.log.Printf("invalid command: %d", command[0])
		return
	}

}

func (t *TCPServer) proxy(src, dst net.Conn) {
	defer src.Close()
	defer dst.Close()
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		_, err := io.Copy(src, dst)
		if err != nil {
			t.log.Printf("failed to forward data: %v", err)
		}
	}()

	go func() {
		defer wg.Done()
		_, err := io.Copy(dst, src)
		if err != nil {
			t.log.Printf("failed to forward data: %v", err)
		}
	}()

	wg.Wait()
}

// check if a byte array contains a byte
func contains(arr []byte, b byte) bool {
	for _, v := range arr {
		if v == b {
			return true
		}
	}
	return false
}
