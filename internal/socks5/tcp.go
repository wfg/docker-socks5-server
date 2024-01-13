package socks5

import (
	"encoding/binary"
	"io"
	"net"
	"strconv"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// Tcp server struct
type TCPServer struct {
	log               *Logger
	config            Config
	externalInterface *net.Interface
}

func (t *TCPServer) Start() {
	l, err := net.Listen("tcp", t.config.ListenAddress)
	if err != nil {
		t.log.Fatalf("failed to listen: %v", err)
	}
	t.log.Printf("listening on %s", t.config.ListenAddress)
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

	// Receiving the following on initial connection:
	// +----+----------+----------+
	// |VER | NMETHODS | METHODS  |
	// +----+----------+----------+
	// | 1  |    1     | 1 to 255 |
	// +----+----------+----------+

	// VER is the first octet and must be X'05' for SOCKS5.
	clientSocksVer := make([]byte, 1)
	n, err := srcConn.Read(clientSocksVer)
	if n == 0 || err != nil {
		t.log.Debugf("failed to read socks version on client greeting: %v", err)
		return
	}
	if clientSocksVer[0] != SocksVersion {
		t.log.Debugf("invalid socks version: %d", clientSocksVer[0])
		return
	}

	// NMETHODS is the second octet and is the number of octets in the following METHODS.
	numClientAuthMethods := make([]byte, 1)
	n, err = srcConn.Read(numClientAuthMethods)
	if n == 0 || err != nil {
		t.log.Debugf("failed to read number of client auth methods: %v", err)
		return
	}
	clientAuthMethods := make([]byte, numClientAuthMethods[0])
	n, err = srcConn.Read(clientAuthMethods)
	if n == 0 || err != nil {
		t.log.Debugf("failed to read client auth methods: %v", err)
		return
	}

	// I am only supporting 'no authentication' and 'username/password authentication' methods.
	// Their values are X'00' and X'02' respectively. The following is returned to the client:
	// +----+--------+
	// |VER | METHOD |
	// +----+--------+
	// | 1  |   1    |
	// +----+--------+

	if t.config.Username != "" && t.config.Password != "" {
		if !contains(clientAuthMethods, UserAuth) {
			t.log.Debugf("client does not support username/password authentication")
			_, err = srcConn.Write([]byte{SocksVersion, NoAcceptableMethods})
			if err != nil {
				t.log.Debugf("failed to write no acceptable methods: %v", err)
			}
			return
		}
		_, err = srcConn.Write([]byte{SocksVersion, UserAuth})
		if err != nil {
			t.log.Debugf("failed to write selected auth method: %v", err)
			return
		}

		// After agreeing on the username/password authentication method, the client sends the following:
		// +----+------+----------+------+----------+
		// |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
		// +----+------+----------+------+----------+
		// | 1  |  1   | 1 to 255 |  1   | 1 to 255 |
		// +----+------+----------+------+----------+

		// VER is the first octet and must be X'01' for username/password authentication.
		clientUserAuthVersion := make([]byte, 1)
		n, err = srcConn.Read(clientUserAuthVersion)
		if n == 0 || err != nil {
			t.log.Debugf("failed to read user/pass auth version: %v", err)
			return
		}
		if clientUserAuthVersion[0] != UserAuthVersion {
			t.log.Debugf("invalid user/pass auth version: %d", clientUserAuthVersion[0])
			return
		}

		// ULEN is the next octet and it is the number of octets required for the username.
		usernameLen := make([]byte, 1)
		n, err = srcConn.Read(usernameLen)
		if n == 0 || err != nil {
			t.log.Debugf("failed to read client username length: %v", err)
			return
		}
		// UNAME is the username itself and requires ULEN octets.
		username := make([]byte, usernameLen[0])
		n, err = srcConn.Read(username)
		if n == 0 || err != nil {
			t.log.Debugf("failed to read client username: %v", err)
			return
		}

		// PLEN is the next octet and it is the number of octets required for the username.
		passwordLen := make([]byte, 1)
		n, err = srcConn.Read(passwordLen)
		if n == 0 || err != nil {
			t.log.Debugf("failed to read client password length: %v", err)
			return
		}
		// PASSWD is the password itself and requires PLEN octets.
		password := make([]byte, passwordLen[0])
		n, err = srcConn.Read(password)
		if n == 0 || err != nil {
			t.log.Debugf("failed to read client password: %v", err)
			return
		}

		// Once the username and password are read, the following is returned to the client:
		// +----+--------+
		// |VER | STATUS |
		// +----+--------+
		// | 1  |   1    |
		// +----+--------+

		// VER must be X'01', and STATUS of X'00' indicates success while X'01' indicates failure.
		if string(username) != t.config.Username || string(password) != t.config.Password {
			t.log.Printf("invalid username or password")
			_, err = srcConn.Write([]byte{UserAuthVersion, Failure})
			if err != nil {
				t.log.Debugf("failed to write auth failure status: %v", err)
				return
			}
			return
		}
		_, err = srcConn.Write([]byte{UserAuthVersion, Success})
		if err != nil {
			t.log.Debugf("failed to write auth success status: %v", err)
			return
		}
	} else {
		if !contains(clientAuthMethods, NoAuth) {
			t.log.Printf("client does not support no auth")
			_, err = srcConn.Write([]byte{SocksVersion, NoAcceptableMethods})
			if err != nil {
				t.log.Debugf("failed to write no acceptable methods: %v", err)
			}
			return
		}
		_, err = srcConn.Write([]byte{SocksVersion, NoAuth})
		if err != nil {
			t.log.Debugf("failed to write selected auth method: %v", err)
			return
		}
	}

	// Once authentication negotiation is complete, the client sends its request details.
	// +----+-----+-------+------+----------+----------+
	// |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
	// +----+-----+-------+------+----------+----------+
	// | 1  |  1  | X'00' |  1   | Variable |    2     |
	// +----+-----+-------+------+----------+----------+
	// Where:
	// o  VER    protocol version: X'05'
	// o  CMD
	//    o  CONNECT X'01'
	//    o  BIND X'02'
	//    o  UDP ASSOCIATE X'03'
	// o  RSV    RESERVED
	// o  ATYP   address type of following address
	//    o  IP V4 address: X'01'
	//    o  DOMAINNAME: X'03'
	//    o  IP V6 address: X'04'
	// o  DST.ADDR       desired destination address
	// o  DST.PORT desired destination port in network octet order
	clientSocksVer = make([]byte, 1)
	n, err = srcConn.Read(clientSocksVer)
	if n == 0 || err != nil {
		t.log.Debugf("failed to read socks version on client connection request: %v", err)
		return
	}
	if clientSocksVer[0] != SocksVersion {
		t.log.Debugf("invalid socks version: %d", clientSocksVer[0])
		return
	}
	command := make([]byte, 1)
	n, err = srcConn.Read(command)
	if n == 0 || err != nil {
		t.log.Debugf("failed to read command: %v", err)
		return
	}
	// ignore the reserved byte
	n, err = srcConn.Read(make([]byte, 1))
	if n == 0 || err != nil {
		t.log.Debugf("failed to read reserved byte: %v", err)
		return
	}
	clientDstAddrType := make([]byte, 1)
	n, err = srcConn.Read(clientDstAddrType)
	if n == 0 || err != nil {
		t.log.Debugf("failed to read client destination address type: %v", err)
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
		if n == 0 || err != nil {
			t.log.Debugf("failed to read domain name length: %v", err)
			return
		}
		clientDstAddr = make([]byte, domainNameLen[0])
	default:
		t.log.Printf("invalid client destination address type: %d", clientDstAddrType[0])
		return
	}
	n, err = srcConn.Read(clientDstAddr)
	if n == 0 || err != nil {
		t.log.Debugf("failed to read client destination address: %v", err)
		return
	}
	clientDstPort := make([]byte, 2)
	n, err = srcConn.Read(clientDstPort)
	if n == 0 || err != nil {
		t.log.Debugf("failed to read client destination port: %v", err)
		return
	}

	// After the request is received, the following is sent to the client:
	// +----+-----+-------+------+----------+----------+
	// |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
	// +----+-----+-------+------+----------+----------+
	// | 1  |  1  | X'00' |  1   | Variable |    2     |
	// +----+-----+-------+------+----------+----------+

	// Only CONNECT is supported.
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
		// t.log.Debugf("connecting to %s", clientDst)
		clientDstConn, err := dialer.Dial("tcp", clientDst)

		// Once the connection is established, the client is sent the following:
		// +----+-----+-------+------+----------+----------+
		// |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
		// +----+-----+-------+------+----------+----------+
		// | 1  |  1  | X'00' |  1   | Variable |    2     |
		// +----+-----+-------+------+----------+----------+
		// Where:
		//   o  VER    protocol version: X'05'
		//   o  REP    Reply field:
		//      o  X'00' succeeded
		//      o  X'01' general SOCKS server failure
		//   o  RSV    RESERVED
		//   o  ATYP   address type of following address
		//      o  IP V4 address: X'01'
		//      o  DOMAINNAME: X'03'
		//      o  IP V6 address: X'04'
		//   o  BND.ADDR       server bound address
		//   o  BND.PORT       server bound port in network octet order
		// Fields marked RESERVED (RSV) must be set to X'00'.

		if err != nil {
			// t.log.Debugf("failed to connect to %s: %v", clientDst, err)
			_, err = srcConn.Write([]byte{SocksVersion, Failure, 0, IPv4, 0, 0, 0, 0, 0, 0})
			if err != nil {
				t.log.Debugf("failed to write connect failure reply: %v", err)
				return
			}
			return
		}
		_, err = srcConn.Write([]byte{SocksVersion, Success, 0, IPv4, 0, 0, 0, 0, 0, 0})
		if err != nil {
			t.log.Debugf("failed to write connect success reply: %v", err)
			return
		}
		t.proxy(srcConn, clientDstConn)
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
			t.log.Debugf("failed to forward data: %v", err)
		}
	}()

	go func() {
		defer wg.Done()
		_, err := io.Copy(dst, src)
		if err != nil {
			t.log.Debugf("failed to forward data: %v", err)
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
