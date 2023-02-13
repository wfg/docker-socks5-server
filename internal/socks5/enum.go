package socks5

const (
	SocksVersion = uint8(5)
)

const (
	Connect      = uint8(1)
	Bind         = uint8(2)
	UDPAssociate = uint8(3)
	Ipv4Address  = uint8(1)
	FqdnAddress  = uint8(3)
	Ipv6Address  = uint8(4)
)

const (
	SuccessReply uint8 = iota
	FailureReply
	RuleFailure
	NetworkUnreachable
	HostUnreachable
	ConnectionRefused
	TTLExpired
	CommandNotSupported
	AddrTypeNotSupported
)

const (
	NoAuth          = uint8(0)
	NoAcceptable    = uint8(255)
	UserAuth        = uint8(2)
	UserAuthVersion = uint8(1)
	AuthSuccess     = uint8(0)
	AuthFailure     = uint8(1)
)

const (
	BufferSize int = 4 * 1024
)

const (
	IPv4       uint8 = 1
	DomainName uint8 = 3
	IPv6       uint8 = 4
)
