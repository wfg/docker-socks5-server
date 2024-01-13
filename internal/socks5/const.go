package socks5

const (
	SocksVersion    uint8 = 5
	UserAuthVersion uint8 = 1
)

// Authentication methods
const (
	NoAuth              uint8 = 0
	UserAuth            uint8 = 2
	NoAcceptableMethods uint8 = 255
)

// Client destination address types
const (
	IPv4       uint8 = 1
	DomainName uint8 = 3
	IPv6       uint8 = 4
)

// Commands
const (
	_ uint8 = iota
	Connect
	Bind
	UDPAssociate
)

// Replies
const (
	Success uint8 = iota
	Failure
)

const (
	BufferSize int = 4 * 1024
)
