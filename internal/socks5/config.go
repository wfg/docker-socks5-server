package socks5

type Config struct {
	InboundAddress    string
	Username          string
	Password          string
	OutboundInterface string
	Timeout           int
}
