package socks5

import (
	"log"
	"net"
)

type Config struct {
	InboundAddress    string
	Username          string
	Password          string
	OutboundInterface string
	Timeout           int
	Debug             bool
}

func StartServer(config Config) {
	var externalInterface *net.Interface
	var err error
	if config.OutboundInterface == "" {
		externalInterface = nil
	} else {
		externalInterface, err = net.InterfaceByName(config.OutboundInterface)
		if err != nil {
			log.Fatalln("unable to get external interface", err)
		}
	}
	tcpLogger := NewLogger("TCP", config.Debug)
	t := &TCPServer{
		log:               tcpLogger,
		config:            config,
		externalInterface: externalInterface,
	}
	t.Start()
}
