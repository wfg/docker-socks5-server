package socks5

import (
	"log"
	"net"
)

type Config struct {
	ListenAddress     string
	Username          string
	Password          string
	ExternalInterface string
	Timeout           int
	Debug             bool
}

func StartServer(config Config) {
	var externalInterface *net.Interface
	var err error
	if config.ExternalInterface == "" {
		externalInterface = nil
	} else {
		externalInterface, err = net.InterfaceByName(config.ExternalInterface)
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
