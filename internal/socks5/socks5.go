package socks5

import (
	"log"
	"net"
	"os"
)

type Config struct {
	InboundAddress    string
	Username          string
	Password          string
	OutboundInterface string
	Timeout           int
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

	udpLogger := log.New(os.Stdout, "", 0)
	udpLogger.SetOutput(newLogWriter("UDP"))
	u := &UDPServer{
		log:               udpLogger,
		config:            config,
		externalInterface: externalInterface,
	}
	udpConn := u.Start()

	tcpLogger := log.New(os.Stdout, "", 0)
	tcpLogger.SetOutput(newLogWriter("TCP"))
	t := &TCPServer{
		log:               tcpLogger,
		config:            config,
		udpConn:           udpConn,
		externalInterface: externalInterface,
	}
	t.Start()
}
