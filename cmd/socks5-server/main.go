package main

import (
	"flag"

	"github.com/wfg/socks5-server/internal/socks5"
)

func main() {
	config := socks5.Config{}
	flag.StringVar(&config.ListenAddress, "l", ":1080", "local address")
	flag.StringVar(&config.Username, "u", "", "username")
	flag.StringVar(&config.Password, "p", "", "password")
	flag.StringVar(&config.ExternalInterface, "iface", "", "specified interface")
	flag.IntVar(&config.Timeout, "t", 30, "dial timeout in seconds")
	flag.BoolVar(&config.Debug, "debug", false, "enable debug logging")
	flag.Parse()

	socks5.StartServer(config)
}
