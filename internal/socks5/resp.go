package socks5

import (
	"bytes"
	"encoding/binary"
	"net"
)

/*
*

	+----+-----+-------+------+----------+----------+
	|VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
	+----+-----+-------+------+----------+----------+
	| 1  |  1  | X'00' |  1   | Variable |    2     |
	+----+-----+-------+------+----------+----------+
*/
func respUDP(conn net.Conn, bindAddr *net.UDPAddr) {
	resp := []byte{SocksVersion, Success, 0x00, 0x01}
	buffer := bytes.NewBuffer(resp)
	binary.Write(buffer, binary.BigEndian, bindAddr.IP.To4())
	binary.Write(buffer, binary.BigEndian, uint16(bindAddr.Port))
	conn.Write(buffer.Bytes())
}
