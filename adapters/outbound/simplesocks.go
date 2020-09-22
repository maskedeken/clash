package outbound

import (
	"bytes"
	"net"

	C "github.com/Dreamacro/clash/constant"
)

var (
	CommandTCP byte = 1
	CommandUDP byte = 3
)

// SimpleSocksConn is SimpleSocks Reader/Write Wrapper for SimpleSocks
type SimpleSocksConn struct {
	net.Conn
	Metadata   *C.Metadata
	headerSent bool
}

// Read implements io.Reader
func (c *SimpleSocksConn) Read(p []byte) (int, error) {
	return c.Conn.Read(p)
}

func (c *SimpleSocksConn) writeHeader() error {
	command := CommandTCP
	if c.Metadata.NetWork == C.UDP {
		command = CommandUDP
	}
	buf := &bytes.Buffer{}
	buf.WriteByte(command)
	buf.Write(serializesSocksAddr(c.Metadata))

	if _, err := c.Conn.Write(buf.Bytes()); err != nil {
		return err
	}

	c.headerSent = true
	return nil
}

// Write implements io.Writer
func (c *SimpleSocksConn) Write(p []byte) (n int, err error) {
	if !c.headerSent {
		if err := c.writeHeader(); err != nil {
			return 0, err
		}
	}

	n, err = c.Conn.Write(p)
	return n, err
}
