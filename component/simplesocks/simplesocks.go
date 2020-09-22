package simplesocks

import (
	"bytes"
	"net"

	C "github.com/Dreamacro/clash/constant"
)

// Conn is SimpleSocks Reader/Write Wrapper for SimpleSocks
type Conn struct {
	net.Conn
	Metadata       *C.Metadata
	addrParser     func(C.NetWork) byte
	addrSerializer func(*C.Metadata) []byte
	headerSent     bool
}

// Read implements io.Reader
func (c *Conn) Read(p []byte) (int, error) {
	return c.Conn.Read(p)
}

func (c *Conn) writeHeader() error {
	buf := &bytes.Buffer{}
	buf.WriteByte(c.addrParser(c.Metadata.NetWork))
	buf.Write(c.addrSerializer(c.Metadata))

	if _, err := c.Conn.Write(buf.Bytes()); err != nil {
		return err
	}

	c.headerSent = true
	return nil
}

// Write implements io.Writer
func (c *Conn) Write(p []byte) (n int, err error) {
	if !c.headerSent {
		if err := c.writeHeader(); err != nil {
			return 0, err
		}
	}

	n, err = c.Conn.Write(p)
	return n, err
}

func NewConn(underlayConn net.Conn, metadata *C.Metadata, addrParser func(C.NetWork) byte, addrSerializer func(*C.Metadata) []byte) *Conn {
	return &Conn{Conn: underlayConn,
		Metadata:       metadata,
		addrParser:     addrParser,
		addrSerializer: addrSerializer,
	}
}
