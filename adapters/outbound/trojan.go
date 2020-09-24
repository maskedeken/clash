package outbound

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strconv"

	"github.com/Dreamacro/clash/component/dialer"
	"github.com/Dreamacro/clash/component/mux"
	"github.com/Dreamacro/clash/component/trojan"
	"github.com/Dreamacro/clash/component/vmess"
	C "github.com/Dreamacro/clash/constant"
)

type Trojan struct {
	*Base
	instance *trojan.Trojan
	mux      *mux.Client
	option   *TrojanOption
}

type TrojanOption struct {
	Name           string            `proxy:"name"`
	Server         string            `proxy:"server"`
	Port           int               `proxy:"port"`
	Password       string            `proxy:"password"`
	ALPN           []string          `proxy:"alpn,omitempty"`
	SNI            string            `proxy:"sni,omitempty"`
	SkipCertVerify bool              `proxy:"skip-cert-verify,omitempty"`
	UDP            bool              `proxy:"udp,omitempty"`
	Mux            int               `proxy:"mux,omitempty"`
	Network        string            `proxy:"network,omitempty"`
	WSPath         string            `proxy:"ws-path,omitempty"`
	WSHeaders      map[string]string `proxy:"ws-headers,omitempty"`
}

func (t *Trojan) streamConn(c net.Conn) (net.Conn, error) {
	var err error

	switch t.option.Network {
	case "ws":
		host, port, _ := net.SplitHostPort(t.addr)
		wsOpts := &vmess.WebsocketConfig{
			Host: host,
			Port: port,
			Path: t.option.WSPath,
		}

		if len(t.option.WSHeaders) != 0 {
			header := http.Header{}
			for key, value := range t.option.WSHeaders {
				header.Add(key, value)
			}
			wsOpts.Headers = header
		}

		wsOpts.TLS = true
		wsOpts.SessionCache = getClientSessionCache()
		wsOpts.SkipCertVerify = t.option.SkipCertVerify
		if t.option.SNI != "" {
			wsOpts.ServerName = t.option.SNI
		} else {
			wsOpts.ServerName = t.option.Server
		}

		c, err = vmess.StreamWebsocketConn(c, wsOpts)

	default:
		c, err = t.instance.StreamConn(c)
	}

	if err != nil {
		return nil, fmt.Errorf("%s connect error: %w", t.addr, err)
	}

	return c, nil
}

func (t *Trojan) StreamConn(c net.Conn, metadata *C.Metadata) (net.Conn, error) {
	c, err := t.streamConn(c)
	if err != nil {
		return nil, err
	}

	err = t.instance.WriteHeader(c, trojan.CommandTCP, serializesSocksAddr(metadata))
	return c, err
}

func (t *Trojan) DialContext(ctx context.Context, metadata *C.Metadata) (C.Conn, error) {
	if t.mux != nil {
		c, err := t.mux.DialConn(ctx, metadata)
		if err != nil {
			return nil, err
		}

		return NewConn(&SimpleSocksConn{Conn: c,
			Metadata: metadata,
		}, t), nil
	}

	c, err := dialer.DialContext(ctx, "tcp", t.addr)
	if err != nil {
		return nil, fmt.Errorf("%s connect error: %w", t.addr, err)
	}
	tcpKeepAlive(c)
	c, err = t.StreamConn(c, metadata)
	if err != nil {
		return nil, err
	}

	return NewConn(c, t), err
}

func (t *Trojan) DialUDP(metadata *C.Metadata) (C.PacketConn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), tcpTimeout)
	defer cancel()

	if t.mux != nil {
		c, err := t.mux.DialConn(ctx, metadata)
		if err != nil {
			return nil, err
		}

		pc := t.instance.PacketConn(&SimpleSocksConn{Conn: c, Metadata: metadata})
		return newPacketConn(pc, t), err
	}

	c, err := dialer.DialContext(ctx, "tcp", t.addr)
	if err != nil {
		return nil, fmt.Errorf("%s connect error: %w", t.addr, err)
	}
	tcpKeepAlive(c)
	c, err = t.streamConn(c)
	if err != nil {
		return nil, err
	}

	err = t.instance.WriteHeader(c, trojan.CommandUDP, serializesSocksAddr(metadata))
	if err != nil {
		return nil, err
	}

	pc := t.instance.PacketConn(c)
	return newPacketConn(pc, t), err
}

func (t *Trojan) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]string{
		"type": t.Type().String(),
	})
}

func NewTrojan(option TrojanOption) (*Trojan, error) {
	addr := net.JoinHostPort(option.Server, strconv.Itoa(option.Port))

	tOption := &trojan.Option{
		Password:           option.Password,
		ALPN:               option.ALPN,
		ServerName:         option.Server,
		SkipCertVerify:     option.SkipCertVerify,
		ClientSessionCache: getClientSessionCache(),
	}

	if option.SNI != "" {
		tOption.ServerName = option.SNI
	}

	t := &Trojan{
		Base: &Base{
			name: option.Name,
			addr: addr,
			tp:   C.Trojan,
			udp:  option.UDP,
		},
		instance: trojan.New(tOption),
		option:   &option,
	}

	if option.Mux > 0 { // enable mux
		muxClient, _ := mux.NewClient(mux.Config{Concurrency: option.Mux, IdleTimeout: 30}, func(ctx context.Context, metadata *C.Metadata) (net.Conn, error) {
			c, err := dialer.DialContext(ctx, "tcp", t.addr)
			if err != nil {
				return nil, fmt.Errorf("%s connect error: %w", t.addr, err)
			}
			tcpKeepAlive(c)
			c, err = t.streamConn(c)
			if err != nil {
				return nil, err
			}

			err = t.instance.WriteHeader(c, trojan.CommandMUX, serializesSocksAddr(metadata))
			if err != nil {
				return nil, err
			}

			return c, nil
		})
		t.mux = muxClient
	}

	return t, nil
}
