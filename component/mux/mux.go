package mux

import (
	"context"
	"errors"
	"math/rand"
	"net"
	"sync"
	"time"

	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/log"
	"github.com/xtaci/smux"
)

var (
	clients []*Client
	once    sync.Once
)

type muxID uint32

type dialer func(context.Context, *C.Metadata) (net.Conn, error)

func generateMuxID() muxID {
	return muxID(rand.Uint32())
}

type smuxClientInfo struct {
	id             muxID
	client         *smux.Session
	lastActiveTime time.Time
	underlayConn   net.Conn
}

//Client is a smux client
type Client struct {
	sync.Mutex
	clientPool  map[muxID]*smuxClientInfo
	concurrency int
	timeout     time.Duration
	dial        dialer
}

// Config of mux
type Config struct {
	Concurrency int
	IdleTimeout int
}

func NewClient(config Config, connDialer dialer) (*Client, error) {

	client := &Client{
		concurrency: config.Concurrency,
		timeout:     time.Duration(config.IdleTimeout) * time.Second,
		clientPool:  make(map[muxID]*smuxClientInfo),
		dial:        connDialer,
	}

	clients = append(clients, client)
	once.Do(func() {
		go cleanLoop() // start clean loop
	})

	return client, nil
}

func (c *Client) DialConn(ctx context.Context, metadata *C.Metadata) (net.Conn, error) {
	createNewConn := func(info *smuxClientInfo) (net.Conn, error) {
		stream, err := info.client.OpenStream()
		info.lastActiveTime = time.Now()
		if err != nil {
			info.underlayConn.Close()
			info.client.Close()
			delete(c.clientPool, info.id)
			return nil, err
		}

		log.Debugln("[MUX] create connection to %s", metadata.RemoteAddress())
		return stream, nil
	}

	c.Lock()
	defer c.Unlock()
	for _, info := range c.clientPool {
		if info.client.IsClosed() {
			delete(c.clientPool, info.id)
			continue
		}
		if info.client.NumStreams() < c.concurrency {
			return createNewConn(info)
		}
	}

	info, err := c.newMuxClient(ctx, metadata)
	if err != nil {
		return nil, err
	}
	return createNewConn(info)
}

func (c *Client) newMuxClient(ctx context.Context, metadata *C.Metadata) (*smuxClientInfo, error) {
	// The mutex should be locked when this function is called
	id := generateMuxID()
	if _, found := c.clientPool[id]; found {
		return nil, errors.New("duplicated id")
	}

	conn, err := c.dial(ctx, metadata)
	if err != nil {
		return nil, err
	}

	smuxConfig := smux.DefaultConfig()
	//smuxConfig.KeepAliveDisabled = true
	client, err := smux.Client(conn, smuxConfig)
	info := &smuxClientInfo{
		client:         client,
		underlayConn:   conn,
		id:             id,
		lastActiveTime: time.Now(),
	}
	c.clientPool[id] = info
	return info, nil
}

func cleanLoop() {
	checkDuration := 30 * time.Second // check every 30 sec

	for {
		<-time.After(checkDuration)
		for _, c := range clients {
			c.Lock()
			for id, info := range c.clientPool {
				if info.client.IsClosed() {
					info.client.Close()
					info.underlayConn.Close()
					delete(c.clientPool, id)
				} else if info.client.NumStreams() == 0 && time.Now().Sub(info.lastActiveTime) > c.timeout {
					info.client.Close()
					info.underlayConn.Close()
					delete(c.clientPool, id)
				}
			}
			c.Unlock()
		}
	}

}
