package mux

import (
	"context"
	"errors"
	"math/rand"
	"net"
	"sync"
	"time"

	"github.com/xtaci/smux"
)

type muxID uint32

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
	ctx         context.Context
	cancel      context.CancelFunc
}

// Config of mux
type Config struct {
	Concurrency int
	IdleTimeout int
}

func NewClient(config Config) (*Client, error) {
	ctx := context.Background()
	ctx, cancel := context.WithCancel(ctx)
	client := &Client{
		concurrency: config.Concurrency,
		timeout:     time.Duration(config.IdleTimeout) * time.Second,
		clientPool:  make(map[muxID]*smuxClientInfo),
		ctx:         ctx,
		cancel:      cancel,
	}
	go client.cleanLoop()
	return client, nil
}

func (c *Client) NewMuxConn(dialer func() (net.Conn, error)) (net.Conn, error) {
	createNewConn := func(info *smuxClientInfo) (net.Conn, error) {
		rwc, err := info.client.Open()
		info.lastActiveTime = time.Now()
		if err != nil {
			info.underlayConn.Close()
			info.client.Close()
			delete(c.clientPool, info.id)
			return nil, err
		}

		return &Conn{rwc: rwc, Conn: info.underlayConn}, nil
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

	info, err := c.newMuxClient(dialer)
	if err != nil {
		return nil, err
	}
	return createNewConn(info)
}

func (c *Client) Close() error {
	c.cancel()
	c.Lock()
	defer c.Unlock()
	for _, info := range c.clientPool {
		info.client.Close()
	}
	return nil
}

func (c *Client) newMuxClient(dialer func() (net.Conn, error)) (*smuxClientInfo, error) {
	// The mutex should be locked when this function is called
	id := generateMuxID()
	if _, found := c.clientPool[id]; found {
		return nil, errors.New("duplicated id")
	}

	conn, err := dialer()
	if err != nil {
		return nil, errors.New("mux failed to dial")
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

func (c *Client) cleanLoop() {
	checkDuration := c.timeout / 4
	for {
		select {
		case <-time.After(checkDuration):
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
		case <-c.ctx.Done():
			c.Lock()
			for id, info := range c.clientPool {
				info.client.Close()
				info.underlayConn.Close()
				delete(c.clientPool, id)
			}
			c.Unlock()
			return
		}
	}
}
