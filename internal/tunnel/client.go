package tunnel

import (
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"lucy/internal/config"
	"lucy/internal/proto"
	"lucy/internal/transport" // New transport package
)

// Client manages the tunnel connection with auto-reconnect.
type Client struct {
	Config    *config.Config
	TLSConfig *tls.Config
	Logger    *log.Logger

	conn      net.Conn
	writer    *proto.FrameWriter
	connected int32 // atomic

	channels   map[uint16]*clientChannel
	chanMu     sync.Mutex
	nextChanID uint32

	connectEvents map[uint16]chan bool
	eventMu       sync.Mutex
}

type clientChannel struct {
	id     uint16
	conn   net.Conn
	closed int32 // atomic
}

// NewClient creates a new tunnel client.
func NewClient(cfg *config.Config, tlsCfg *tls.Config, logger *log.Logger) *Client {
	return &Client{
		Config:        cfg,
		TLSConfig:     tlsCfg,
		Logger:        logger,
		channels:      make(map[uint16]*clientChannel),
		connectEvents: make(map[uint16]chan bool),
		nextChanID:    1,
	}
}

// Connected returns true if the tunnel is active.
func (c *Client) Connected() bool {
	return atomic.LoadInt32(&c.connected) == 1
}

// Connect establishes the tunnel connection.
func (c *Client) Connect() error {
	c.logf("Connecting to %s via %s", c.Config.Client.Server, c.Config.Transport.Type)

	// Dial the underlying TCP connection to the "server" address
	// Note: In HTTPS/SNI rotation mode, "server" acts as the default/fallback destination IP
	// if DNS resolution isn't handled per-host.
	// For now, we assume Config.Client.Server is the IP:Port or Host:Port of the tunnel server.
	rawConn, err := net.DialTimeout("tcp", c.Config.Client.Server, 30*time.Second)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}

	// Handshake
	tr := transport.New(c.Config, c.TLSConfig)
	
	// ServerHost is used for SNI fallback if list is empty
	serverHost, _, _ := net.SplitHostPort(c.Config.Client.Server)
	
	tunnelConn, err := tr.ClientHandshake(rawConn, serverHost)
	if err != nil {
		rawConn.Close()
		return fmt.Errorf("handshake: %w", err)
	}

	c.conn = tunnelConn
	c.writer = proto.NewFrameWriter(tunnelConn)
	atomic.StoreInt32(&c.connected, 1)
	c.logf("Connected - tunnel active")

	// Start health monitor
	go c.monitorConnection()

	return nil
}

func (c *Client) monitorConnection() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	failCount := 0
	const maxFails = 3

	for {
		if !c.Connected() {
			return
		}

		select {
		case <-ticker.C:
			rtt, err := c.Ping()
			if err != nil {
				c.logf("Health check failed: %v", err)
				failCount++
			} else {
				if rtt > 2*time.Second {
					c.logf("High latency detected: %v", rtt)
					failCount++
				} else {
					failCount = 0
				}
			}

			if failCount >= maxFails {
				c.logf("Connection unhealthy (fails=%d), reconnecting...", failCount)
				c.Disconnect()
				return
			}
		}
	}
}

// RunReceiver reads frames from the server and dispatches them. Blocks until connection lost.
func (c *Client) RunReceiver() {
	defer func() {
		atomic.StoreInt32(&c.connected, 0)
	}()

	for {
		frame, err := proto.ReadFrame(c.conn)
		if err != nil {
			if err != io.EOF {
				c.logf("Receiver error: %v", err)
			}
			return
		}
		c.handleFrame(frame)
	}
}

func (c *Client) handleFrame(f proto.Frame) {
	switch f.Type {
	case proto.FrameConnectOK:
		c.eventMu.Lock()
		ch, ok := c.connectEvents[f.ChannelID]
		c.eventMu.Unlock()
		if ok {
			ch <- true
		}

	case proto.FrameConnectFail:
		c.eventMu.Lock()
		ch, ok := c.connectEvents[f.ChannelID]
		c.eventMu.Unlock()
		if ok {
			ch <- false
		}

	case proto.FrameData:
		c.chanMu.Lock()
		cc, ok := c.channels[f.ChannelID]
		c.chanMu.Unlock()
		if ok && cc != nil && atomic.LoadInt32(&cc.closed) == 0 {
			cc.conn.Write(f.Payload)
		}

	case proto.FrameClose:
		c.CloseChannel(f.ChannelID)

	case proto.FramePong:
		c.eventMu.Lock()
		ch, ok := c.connectEvents[f.ChannelID]
		c.eventMu.Unlock()
		if ok {
			ch <- true
		}
	}
}

// OpenChannel requests a new tunnel channel to host:port.
func (c *Client) OpenChannel(host string, port uint16) (uint16, bool) {
	if !c.Connected() {
		return 0, false
	}

	channelID := uint16(atomic.AddUint32(&c.nextChanID, 1) - 1)
	if channelID == 0 {
		channelID = uint16(atomic.AddUint32(&c.nextChanID, 1) - 1)
	}

	resultCh := make(chan bool, 1)
	c.eventMu.Lock()
	c.connectEvents[channelID] = resultCh
	c.eventMu.Unlock()

	payload := proto.MakeConnectPayload(host, port)
	if err := c.writer.WriteFrame(proto.Frame{
		Type:      proto.FrameConnect,
		ChannelID: channelID,
		Payload:   payload,
	}); err != nil {
		c.eventMu.Lock()
		delete(c.connectEvents, channelID)
		c.eventMu.Unlock()
		return channelID, false
	}

	select {
	case success := <-resultCh:
		c.eventMu.Lock()
		delete(c.connectEvents, channelID)
		c.eventMu.Unlock()
		return channelID, success
	case <-time.After(30 * time.Second):
		c.eventMu.Lock()
		delete(c.connectEvents, channelID)
		c.eventMu.Unlock()
		return channelID, false
	}
}

// RegisterChannel adds a local connection to the channel map.
func (c *Client) RegisterChannel(channelID uint16, conn net.Conn) {
	c.chanMu.Lock()
	c.channels[channelID] = &clientChannel{id: channelID, conn: conn}
	c.chanMu.Unlock()
}

// SendData sends data on a channel.
func (c *Client) SendData(channelID uint16, data []byte) error {
	return c.writer.WriteFrame(proto.Frame{
		Type:      proto.FrameData,
		ChannelID: channelID,
		Payload:   data,
	})
}

// CloseChannelRemote tells the server to close a channel.
func (c *Client) CloseChannelRemote(channelID uint16) {
	c.writer.WriteFrame(proto.Frame{
		Type:      proto.FrameClose,
		ChannelID: channelID,
	})
}

// CloseChannel closes a local channel.
func (c *Client) CloseChannel(channelID uint16) {
	c.chanMu.Lock()
	cc, ok := c.channels[channelID]
	if ok {
		delete(c.channels, channelID)
	}
	c.chanMu.Unlock()

	if ok && cc != nil {
		atomic.StoreInt32(&cc.closed, 1)
		cc.conn.Close()
	}
}

// Disconnect closes the tunnel and all channels.
func (c *Client) Disconnect() {
	atomic.StoreInt32(&c.connected, 0)

	c.chanMu.Lock()
	ids := make([]uint16, 0, len(c.channels))
	for id := range c.channels {
		ids = append(ids, id)
	}
	c.chanMu.Unlock()

	for _, id := range ids {
		c.CloseChannel(id)
	}

	if c.conn != nil {
		c.conn.Close()
	}
}

// InjectConn allows injecting an already-established connection (used by debug tools).
func (c *Client) InjectConn(conn net.Conn) {
	c.conn = conn
	c.writer = proto.NewFrameWriter(conn)
	atomic.StoreInt32(&c.connected, 1)
}

func (c *Client) logf(format string, args ...interface{}) {
	if c.Logger != nil {
		c.Logger.Printf(format, args...)
	}
}

// Ping sends a PING frame and waits for PONG. Returns RTT.
func (c *Client) Ping() (time.Duration, error) {
	if !c.Connected() {
		return 0, fmt.Errorf("not connected")
	}

	// Use channelID 0xFFFF for ping
	channelID := uint16(0xFFFF)
	resultCh := make(chan bool, 1)

	c.eventMu.Lock()
	c.connectEvents[channelID] = resultCh
	c.eventMu.Unlock()

	// Embed timestamp in payload
	payload := make([]byte, 8)
	binary.BigEndian.PutUint64(payload, uint64(time.Now().UnixNano()))

	start := time.Now()
	if err := c.writer.WriteFrame(proto.Frame{
		Type:      proto.FramePing,
		ChannelID: channelID,
		Payload:   payload,
	}); err != nil {
		c.eventMu.Lock()
		delete(c.connectEvents, channelID)
		c.eventMu.Unlock()
		return 0, err
	}

	select {
	case <-resultCh:
		rtt := time.Since(start)
		c.eventMu.Lock()
		delete(c.connectEvents, channelID)
		c.eventMu.Unlock()
		return rtt, nil
	case <-time.After(10 * time.Second):
		c.eventMu.Lock()
		delete(c.connectEvents, channelID)
		c.eventMu.Unlock()
		return 0, fmt.Errorf("ping timeout")
	}
}
