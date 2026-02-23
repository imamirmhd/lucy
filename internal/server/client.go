package server

import (
	"fmt"
	"lucy/internal/flog"
	"lucy/internal/pkg/hash"
	"lucy/internal/protocol"
	"lucy/internal/tnet"
	"sync"
)

// Client implements tnet.StreamProvider for the server side.
// It opens streams on accepted client connections to request
// the remote client to dial out on behalf of the server.
type Client struct {
	conns    []tnet.Conn
	mu       sync.Mutex
	idx      int
	udpStrms map[uint64]tnet.Strm
	udpMu    sync.RWMutex
}

func NewClient() *Client {
	return &Client{
		udpStrms: make(map[uint64]tnet.Strm),
	}
}

func (c *Client) AddConn(conn tnet.Conn) {
	c.mu.Lock()
	c.conns = append(c.conns, conn)
	c.mu.Unlock()
}

func (c *Client) nextConn() (tnet.Conn, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	n := len(c.conns)
	if n == 0 {
		return nil, fmt.Errorf("no connections available")
	}

	// Try up to n connections, pruning dead ones
	for range n {
		idx := c.idx % len(c.conns)
		c.idx++

		conn := c.conns[idx]
		if conn.IsClosed() {
			// Remove dead connection by swapping with last
			last := len(c.conns) - 1
			c.conns[idx] = c.conns[last]
			c.conns[last] = nil // help GC
			c.conns = c.conns[:last]
			flog.Debugf("pruned dead connection from pool, %d remaining", len(c.conns))
			if len(c.conns) == 0 {
				return nil, fmt.Errorf("no live connections available")
			}
			// Adjust index since we swapped
			if c.idx > 0 {
				c.idx--
			}
			continue
		}
		return conn, nil
	}
	return nil, fmt.Errorf("no live connections available")
}

func (c *Client) TCP(addr string) (tnet.Strm, error) {
	conn, err := c.nextConn()
	if err != nil {
		return nil, err
	}

	strm, err := conn.OpenStrm()
	if err != nil {
		flog.Debugf("server-client: failed to open stream: %v", err)
		return nil, err
	}

	tAddr, err := tnet.NewAddr(addr)
	if err != nil {
		strm.Close()
		return nil, err
	}

	p := protocol.Proto{Type: protocol.PTCP, Addr: tAddr}
	if err := p.Write(strm); err != nil {
		strm.Close()
		return nil, err
	}

	flog.Debugf("server-client: TCP stream %d opened for %s", strm.SID(), addr)
	return strm, nil
}

func (c *Client) UDP(lAddr, tAddr string) (tnet.Strm, bool, uint64, error) {
	key := hash.AddrPair(lAddr, tAddr)

	c.udpMu.RLock()
	if strm, exists := c.udpStrms[key]; exists {
		c.udpMu.RUnlock()
		return strm, false, key, nil
	}
	c.udpMu.RUnlock()

	conn, err := c.nextConn()
	if err != nil {
		return nil, false, 0, err
	}

	strm, err := conn.OpenStrm()
	if err != nil {
		return nil, false, 0, err
	}

	taddr, err := tnet.NewAddr(tAddr)
	if err != nil {
		strm.Close()
		return nil, false, 0, err
	}

	p := protocol.Proto{Type: protocol.PUDP, Addr: taddr}
	if err := p.Write(strm); err != nil {
		strm.Close()
		return nil, false, 0, err
	}

	c.udpMu.Lock()
	c.udpStrms[key] = strm
	c.udpMu.Unlock()

	return strm, true, key, nil
}

func (c *Client) CloseUDP(key uint64) error {
	c.udpMu.Lock()
	defer c.udpMu.Unlock()
	if strm, exists := c.udpStrms[key]; exists {
		strm.Close()
	}
	delete(c.udpStrms, key)
	return nil
}
