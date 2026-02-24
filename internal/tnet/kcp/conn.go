package kcp

import (
	"fmt"
	"net"
	"lucy/internal/protocol"
	"lucy/internal/socket"
	"lucy/internal/tnet"
	"time"

	"github.com/xtaci/kcp-go/v5"
	"github.com/xtaci/smux"
)

type Conn struct {
	PacketConn *socket.PacketConn
	UDPSession *kcp.UDPSession
	Session    *smux.Session
}

func (c *Conn) OpenStrm() (tnet.Strm, error) {
	strm, err := c.Session.OpenStream()
	if err != nil {
		return nil, err
	}
	return &Strm{strm}, nil
}

func (c *Conn) AcceptStrm() (tnet.Strm, error) {
	strm, err := c.Session.AcceptStream()
	if err != nil {
		return nil, err
	}
	return &Strm{strm}, nil
}

func (c *Conn) Ping(wait bool) error {
	if !wait {
		if c.Session.IsClosed() {
			return fmt.Errorf("session is closed")
		}
		return nil
	}
	strm, err := c.Session.OpenStream()
	if err != nil {
		return fmt.Errorf("ping failed: %v", err)
	}
	defer strm.Close()
	p := protocol.Proto{Type: protocol.PPING}
	err = p.Write(strm)
	if err != nil {
		return fmt.Errorf("strm ping write failed: %v", err)
	}
	err = p.Read(strm)
	if err != nil {
		return fmt.Errorf("strm ping read failed: %v", err)
	}
	if p.Type != protocol.PPONG {
		return fmt.Errorf("strm pong failed: %v", err)
	}
	return nil
}

func (c *Conn) Close() error {
	var err error
	if c.UDPSession != nil {
		c.UDPSession.Close()
	}
	if c.Session != nil {
		c.Session.Close()
	}
	// NOTE: PacketConn is NOT closed here — it is shared with the KCP listener
	// and other connections. Only the listener owns (and closes) the PacketConn.
	return err
}

func (c *Conn) IsClosed() bool                     { return c.Session.IsClosed() }
func (c *Conn) LocalAddr() net.Addr                { return c.Session.LocalAddr() }
func (c *Conn) RemoteAddr() net.Addr               { return c.Session.RemoteAddr() }
func (c *Conn) SetDeadline(t time.Time) error      { return c.Session.SetDeadline(t) }
func (c *Conn) SetReadDeadline(t time.Time) error  { return c.UDPSession.SetReadDeadline(t) }
func (c *Conn) SetWriteDeadline(t time.Time) error { return c.UDPSession.SetWriteDeadline(t) }
