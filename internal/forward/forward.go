// Package forward implements port-forwarding through the tunnel.
package forward

import (
	"log"
	"net"
	"sync/atomic"
	"time"

	"lucy/internal/tunnel"
)

// Forwarder listens on a local address and forwards connections through the tunnel.
type Forwarder struct {
	ListenAddr  string
	ForwardAddr string
	Protocol    string // "tcp" or "udp"
	Tunnel      *tunnel.Client
	Logger      *log.Logger

	listener net.Listener
	udpConn  *net.UDPConn
	closed   int32
}

// ListenAndServe starts the forwarder. Blocks until Close() or error.
func (f *Forwarder) ListenAndServe() error {
	if f.Protocol == "udp" {
		return f.listenUDP()
	}
	return f.listenTCP()
}

func (f *Forwarder) listenTCP() error {
	ln, err := net.Listen("tcp", f.ListenAddr)
	if err != nil {
		return err
	}
	f.listener = ln
	f.Logger.Printf("Forward %s -> %s (TCP)", f.ListenAddr, f.ForwardAddr)

	for {
		conn, err := ln.Accept()
		if err != nil {
			if atomic.LoadInt32(&f.closed) == 1 {
				return nil
			}
			continue
		}
		go f.handleTCPConn(conn)
	}
}

func (f *Forwarder) handleTCPConn(conn net.Conn) {
	defer conn.Close()

	if !f.Tunnel.Connected() {
		return
	}

	host, portStr, err := net.SplitHostPort(f.ForwardAddr)
	if err != nil {
		f.Logger.Printf("Forward: invalid forward address %s: %v", f.ForwardAddr, err)
		return
	}

	port, err := net.LookupPort("tcp", portStr)
	if err != nil {
		f.Logger.Printf("Forward: invalid port %s: %v", portStr, err)
		return
	}

	channelID, success := f.Tunnel.OpenChannel(host, uint16(port))
	if !success {
		f.Logger.Printf("Forward: tunnel connect failed to %s", f.ForwardAddr)
		return
	}

	// Register channel and pipe data
	conn.SetDeadline(time.Time{})
	f.Tunnel.RegisterChannel(channelID, conn)

	defer func() {
		f.Tunnel.CloseChannelRemote(channelID)
		f.Tunnel.CloseChannel(channelID)
	}()

	buf := make([]byte, 32768)
	for {
		if !f.Tunnel.Connected() {
			return
		}
		conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		n, err := conn.Read(buf)
		if n > 0 {
			if sendErr := f.Tunnel.SendData(channelID, buf[:n]); sendErr != nil {
				return
			}
		}
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			return
		}
	}
}

func (f *Forwarder) listenUDP() error {
	addr, err := net.ResolveUDPAddr("udp", f.ListenAddr)
	if err != nil {
		return err
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return err
	}
	f.udpConn = conn
	f.Logger.Printf("Forward %s -> %s (UDP)", f.ListenAddr, f.ForwardAddr)

	buf := make([]byte, 65535)
	for {
		if atomic.LoadInt32(&f.closed) == 1 {
			return nil
		}

		conn.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, remoteAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			if atomic.LoadInt32(&f.closed) == 1 {
				return nil
			}
			continue
		}

		if n > 0 && f.Tunnel.Connected() {
			go f.handleUDPPacket(buf[:n], remoteAddr)
		}
	}
}

func (f *Forwarder) handleUDPPacket(data []byte, _ *net.UDPAddr) {
	host, portStr, err := net.SplitHostPort(f.ForwardAddr)
	if err != nil {
		return
	}
	port, err := net.LookupPort("udp", portStr)
	if err != nil {
		return
	}

	channelID, success := f.Tunnel.OpenChannel(host, uint16(port))
	if !success {
		return
	}

	f.Tunnel.SendData(channelID, data)
	// Close channel after sending — UDP is stateless per packet
	f.Tunnel.CloseChannelRemote(channelID)
	f.Tunnel.CloseChannel(channelID)
}

// Close stops the forwarder.
func (f *Forwarder) Close() {
	atomic.StoreInt32(&f.closed, 1)
	if f.listener != nil {
		f.listener.Close()
	}
	if f.udpConn != nil {
		f.udpConn.Close()
	}
}
