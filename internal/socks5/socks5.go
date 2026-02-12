// Package socks5 implements a SOCKS5 proxy server with optional authentication.
package socks5

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"sync/atomic"
	"time"

	"lucy/internal/tunnel"
)

const (
	socks5Version = 0x05

	authNone     = 0x00
	authPassword = 0x02
	authNoAccept = 0xFF

	cmdConnect = 0x01

	atypIPv4   = 0x01
	atypDomain = 0x03
	atypIPv6   = 0x04

	repSuccess         = 0x00
	repFailure         = 0x01
	repNotAllowed      = 0x02
	repNetUnreachable  = 0x03
	repHostUnreachable = 0x04
	repConnRefused     = 0x05
	repCmdNotSupported = 0x07
	repAddrNotSupported = 0x08
)

// Server is a SOCKS5 proxy that tunnels connections.
type Server struct {
	ListenAddr string
	Username   string
	Password   string
	Tunnel     *tunnel.Client
	Logger     *log.Logger

	listener net.Listener
	closed   int32
}

// ListenAndServe starts the SOCKS5 server. Blocks until Close() or error.
func (s *Server) ListenAndServe() error {
	ln, err := net.Listen("tcp", s.ListenAddr)
	if err != nil {
		return err
	}
	s.listener = ln

	hasAuth := s.Username != "" && s.Password != ""
	authStr := "none"
	if hasAuth {
		authStr = fmt.Sprintf("user/pass (%s)", s.Username)
	}
	s.Logger.Printf("SOCKS5 proxy on %s (auth: %s)", s.ListenAddr, authStr)

	for {
		conn, err := ln.Accept()
		if err != nil {
			if atomic.LoadInt32(&s.closed) == 1 {
				return nil
			}
			continue
		}
		go s.handleConn(conn)
	}
}

// Close stops the SOCKS5 server.
func (s *Server) Close() {
	atomic.StoreInt32(&s.closed, 1)
	if s.listener != nil {
		s.listener.Close()
	}
}

func (s *Server) handleConn(conn net.Conn) {
	defer conn.Close()

	if !s.Tunnel.Connected() {
		return
	}

	conn.SetDeadline(time.Now().Add(30 * time.Second))

	// --- Auth negotiation ---
	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return
	}
	if buf[0] != socks5Version {
		return
	}

	nmethods := int(buf[1])
	methods := make([]byte, nmethods)
	if _, err := io.ReadFull(conn, methods); err != nil {
		return
	}

	hasAuth := s.Username != "" && s.Password != ""

	if hasAuth {
		// Require username/password auth
		found := false
		for _, m := range methods {
			if m == authPassword {
				found = true
				break
			}
		}
		if !found {
			conn.Write([]byte{socks5Version, authNoAccept})
			return
		}
		conn.Write([]byte{socks5Version, authPassword})

		// RFC 1929 username/password
		if _, err := io.ReadFull(conn, buf[:1]); err != nil {
			return
		}
		if buf[0] != 0x01 {
			return
		}
		if _, err := io.ReadFull(conn, buf[:1]); err != nil {
			return
		}
		ulen := int(buf[0])
		uname := make([]byte, ulen)
		if _, err := io.ReadFull(conn, uname); err != nil {
			return
		}
		if _, err := io.ReadFull(conn, buf[:1]); err != nil {
			return
		}
		plen := int(buf[0])
		passwd := make([]byte, plen)
		if _, err := io.ReadFull(conn, passwd); err != nil {
			return
		}

		if string(uname) != s.Username || string(passwd) != s.Password {
			conn.Write([]byte{0x01, 0x01}) // auth failure
			return
		}
		conn.Write([]byte{0x01, 0x00}) // auth success
	} else {
		conn.Write([]byte{socks5Version, authNone})
	}

	// --- Request ---
	reqBuf := make([]byte, 4)
	if _, err := io.ReadFull(conn, reqBuf); err != nil {
		return
	}

	if reqBuf[0] != socks5Version || reqBuf[1] != cmdConnect {
		s.sendReply(conn, repCmdNotSupported)
		return
	}

	// Parse address
	var host string
	atyp := reqBuf[3]

	switch atyp {
	case atypIPv4:
		addr := make([]byte, 4)
		if _, err := io.ReadFull(conn, addr); err != nil {
			return
		}
		host = net.IP(addr).String()

	case atypDomain:
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return
		}
		domain := make([]byte, lenBuf[0])
		if _, err := io.ReadFull(conn, domain); err != nil {
			return
		}
		host = string(domain)

	case atypIPv6:
		addr := make([]byte, 16)
		if _, err := io.ReadFull(conn, addr); err != nil {
			return
		}
		host = net.IP(addr).String()

	default:
		s.sendReply(conn, repAddrNotSupported)
		return
	}

	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBuf); err != nil {
		return
	}
	port := binary.BigEndian.Uint16(portBuf)

	s.Logger.Printf("SOCKS5 CONNECT %s:%d", host, port)

	// Open tunnel channel
	channelID, success := s.Tunnel.OpenChannel(host, port)
	if !success {
		s.sendReply(conn, repHostUnreachable)
		return
	}

	// Success reply
	s.sendReply(conn, repSuccess)

	// Register channel and clear deadline
	conn.SetDeadline(time.Time{})
	s.Tunnel.RegisterChannel(channelID, conn)

	// Forward local -> tunnel
	defer func() {
		s.Tunnel.CloseChannelRemote(channelID)
		s.Tunnel.CloseChannel(channelID)
	}()

	buf2 := make([]byte, 32768)
	for {
		if !s.Tunnel.Connected() {
			return
		}
		conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		n, err := conn.Read(buf2)
		if n > 0 {
			if sendErr := s.Tunnel.SendData(channelID, buf2[:n]); sendErr != nil {
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

func (s *Server) sendReply(conn net.Conn, rep byte) {
	// BND.ADDR = 0.0.0.0:0
	conn.Write([]byte{socks5Version, rep, 0x00, atypIPv4, 0, 0, 0, 0, 0, 0})
}
