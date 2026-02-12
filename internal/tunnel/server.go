package tunnel

import (
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"lucy/internal/config"
	"lucy/internal/proto"
	"lucy/internal/transport" // New transport package
)

// Server is the main tunnel server.
type Server struct {
	Config    *config.Config
	TLSConfig *tls.Config
	Logger    *log.Logger
}

// NewServer creates a new tunnel server.
func NewServer(cfg *config.Config, tlsCfg *tls.Config, logger *log.Logger) *Server {
	return &Server{Config: cfg, TLSConfig: tlsCfg, Logger: logger}
}

// ListenAndServe starts listening for connections.
func (s *Server) ListenAndServe() error {
	ln, err := net.Listen("tcp", s.Config.Server.Listen)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	s.Logger.Printf("Listening on %s", s.Config.Server.Listen)
	s.Logger.Printf("Hostname: %s", s.Config.Server.Hostname)
	s.Logger.Printf("Users loaded: %d", len(s.Config.Server.Users))

	for {
		conn, err := ln.Accept()
		if err != nil {
			s.Logger.Printf("Accept error: %v", err)
			continue
		}
		go s.handleConn(conn)
	}
}

func (s *Server) handleConn(conn net.Conn) {
	peer := conn.RemoteAddr().String()
	// s.Logger.Printf("Connection from %s", peer) // Too noisy for stealth server? Maybe debug only.

	// Build user map for auth
	users := make(map[string]string)
	for _, u := range s.Config.Server.Users {
		users[u.Username] = u.Secret
	}

	// Use the transport layer to handle the handshake (HTTP/HTTPS)
	username, tunnelConn, err := transport.ServerHandshake(conn, s.TLSConfig, s.Config, users)
	if err != nil {
		// Handshake failed or was a fake request. Connection is already closed/handled by transport.
		// Detailed logging only on debug
		if s.Config.Server.LogLevel == "debug" {
			s.Logger.Printf("Handshake failed from %s: %v", peer, err)
		}
		return
	}

	// Check IP whitelist
	user := s.Config.FindUser(username)
	if user != nil && len(user.Whitelist) > 0 {
		clientIP, _, _ := net.SplitHostPort(peer)
		if !isIPAllowed(clientIP, user.Whitelist) {
			s.Logger.Printf("IP %s not in whitelist for user %s", clientIP, username)
			tunnelConn.Close()
			return
		}
	}

	if s.Config.Server.LogLevel != "error" {
		s.Logger.Printf("[%s] Authenticated from %s, entering tunnel mode", username, peer)
	}

	session := &serverSession{
		conn:     tunnelConn,
		username: username,
		writer:   proto.NewFrameWriter(tunnelConn),
		channels: make(map[uint16]*channel),
		logger:   s.Logger,
	}
	session.run()
	
	if s.Config.Server.LogLevel != "error" {
		s.Logger.Printf("[%s] Session ended from %s", username, peer)
	}
}

func isIPAllowed(ip string, whitelist []string) bool {
	if len(whitelist) == 0 {
		return true
	}
	clientIP := net.ParseIP(ip)
	if clientIP == nil {
		return false
	}
	for _, entry := range whitelist {
		if entry == "0.0.0.0/0" || entry == "::/0" {
			return true
		}
		_, cidr, err := net.ParseCIDR(entry)
		if err != nil {
			// Try as single IP
			if net.ParseIP(entry) != nil && net.ParseIP(entry).Equal(clientIP) {
				return true
			}
			continue
		}
		if cidr.Contains(clientIP) {
			return true
		}
	}
	return false
}

type channel struct {
	id     uint16
	host   string
	port   uint16
	conn   net.Conn
	closed bool
	mu     sync.Mutex
}

type serverSession struct {
	conn     net.Conn
	username string
	writer   *proto.FrameWriter
	channels map[uint16]*channel
	chanMu   sync.Mutex
	logger   *log.Logger
}

func (s *serverSession) run() {
	defer s.cleanup()

	for {
		frame, err := proto.ReadFrame(s.conn)
		if err != nil {
			if err != io.EOF {
				// s.logger.Printf("[%s] Read error: %v", s.username, err)
			}
			return
		}
		s.handleFrame(frame)
	}
}

func (s *serverSession) handleFrame(f proto.Frame) {
	switch f.Type {
	case proto.FrameConnect:
		s.handleConnect(f)
	case proto.FrameData:
		s.handleData(f)
	case proto.FrameClose:
		s.handleClose(f.ChannelID)
	case proto.FramePing:
		s.writer.WriteFrame(proto.Frame{Type: proto.FramePong, ChannelID: f.ChannelID, Payload: f.Payload})
	}
}

func (s *serverSession) handleConnect(f proto.Frame) {
	host, port, err := proto.ParseConnectPayload(f.Payload)
	if err != nil {
		s.logger.Printf("[%s] Bad CONNECT: %v", s.username, err)
		s.writer.WriteFrame(proto.Frame{Type: proto.FrameConnectFail, ChannelID: f.ChannelID})
		return
	}

	s.logger.Printf("[%s] CONNECT ch=%d -> %s:%d", s.username, f.ChannelID, host, port)

	addr := fmt.Sprintf("%s:%d", host, port)
	destConn, err := net.DialTimeout("tcp", addr, 30*time.Second)
	if err != nil {
		s.logger.Printf("[%s] Connect failed ch=%d: %v", s.username, f.ChannelID, err)
		errMsg := []byte(err.Error())
		if len(errMsg) > 100 {
			errMsg = errMsg[:100]
		}
		s.writer.WriteFrame(proto.Frame{Type: proto.FrameConnectFail, ChannelID: f.ChannelID, Payload: errMsg})
		return
	}

	ch := &channel{
		id:   f.ChannelID,
		host: host,
		port: port,
		conn: destConn,
	}

	s.chanMu.Lock()
	s.channels[f.ChannelID] = ch
	s.chanMu.Unlock()

	s.writer.WriteFrame(proto.Frame{Type: proto.FrameConnectOK, ChannelID: f.ChannelID})
	// s.logger.Printf("[%s] CONNECTED ch=%d", s.username, f.ChannelID)

	// Read from destination and send to client
	go s.channelReader(ch)
}

func (s *serverSession) channelReader(ch *channel) {
	buf := make([]byte, 32768)
	defer func() {
		ch.mu.Lock()
		wasClosed := ch.closed
		ch.mu.Unlock()
		if !wasClosed {
			s.writer.WriteFrame(proto.Frame{Type: proto.FrameClose, ChannelID: ch.id})
			s.closeChannel(ch.id)
		}
	}()

	for {
		n, err := ch.conn.Read(buf)
		if n > 0 {
			if writeErr := s.writer.WriteFrame(proto.Frame{
				Type:      proto.FrameData,
				ChannelID: ch.id,
				Payload:   buf[:n],
			}); writeErr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

func (s *serverSession) handleData(f proto.Frame) {
	s.chanMu.Lock()
	ch, ok := s.channels[f.ChannelID]
	s.chanMu.Unlock()

	if !ok || ch == nil {
		return
	}

	ch.mu.Lock()
	closed := ch.closed
	ch.mu.Unlock()
	if closed {
		return
	}

	if _, err := ch.conn.Write(f.Payload); err != nil {
		s.closeChannel(f.ChannelID)
	}
}

func (s *serverSession) handleClose(channelID uint16) {
	s.closeChannel(channelID)
}

func (s *serverSession) closeChannel(channelID uint16) {
	s.chanMu.Lock()
	ch, ok := s.channels[channelID]
	if !ok {
		s.chanMu.Unlock()
		return
	}
	delete(s.channels, channelID)
	s.chanMu.Unlock()

	ch.mu.Lock()
	ch.closed = true
	ch.mu.Unlock()

	ch.conn.Close()
}

func (s *serverSession) cleanup() {
	s.chanMu.Lock()
	ids := make([]uint16, 0, len(s.channels))
	for id := range s.channels {
		ids = append(ids, id)
	}
	s.chanMu.Unlock()

	for _, id := range ids {
		s.closeChannel(id)
	}

	s.conn.Close()
}
