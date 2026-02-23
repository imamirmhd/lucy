package client

import (
	"context"
	"fmt"
	"lucy/internal/conf"
	"lucy/internal/flog"
	"lucy/internal/protocol"
	"lucy/internal/socket"
	"lucy/internal/tnet"
	"lucy/internal/tnet/kcp"
	"sync"
	"time"
)

const reconnectDelay = 2 * time.Second

type timedConn struct {
	cfg  *conf.Conf
	conn tnet.Conn
	ctx  context.Context
	mu   sync.Mutex
}

func newTimedConn(ctx context.Context, cfg *conf.Conf) (*timedConn, error) {
	var err error
	tc := timedConn{cfg: cfg, ctx: ctx}
	tc.conn, err = tc.createConn()
	if err != nil {
		return nil, err
	}
	return &tc, nil
}

// getConn returns a healthy connection, reconnecting if the connection is dead.
func (tc *timedConn) getConn() (tnet.Conn, error) {
	tc.mu.Lock()
	defer tc.mu.Unlock()

	needReconnect := tc.conn == nil

	// Check liveness via ping
	if !needReconnect {
		if err := tc.conn.Ping(false); err != nil {
			flog.Infof("connection lost, reconnecting...")
			needReconnect = true
		}
	}

	if needReconnect {
		if tc.conn != nil {
			tc.conn.Close()
		}
		conn, err := tc.createConn()
		if err != nil {
			tc.conn = nil
			return nil, fmt.Errorf("reconnect failed: %w", err)
		}
		tc.conn = conn
	}

	return tc.conn, nil
}

func (tc *timedConn) createConn() (tnet.Conn, error) {
	netCfg := tc.cfg.Network
	pConn, err := socket.New(tc.ctx, &netCfg)
	if err != nil {
		return nil, fmt.Errorf("could not create packet conn: %w", err)
	}

	// Enable decoy source spoofing BEFORE dialing so the KCP handshake
	// itself uses the spoofed source IP from the very first packet.
	if tc.cfg.Stealth.Enabled() {
		serverAddr := tc.cfg.Server.Addr
		pConn.SetStealth(serverAddr.IP, uint16(serverAddr.Port), nil, tc.cfg.Stealth.DecoySources)
	}

	conn, err := kcp.Dial(tc.cfg.Server.Addr, tc.cfg.Transport.KCP, pConn)
	if err != nil {
		return nil, err
	}
	err = tc.sendTCPF(conn)
	if err != nil {
		return nil, err
	}
	if tc.cfg.Stealth.Enabled() {
		err = tc.sendStealth(conn, pConn)
		if err != nil {
			return nil, err
		}
	}
	return conn, nil
}

func (tc *timedConn) sendTCPF(conn tnet.Conn) error {
	strm, err := conn.OpenStrm()
	if err != nil {
		return err
	}
	defer strm.Close()

	p := protocol.Proto{Type: protocol.PTCPF, TCPF: tc.cfg.Network.TCP.RF}
	err = p.Write(strm)
	if err != nil {
		return err
	}
	return nil
}

func (tc *timedConn) sendStealth(conn tnet.Conn, pConn *socket.PacketConn) error {
	strm, err := conn.OpenStrm()
	if err != nil {
		return fmt.Errorf("stealth: open stream: %w", err)
	}
	defer strm.Close()

	p := protocol.Proto{
		Type:             protocol.PSTEALTH,
		StealthSources:   tc.cfg.Stealth.DecoySources,
		StealthRealIP:    tc.cfg.Stealth.RealIP,
		StealthResponses: tc.cfg.Stealth.DecoyResponses,
	}
	if err := p.Write(strm); err != nil {
		return fmt.Errorf("stealth: write: %w", err)
	}

	// Read server's response with its decoy responses
	var resp protocol.Proto
	if err := resp.Read(strm); err != nil {
		return fmt.Errorf("stealth: read response: %w", err)
	}
	if resp.Type != protocol.PSTEALTH {
		return fmt.Errorf("stealth: unexpected response type: %d", resp.Type)
	}

	// Decoy source IPs are already active (set before KCP dial)
	flog.Infof("stealth mode enabled: %d decoy sources, %d server decoy responses",
		len(tc.cfg.Stealth.DecoySources), len(resp.StealthResponses))

	return nil
}

func (tc *timedConn) close() {
	tc.mu.Lock()
	defer tc.mu.Unlock()
	if tc.conn != nil {
		tc.conn.Close()
		tc.conn = nil
	}
}
