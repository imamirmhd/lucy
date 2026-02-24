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
	"sync/atomic"
	"time"
)

const (
	healthCheckInterval = 5 * time.Second
	maxBackoff          = 30 * time.Second
	initialBackoff      = 1 * time.Second
)

type timedConn struct {
	cfg    *conf.Conf
	conn   atomic.Pointer[tnet.Conn]
	ctx    context.Context
	cancel context.CancelFunc

	// reconnectMu prevents multiple concurrent reconnection attempts
	reconnectMu sync.Mutex
}

func newTimedConn(ctx context.Context, cfg *conf.Conf) (*timedConn, error) {
	childCtx, cancel := context.WithCancel(ctx)
	tc := &timedConn{cfg: cfg, ctx: childCtx, cancel: cancel}

	conn, err := tc.createConn()
	if err != nil {
		cancel()
		return nil, err
	}
	tc.conn.Store(&conn)
	return tc, nil
}

// getConn returns the current connection — a single atomic load, zero lock contention.
// Returns nil error with nil conn if reconnecting.
func (tc *timedConn) getConn() (tnet.Conn, error) {
	p := tc.conn.Load()
	if p == nil {
		return nil, fmt.Errorf("connection unavailable, reconnecting")
	}
	return *p, nil
}

// reconnectLoop runs in the background, monitoring connection health
// and reconnecting with exponential backoff on failure.
func (tc *timedConn) reconnectLoop() {
	ticker := time.NewTicker(healthCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-tc.ctx.Done():
			return
		case <-ticker.C:
		}

		p := tc.conn.Load()
		if p == nil {
			// Connection is nil — reconnect immediately
			tc.doReconnect()
			continue
		}

		// Check liveness
		if err := (*p).Ping(false); err != nil {
			flog.Infof("connection lost, starting reconnect...")
			tc.doReconnect()
		}
	}
}

func (tc *timedConn) doReconnect() {
	tc.reconnectMu.Lock()
	defer tc.reconnectMu.Unlock()

	// Double-check: another goroutine may have already reconnected
	if p := tc.conn.Load(); p != nil {
		if err := (*p).Ping(false); err == nil {
			return // already healthy
		}
	}

	// Close old connection
	if p := tc.conn.Load(); p != nil {
		(*p).Close()
		tc.conn.Store(nil)
	}

	backoff := initialBackoff
	for {
		select {
		case <-tc.ctx.Done():
			return
		default:
		}

		flog.Infof("attempting reconnect (backoff: %v)...", backoff)
		conn, err := tc.createConn()
		if err != nil {
			flog.Errorf("reconnect failed: %v, retrying in %v", err, backoff)
			select {
			case <-tc.ctx.Done():
				return
			case <-time.After(backoff):
			}
			backoff = min(backoff*2, maxBackoff)
			continue
		}

		tc.conn.Store(&conn)
		flog.Infof("reconnected successfully")
		return
	}
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
	tc.cancel()
	if p := tc.conn.Load(); p != nil {
		(*p).Close()
		tc.conn.Store(nil)
	}
}
