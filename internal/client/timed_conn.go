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

const autoExpireSecs = 300

type timedConn struct {
	cfg    *conf.Conf
	conn   tnet.Conn
	expire time.Time
	ctx    context.Context
	mu     sync.Mutex
}

func newTimedConn(ctx context.Context, cfg *conf.Conf) (*timedConn, error) {
	var err error
	tc := timedConn{cfg: cfg, ctx: ctx}
	tc.conn, err = tc.createConn()
	if err != nil {
		return nil, err
	}
	tc.expire = time.Now().Add(autoExpireSecs * time.Second)
	return &tc, nil
}

// getConn returns a healthy connection, reconnecting if stale or dead.
// Caller must hold no lock; this method handles its own synchronization.
func (tc *timedConn) getConn() (tnet.Conn, error) {
	tc.mu.Lock()
	defer tc.mu.Unlock()

	needReconnect := false

	// Check expiry — proactively rotate before session degrades
	if time.Now().After(tc.expire) {
		flog.Debugf("connection expired, rotating...")
		needReconnect = true
	}

	// Check liveness
	if !needReconnect && tc.conn != nil {
		if err := tc.conn.Ping(false); err != nil {
			flog.Infof("connection lost, reconnecting...")
			needReconnect = true
		}
	}

	if tc.conn == nil {
		needReconnect = true
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
		tc.expire = time.Now().Add(autoExpireSecs * time.Second)
	}

	return tc.conn, nil
}

func (tc *timedConn) createConn() (tnet.Conn, error) {
	netCfg := tc.cfg.Network
	pConn, err := socket.New(tc.ctx, &netCfg)
	if err != nil {
		return nil, fmt.Errorf("could not create packet conn: %w", err)
	}

	conn, err := kcp.Dial(tc.cfg.Server.Addr, tc.cfg.Transport.KCP, pConn)
	if err != nil {
		return nil, err
	}
	err = tc.sendTCPF(conn)
	if err != nil {
		return nil, err
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

func (tc *timedConn) close() {
	tc.mu.Lock()
	defer tc.mu.Unlock()
	if tc.conn != nil {
		tc.conn.Close()
		tc.conn = nil
	}
}
