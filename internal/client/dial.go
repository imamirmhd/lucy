package client

import (
	"fmt"
	"lucy/internal/flog"
	"lucy/internal/tnet"
	"time"
)

const maxRetries = 3

func (c *Client) newConn() (tnet.Conn, error) {
	c.mu.Lock()
	tc := c.iter.Next()
	c.mu.Unlock()

	autoExpire := 300
	err := tc.conn.Ping(false)
	if err != nil {
		flog.Infof("connection lost, retrying....")
		if tc.conn != nil {
			tc.conn.Close()
		}
		if conn, err := tc.createConn(); err == nil {
			tc.conn = conn
		}
		tc.expire = time.Now().Add(time.Duration(autoExpire) * time.Second)
	}
	return tc.conn, nil
}

func (c *Client) newStrm() (tnet.Strm, error) {
	var lastErr error
	for attempt := range maxRetries {
		conn, err := c.newConn()
		if err != nil {
			lastErr = err
			backoff := time.Duration(500*(1<<attempt)) * time.Millisecond
			flog.Debugf("session creation failed (attempt %d/%d), retrying in %v", attempt+1, maxRetries, backoff)
			time.Sleep(backoff)
			continue
		}
		strm, err := conn.OpenStrm()
		if err != nil {
			lastErr = err
			backoff := time.Duration(500*(1<<attempt)) * time.Millisecond
			flog.Debugf("failed to open stream (attempt %d/%d), retrying in %v: %v", attempt+1, maxRetries, backoff, err)
			time.Sleep(backoff)
			continue
		}
		return strm, nil
	}
	return nil, fmt.Errorf("failed to create stream after %d attempts: %w", maxRetries, lastErr)
}
