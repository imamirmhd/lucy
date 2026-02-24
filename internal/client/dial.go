package client

import (
	"fmt"
	"lucy/internal/flog"
	"lucy/internal/tnet"
	"time"
)

const maxRetries = 5

func (c *Client) newConn() (tnet.Conn, error) {
	c.mu.Lock()
	tc := c.iter.Next()
	c.mu.Unlock()

	return tc.getConn()
}

func (c *Client) newStrm() (tnet.Strm, error) {
	var lastErr error
	for attempt := range maxRetries {
		conn, err := c.newConn()
		if err != nil {
			lastErr = err
			// Brief wait — the background reconnect loop is doing the heavy lifting
			backoff := time.Duration(100*(1<<attempt)) * time.Millisecond
			if backoff > 2*time.Second {
				backoff = 2 * time.Second
			}
			flog.Debugf("no connection available (attempt %d/%d), waiting %v", attempt+1, maxRetries, backoff)
			time.Sleep(backoff)
			continue
		}
		strm, err := conn.OpenStrm()
		if err != nil {
			lastErr = err
			backoff := time.Duration(100*(1<<attempt)) * time.Millisecond
			if backoff > 2*time.Second {
				backoff = 2 * time.Second
			}
			flog.Debugf("failed to open stream (attempt %d/%d): %v", attempt+1, maxRetries, err)
			time.Sleep(backoff)
			continue
		}
		return strm, nil
	}
	return nil, fmt.Errorf("failed to create stream after %d attempts: %w", maxRetries, lastErr)
}
