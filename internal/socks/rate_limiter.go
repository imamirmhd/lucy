package socks

import (
	"lucy/internal/flog"
	"net"
	"sync"
	"time"
)

type rateLimiter struct {
	maxFails int
	blockDur time.Duration
	mu       sync.Mutex
	entries  map[string]*rlEntry
}

type rlEntry struct {
	fails    int
	blockedUntil time.Time
}

func newRateLimiter(maxFails int, blockDur time.Duration) *rateLimiter {
	rl := &rateLimiter{
		maxFails: maxFails,
		blockDur: blockDur,
		entries:  make(map[string]*rlEntry),
	}
	go rl.cleanup()
	return rl
}

// isBlocked returns true if the IP is currently blocked.
func (rl *rateLimiter) isBlocked(addr net.Addr) bool {
	ip := extractIP(addr)
	rl.mu.Lock()
	defer rl.mu.Unlock()
	e, ok := rl.entries[ip]
	if !ok {
		return false
	}
	if time.Now().Before(e.blockedUntil) {
		return true
	}
	// Block expired — remove entry
	if e.fails >= rl.maxFails {
		delete(rl.entries, ip)
	}
	return false
}

// recordFail records a failed attempt and blocks the IP if threshold is reached.
func (rl *rateLimiter) recordFail(addr net.Addr) {
	ip := extractIP(addr)
	rl.mu.Lock()
	defer rl.mu.Unlock()
	e, ok := rl.entries[ip]
	if !ok {
		e = &rlEntry{}
		rl.entries[ip] = e
	}
	e.fails++
	if e.fails >= rl.maxFails {
		e.blockedUntil = time.Now().Add(rl.blockDur)
		flog.Warnf("SOCKS5 rate limit: blocking %s for %v after %d failed attempts", ip, rl.blockDur, e.fails)
	}
}

// recordSuccess clears the failure counter for an IP on successful connection.
func (rl *rateLimiter) recordSuccess(addr net.Addr) {
	ip := extractIP(addr)
	rl.mu.Lock()
	defer rl.mu.Unlock()
	delete(rl.entries, ip)
}

func (rl *rateLimiter) cleanup() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		rl.mu.Lock()
		now := time.Now()
		for ip, e := range rl.entries {
			if e.fails >= rl.maxFails && now.After(e.blockedUntil) {
				delete(rl.entries, ip)
			}
		}
		rl.mu.Unlock()
	}
}

func extractIP(addr net.Addr) string {
	if tcpAddr, ok := addr.(*net.TCPAddr); ok {
		return tcpAddr.IP.String()
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return addr.String()
	}
	return host
}
