package metrics

import (
	"sync"
	"sync/atomic"
	"time"
)

// ConnType describes what kind of session a tracked connection represents.
type ConnType string

const (
	ConnKCP      ConnType = "KCP"
	ConnSOCKSTCP ConnType = "SOCKS5/TCP"
	ConnSOCKSUDP ConnType = "SOCKS5/UDP"
	ConnFwdTCP   ConnType = "FWD/TCP"
	ConnFwdUDP   ConnType = "FWD/UDP"
	ConnStream   ConnType = "STREAM"
)

// ConnInfo holds per-connection metadata.
type ConnInfo struct {
	ID       uint64
	Type     ConnType
	Source   string
	Target   string
	StreamID int
	Start    time.Time
	BytesTX  atomic.Int64
	BytesRX  atomic.Int64
}

// ConnSnapshot is a point-in-time, copy-safe view of a ConnInfo.
type ConnSnapshot struct {
	ID       uint64
	Type     ConnType
	Source   string
	Target   string
	StreamID int
	Start    time.Time
	BytesTX  int64
	BytesRX  int64
}

// ConnTracker is a thread-safe registry of active connections.
type ConnTracker struct {
	mu    sync.RWMutex
	conns map[uint64]*ConnInfo
	seq   atomic.Uint64
}

// Tracker is the global connection tracker singleton.
var Tracker = &ConnTracker{
	conns: make(map[uint64]*ConnInfo),
}

// Register adds a new connection and returns its assigned ID.
func (ct *ConnTracker) Register(typ ConnType, source, target string, streamID int) uint64 {
	id := ct.seq.Add(1)
	info := &ConnInfo{
		ID:       id,
		Type:     typ,
		Source:   source,
		Target:   target,
		StreamID: streamID,
		Start:    time.Now(),
	}
	ct.mu.Lock()
	ct.conns[id] = info
	ct.mu.Unlock()
	TotalConns.Add(1)
	return id
}

// Unregister removes a connection from tracking.
func (ct *ConnTracker) Unregister(id uint64) {
	ct.mu.Lock()
	delete(ct.conns, id)
	ct.mu.Unlock()
}

// Get returns the ConnInfo for byte-counter updates. Returns nil if not found.
func (ct *ConnTracker) Get(id uint64) *ConnInfo {
	ct.mu.RLock()
	info := ct.conns[id]
	ct.mu.RUnlock()
	return info
}

// Snapshot returns a copy-safe slice of all active connections.
func (ct *ConnTracker) Snapshot() []ConnSnapshot {
	ct.mu.RLock()
	defer ct.mu.RUnlock()
	out := make([]ConnSnapshot, 0, len(ct.conns))
	for _, c := range ct.conns {
		out = append(out, ConnSnapshot{
			ID:       c.ID,
			Type:     c.Type,
			Source:   c.Source,
			Target:   c.Target,
			StreamID: c.StreamID,
			Start:    c.Start,
			BytesTX:  c.BytesTX.Load(),
			BytesRX:  c.BytesRX.Load(),
		})
	}
	return out
}

// Count returns the number of tracked connections.
func (ct *ConnTracker) Count() int {
	ct.mu.RLock()
	n := len(ct.conns)
	ct.mu.RUnlock()
	return n
}
