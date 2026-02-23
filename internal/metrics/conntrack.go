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
// Uses sync.Map for optimal read-heavy workloads (Get is called on every
// data transfer, Register/Unregister are much less frequent).
type ConnTracker struct {
	conns sync.Map // map[uint64]*ConnInfo
	seq   atomic.Uint64
}

// Tracker is the global connection tracker singleton.
var Tracker = &ConnTracker{}

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
	ct.conns.Store(id, info)
	TotalConns.Add(1)
	return id
}

// Unregister removes a connection from tracking.
func (ct *ConnTracker) Unregister(id uint64) {
	ct.conns.Delete(id)
}

// Get returns the ConnInfo for byte-counter updates. Returns nil if not found.
func (ct *ConnTracker) Get(id uint64) *ConnInfo {
	v, ok := ct.conns.Load(id)
	if !ok {
		return nil
	}
	return v.(*ConnInfo)
}

// Snapshot returns a copy-safe slice of all active connections.
func (ct *ConnTracker) Snapshot() []ConnSnapshot {
	var out []ConnSnapshot
	ct.conns.Range(func(key, value any) bool {
		c := value.(*ConnInfo)
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
		return true
	})
	return out
}

// Count returns the number of tracked connections.
func (ct *ConnTracker) Count() int {
	n := 0
	ct.conns.Range(func(_, _ any) bool {
		n++
		return true
	})
	return n
}
