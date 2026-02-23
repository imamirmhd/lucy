package metrics

import (
	"sync/atomic"
)

// Global metrics - use atomic operations for thread-safe access from hot paths.
var (
	PacketsTX atomic.Int64
	PacketsRX atomic.Int64
	BytesTX   atomic.Int64
	BytesRX   atomic.Int64

	ActiveConns     atomic.Int64
	ActiveStreams    atomic.Int64
	SOCKSSessions   atomic.Int64
	ForwardSessions atomic.Int64

	TotalConns   atomic.Int64
	TotalStreams  atomic.Int64
)

// Snapshot holds a point-in-time copy of all metrics for rendering.
type Snapshot struct {
	PacketsTX int64
	PacketsRX int64
	BytesTX   int64
	BytesRX   int64

	ActiveConns     int64
	ActiveStreams    int64
	SOCKSSessions   int64
	ForwardSessions int64

	TotalConns  int64
	TotalStreams int64
}

// Take returns a snapshot of all current metrics.
func Take() Snapshot {
	return Snapshot{
		PacketsTX:       PacketsTX.Load(),
		PacketsRX:       PacketsRX.Load(),
		BytesTX:         BytesTX.Load(),
		BytesRX:         BytesRX.Load(),
		ActiveConns:     ActiveConns.Load(),
		ActiveStreams:    ActiveStreams.Load(),
		SOCKSSessions:   SOCKSSessions.Load(),
		ForwardSessions: ForwardSessions.Load(),
		TotalConns:      TotalConns.Load(),
		TotalStreams:     TotalStreams.Load(),
	}
}
