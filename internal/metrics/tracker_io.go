package metrics

import (
	"io"
)

// TrackerReader wraps an io.Reader and adds read bytes to the connection's BytesRX counter.
// The ConnInfo pointer is cached at construction to avoid map lookups on every Read.
type TrackerReader struct {
	r    io.Reader
	info *ConnInfo
}

// NewTrackerReader creates a new TrackerReader with a cached ConnInfo pointer.
func NewTrackerReader(r io.Reader, cid uint64) *TrackerReader {
	return &TrackerReader{
		r:    r,
		info: Tracker.Get(cid),
	}
}

func (tr *TrackerReader) Read(p []byte) (int, error) {
	n, err := tr.r.Read(p)
	if n > 0 && tr.info != nil {
		tr.info.BytesRX.Add(int64(n))
	}
	return n, err
}

// TrackerWriter wraps an io.Writer and adds written bytes to the connection's BytesTX counter.
// The ConnInfo pointer is cached at construction to avoid map lookups on every Write.
type TrackerWriter struct {
	w    io.Writer
	info *ConnInfo
}

// NewTrackerWriter creates a new TrackerWriter with a cached ConnInfo pointer.
func NewTrackerWriter(w io.Writer, cid uint64) *TrackerWriter {
	return &TrackerWriter{
		w:    w,
		info: Tracker.Get(cid),
	}
}

func (tw *TrackerWriter) Write(p []byte) (int, error) {
	n, err := tw.w.Write(p)
	if n > 0 && tw.info != nil {
		tw.info.BytesTX.Add(int64(n))
	}
	return n, err
}
