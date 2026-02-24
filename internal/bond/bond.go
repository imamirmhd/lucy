// Package bond implements multi-stream bonded I/O.
//
// A bonded writer splits data across N streams with sequence-numbered
// frames so a bonded reader can reassemble them in order.
//
// Frame format: [4B big-endian seq][2B big-endian payload_len][payload]
// An EOF is signalled by sending a frame with payload_len == 0.
package bond

import (
	"encoding/binary"
	"io"
	"sync"
)

const (
	hdrSize      = 6          // 4B seq + 2B len
	maxChunkSize = 32 * 1024  // 32 KB per frame
)

// ---------- Writer ----------

// Writer distributes sequential chunks across N streams.
// It is safe for concurrent use.
type Writer struct {
	streams []io.Writer
	seq     uint32
	idx     int
	mu      sync.Mutex
}

func NewWriter(streams []io.Writer) *Writer {
	return &Writer{streams: streams}
}

func (w *Writer) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	total := 0
	for len(p) > 0 {
		chunk := p
		if len(chunk) > maxChunkSize {
			chunk = chunk[:maxChunkSize]
		}

		var hdr [hdrSize]byte
		binary.BigEndian.PutUint32(hdr[0:4], w.seq)
		binary.BigEndian.PutUint16(hdr[4:6], uint16(len(chunk)))
		w.seq++

		s := w.streams[w.idx]
		w.idx = (w.idx + 1) % len(w.streams)

		if _, err := s.Write(hdr[:]); err != nil {
			return total, err
		}
		if _, err := s.Write(chunk); err != nil {
			return total, err
		}

		p = p[len(chunk):]
		total += len(chunk)
	}
	return total, nil
}

// Close sends an EOF frame (len=0) on every stream so each reader
// goroutine can terminate cleanly.
func (w *Writer) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	var hdr [hdrSize]byte
	binary.BigEndian.PutUint32(hdr[0:4], w.seq)
	// hdr[4:6] is already 0 (EOF)

	for _, s := range w.streams {
		if _, err := s.Write(hdr[:]); err != nil {
			return err
		}
	}
	return nil
}

// ---------- Reader ----------

// Reader reassembles sequenced frames from N streams in order,
// presenting a single io.Reader interface.
type Reader struct {
	mu      sync.Mutex
	cond    *sync.Cond
	pending map[uint32][]byte
	nextSeq uint32
	buf     []byte // leftover from a partially consumed chunk
	eof     bool
	readErr error
	done    int // number of reader goroutines finished
	total   int // total reader goroutines
}

func NewReader(streams []io.Reader) *Reader {
	r := &Reader{
		pending: make(map[uint32][]byte),
		total:   len(streams),
	}
	r.cond = sync.NewCond(&r.mu)
	for _, s := range streams {
		go r.loop(s)
	}
	return r
}

func (r *Reader) loop(stream io.Reader) {
	var hdr [hdrSize]byte
	for {
		if _, err := io.ReadFull(stream, hdr[:]); err != nil {
			r.mu.Lock()
			if !r.eof {
				r.readErr = err
				r.eof = true
			}
			r.cond.Broadcast()
			r.mu.Unlock()
			return
		}

		seq := binary.BigEndian.Uint32(hdr[0:4])
		length := binary.BigEndian.Uint16(hdr[4:6])

		if length == 0 {
			// EOF marker
			r.mu.Lock()
			r.done++
			if r.done >= r.total {
				r.eof = true
			}
			r.cond.Broadcast()
			r.mu.Unlock()
			return
		}

		data := make([]byte, length)
		if _, err := io.ReadFull(stream, data); err != nil {
			r.mu.Lock()
			if !r.eof {
				r.readErr = err
				r.eof = true
			}
			r.cond.Broadcast()
			r.mu.Unlock()
			return
		}

		r.mu.Lock()
		r.pending[seq] = data
		r.cond.Broadcast()
		r.mu.Unlock()
	}
}

func (r *Reader) Read(p []byte) (int, error) {
	// Drain leftover bytes first.
	if len(r.buf) > 0 {
		n := copy(p, r.buf)
		r.buf = r.buf[n:]
		return n, nil
	}

	r.mu.Lock()
	for {
		if data, ok := r.pending[r.nextSeq]; ok {
			delete(r.pending, r.nextSeq)
			r.nextSeq++
			r.mu.Unlock()

			n := copy(p, data)
			if n < len(data) {
				r.buf = data[n:]
			}
			return n, nil
		}

		if r.eof {
			r.mu.Unlock()
			if r.readErr != nil {
				return 0, r.readErr
			}
			return 0, io.EOF
		}

		r.cond.Wait()
	}
}
