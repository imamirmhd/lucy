package server

import (
	"context"
	"fmt"
	"io"
	"lucy/internal/bond"
	"lucy/internal/flog"
	"lucy/internal/metrics"
	"lucy/internal/pkg/buffer"
	"lucy/internal/tnet"
	"sync"
	"time"
)

const bondTimeout = 10 * time.Second

type bondManager struct {
	mu    sync.Mutex
	bonds map[uint32]*pendingBond
}

type pendingBond struct {
	total   int
	addr    string
	streams []tnet.Strm
	count   int
	ready   chan struct{} // closed when all streams arrive
	done    chan struct{} // closed when relay finishes
	err     error
}

func newBondManager() *bondManager {
	return &bondManager{bonds: make(map[uint32]*pendingBond)}
}

func (bm *bondManager) join(bondID uint32, total int, index int, addr string, strm tnet.Strm) (*pendingBond, bool) {
	bm.mu.Lock()

	pb, ok := bm.bonds[bondID]
	if !ok {
		pb = &pendingBond{
			total:   total,
			addr:    addr,
			streams: make([]tnet.Strm, total),
			ready:   make(chan struct{}),
			done:    make(chan struct{}),
		}
		bm.bonds[bondID] = pb
	}

	pb.streams[index] = strm
	pb.count++
	complete := pb.count == pb.total

	if complete {
		close(pb.ready)
	}

	bm.mu.Unlock()
	return pb, complete
}

func (bm *bondManager) remove(bondID uint32) {
	bm.mu.Lock()
	delete(bm.bonds, bondID)
	bm.mu.Unlock()
}

func (s *Server) handleBond(ctx context.Context, bondID uint32, total int, index int, addr string, strm tnet.Strm) error {
	pb, isRunner := s.bonds.join(bondID, total, index, addr, strm)

	if !isRunner {
		select {
		case <-pb.ready:
		case <-time.After(bondTimeout):
			return fmt.Errorf("bond %08x: timed out waiting for all streams", bondID)
		case <-ctx.Done():
			return ctx.Err()
		}
		<-pb.done
		return pb.err
	}

	defer func() {
		s.bonds.remove(bondID)
		close(pb.done)
	}()

	flog.Infof("bond %08x: all %d streams assembled for %s, starting relay", bondID, total, addr)

	targetConn, err := s.dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		pb.err = fmt.Errorf("bond %08x: dial %s: %w", bondID, addr, err)
		return pb.err
	}
	defer targetConn.Close()

	for _, st := range pb.streams {
		cid := metrics.Tracker.Register(metrics.ConnStream, st.RemoteAddr().String(), addr, st.SID())
		defer metrics.Tracker.Unregister(cid)
	}

	ioWriters := make([]io.Writer, total)
	for i, st := range pb.streams {
		ioWriters[i] = st
	}
	bondW := bond.NewWriter(ioWriters)

	errCh := make(chan error, 2)

	// Upload: raw read from stream 0 → target
	go func() {
		err := buffer.CopyT(targetConn, pb.streams[0])
		targetConn.Close()
		errCh <- err
	}()

	// Download: target → bonded writer (all streams)
	go func() {
		bp := buffer.GetTCP()
		defer buffer.PutTCP(bp)
		_, err := io.CopyBuffer(bondW, targetConn, *bp)
		bondW.Close()
		errCh <- err
	}()

	for i := 0; i < 2; i++ {
		select {
		case e := <-errCh:
			if e != nil && pb.err == nil {
				pb.err = e
			}
		case <-ctx.Done():
			return nil
		}
	}

	flog.Debugf("bond %08x: relay finished for %s", bondID, addr)
	return pb.err
}
