package server

import (
	"context"
	"lucy/internal/flog"
	"lucy/internal/metrics"
	"lucy/internal/pkg/buffer"
	"lucy/internal/protocol"
	"lucy/internal/tnet"
)

func (s *Server) handleTCPProtocol(ctx context.Context, strm tnet.Strm, p *protocol.Proto, cid uint64) error {
	flog.Infof("accepted TCP stream %d: %s -> %s", strm.SID(), strm.RemoteAddr(), p.Addr.String())
	return s.handleTCP(ctx, strm, p.Addr.String(), cid)
}

func (s *Server) handleTCP(ctx context.Context, strm tnet.Strm, addr string, cid uint64) error {
	conn, err := s.dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		flog.Errorf("failed to establish TCP connection to %s for stream %d: %v", addr, strm.SID(), err)
		return err
	}
	defer func() {
		conn.Close()
		flog.Debugf("closed TCP connection %s for stream %d", addr, strm.SID())
	}()
	flog.Debugf("TCP connection established to %s for stream %d", addr, strm.SID())

	errChan := make(chan error, 2)
	go func() {
		err := buffer.CopyT(conn, metrics.NewTrackerReader(strm, cid))
		errChan <- err
	}()
	go func() {
		err := buffer.CopyT(metrics.NewTrackerWriter(strm, cid), conn)
		errChan <- err
	}()

	var firstErr error
	for i := 0; i < 2; i++ {
		select {
		case err := <-errChan:
			if firstErr == nil && err != nil {
				firstErr = err
			}
		case <-ctx.Done():
			return nil
		}
	}
	return firstErr
}
