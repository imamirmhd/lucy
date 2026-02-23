package server

import (
	"context"
	"fmt"

	"lucy/internal/flog"
	"lucy/internal/metrics"
	"lucy/internal/protocol"
	"lucy/internal/tnet"
)

func (s *Server) handleConn(ctx context.Context, conn tnet.Conn) {
	for {
		select {
		case <-ctx.Done():
			flog.Debugf("stopping smux session for %s due to context cancellation", conn.RemoteAddr())
			return
		default:
		}
		strm, err := conn.AcceptStrm()
		if err != nil {
			flog.Errorf("failed to accept stream on %s: %v", conn.RemoteAddr(), err)
			return
		}
		metrics.ActiveStreams.Add(1)
		s.wg.Go(func() {
			defer func() {
				strm.Close()
				metrics.ActiveStreams.Add(-1)
			}()
			if err := s.handleStrm(ctx, strm); err != nil {
				flog.Errorf("stream %d from %s closed with error: %v", strm.SID(), strm.RemoteAddr(), err)
			} else {
				flog.Debugf("stream %d from %s closed", strm.SID(), strm.RemoteAddr())
			}
		})
	}
}

func (s *Server) handleStrm(ctx context.Context, strm tnet.Strm) error {
	var p protocol.Proto
	err := p.Read(strm)
	if err != nil {
		flog.Errorf("failed to read protocol message from stream %d: %v", strm.SID(), err)
		return err
	}

	switch p.Type {
	case protocol.PPING:
		return s.handlePing(strm)
	case protocol.PTCPF:
		if len(p.TCPF) != 0 {
			s.pConn.SetClientTCPF(strm.RemoteAddr(), p.TCPF)
		}
		return nil
	case protocol.PTCP:
		cid := metrics.Tracker.Register(metrics.ConnStream, strm.RemoteAddr().String(), p.Addr.String(), strm.SID())
		defer metrics.Tracker.Unregister(cid)
		return s.handleTCPProtocol(ctx, strm, &p, cid)
	case protocol.PUDP:
		cid := metrics.Tracker.Register(metrics.ConnStream, strm.RemoteAddr().String(), p.Addr.String(), strm.SID())
		defer metrics.Tracker.Unregister(cid)
		return s.handleUDPProtocol(ctx, strm, &p, cid)
	default:
		flog.Errorf("unknown protocol type %d on stream %d", p.Type, strm.SID())
		return fmt.Errorf("unknown protocol type: %d", p.Type)
	}
}
