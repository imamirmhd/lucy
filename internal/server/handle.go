package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"net"

	"lucy/internal/flog"
	"lucy/internal/metrics"
	"lucy/internal/protocol"
	"lucy/internal/tnet"
)

const maxStreamsPerConn = 512

func (s *Server) handleConn(ctx context.Context, conn tnet.Conn) {
	sem := make(chan struct{}, maxStreamsPerConn)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		strm, err := conn.AcceptStrm()
		if err != nil {
			if ctx.Err() != nil {
				return // shutting down
			}
			flog.Debugf("stream accept on %s ended: %v", conn.RemoteAddr(), err)
			return
		}

		// Non-blocking semaphore check — reject excess streams instantly
		select {
		case sem <- struct{}{}:
		default:
			strm.Close()
			flog.Debugf("stream %d rejected: concurrency limit (%d) reached for %s", strm.SID(), maxStreamsPerConn, conn.RemoteAddr())
			continue
		}

		metrics.ActiveStreams.Add(1)
		s.wg.Go(func() {
			defer func() {
				strm.Close()
				metrics.ActiveStreams.Add(-1)
				<-sem
			}()
			if err := s.handleStrm(ctx, strm); err != nil {
				if errors.Is(err, io.EOF) || errors.Is(err, io.ErrClosedPipe) ||
					strings.Contains(err.Error(), "closed pipe") ||
					strings.Contains(err.Error(), "closed network connection") {
					flog.Debugf("stream %d from %s closed", strm.SID(), strm.RemoteAddr())
				} else {
					flog.Errorf("stream %d from %s closed with error: %v", strm.SID(), strm.RemoteAddr(), err)
				}
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
		if errors.Is(err, io.EOF) {
			return err
		}
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
	case protocol.PSTEALTH:
		return s.handleStealth(strm, &p)
	case protocol.PTCP:
		cid := metrics.Tracker.Register(metrics.ConnStream, strm.RemoteAddr().String(), p.Addr.String(), strm.SID())
		defer metrics.Tracker.Unregister(cid)
		return s.handleTCPProtocol(ctx, strm, &p, cid)
	case protocol.PMULTI:
		return s.handleBond(ctx, p.BondID, int(p.BondTotal), int(p.BondIndex), p.Addr.String(), strm)
	case protocol.PUDP:
		cid := metrics.Tracker.Register(metrics.ConnStream, strm.RemoteAddr().String(), p.Addr.String(), strm.SID())
		defer metrics.Tracker.Unregister(cid)
		return s.handleUDPProtocol(ctx, strm, &p, cid)
	default:
		flog.Errorf("unknown protocol type %d on stream %d", p.Type, strm.SID())
		return fmt.Errorf("unknown protocol type: %d", p.Type)
	}
}

func (s *Server) handleStealth(strm tnet.Strm, p *protocol.Proto) error {
	flog.Infof("stealth handshake from %s: %d decoy sources, %d decoy responses, real IP %s",
		strm.RemoteAddr(), len(p.StealthSources), len(p.StealthResponses), p.StealthRealIP)

	// If client provided a real IP, configure server to override destination IP
	// to the real IP when replying to any of the client's decoy sources (preserving port).
	if len(p.StealthRealIP) > 0 {
		clientUDP := strm.RemoteAddr().(*net.UDPAddr)
		clientPort := uint16(clientUDP.Port)

		// Register mapping for the current address KCP sees
		s.pConn.SetStealth(clientUDP.IP, clientPort, p.StealthRealIP, p.StealthResponses)

		// Register mapping for all known decoy sources the client might roam to
		for _, decoyIP := range p.StealthSources {
			s.pConn.SetStealth(decoyIP, clientPort, p.StealthRealIP, p.StealthResponses)
		}

		flog.Infof("stealth: server will rewrite dst IP to %s and use %d spoofed sources for client port %d",
			p.StealthRealIP, len(p.StealthResponses), clientPort)
	}

	// Reply with an empty PSTEALTH ack (server doesn't configure its own decoys via config)
	resp := protocol.Proto{Type: protocol.PSTEALTH}
	if err := resp.Write(strm); err != nil {
		return fmt.Errorf("stealth: write response: %w", err)
	}

	return nil
}
