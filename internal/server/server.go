package server

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"lucy/internal/conf"
	"lucy/internal/flog"
	"lucy/internal/metrics"
	"lucy/internal/socket"
	"lucy/internal/tnet"
	"lucy/internal/tnet/kcp"
)

type Server struct {
	cfg    *conf.Conf
	pConn  *socket.PacketConn
	dialer net.Dialer
	wg     sync.WaitGroup
	client *Client
}

func New(cfg *conf.Conf) (*Server, error) {
	s := &Server{
		cfg:    cfg,
		dialer: net.Dialer{Timeout: 10 * time.Second},
		client: NewClient(),
	}

	return s, nil
}

// Client returns the server-side StreamProvider for SOCKS5/Forward usage.
func (s *Server) StreamProvider() tnet.StreamProvider {
	return s.client
}

func (s *Server) Start() error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		flog.Infof("Shutdown signal received, initiating graceful shutdown...")
		cancel()
	}()

	pConn, err := socket.New(ctx, &s.cfg.Network)
	if err != nil {
		return fmt.Errorf("could not create raw packet conn: %w", err)
	}
	s.pConn = pConn

	listener, err := kcp.Listen(s.cfg.Transport.KCP, pConn)
	if err != nil {
		return fmt.Errorf("could not start KCP listener: %w", err)
	}
	defer listener.Close()
	flog.Infof("Server started - listening for packets on :%d", s.cfg.Listen.Addr.Port)

	s.wg.Go(func() {
		s.listen(ctx, listener)
	})

	s.wg.Wait()
	flog.Infof("Server shutdown completed")
	return nil
}

func (s *Server) listen(ctx context.Context, listener tnet.Listener) {
	go func() {
		<-ctx.Done()
		listener.Close()
	}()
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return // shutting down
			}
			errStr := err.Error()
			if strings.Contains(errStr, "closed") || strings.Contains(errStr, "shutdown") {
				flog.Debugf("listener closed, stopping accept loop")
				return
			}
			flog.Errorf("failed to accept connection: %v", err)
			continue
		}
		flog.Infof("accepted new connection from %s (local: %s)", conn.RemoteAddr(), conn.LocalAddr())
		metrics.ActiveConns.Add(1)

		// Add connection to the server-side client pool for SOCKS5/Forward
		s.client.AddConn(conn)

		s.wg.Go(func() {
			defer func() {
				conn.Close()
				metrics.ActiveConns.Add(-1)
			}()
			s.handleConn(ctx, conn)
		})
	}
}
