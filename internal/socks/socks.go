package socks

import (
	"context"
	"io"
	"log"
	"lucy/internal/conf"
	"lucy/internal/flog"
	"lucy/internal/metrics"
	"lucy/internal/tnet"
	"net"

	"github.com/txthinking/socks5"
)

type SOCKS5 struct {
	handle *Handler
}

func New(provider tnet.StreamProvider) (*SOCKS5, error) {
	return &SOCKS5{
		handle: &Handler{provider: provider},
	}, nil
}

func (s *SOCKS5) Start(ctx context.Context, cfg conf.SOCKS5) error {
	s.handle.ctx = ctx
	go s.listen(ctx, cfg)
	return nil
}

// flogWriter redirects the third-party socks5 library's log.Println
// output to our flog.Debugf so the messages appear at DEBUG level
// instead of raw stdout.
type flogWriter struct{}

func (flogWriter) Write(p []byte) (n int, err error) {
	msg := string(p)
	if len(msg) > 0 && msg[len(msg)-1] == '\n' {
		msg = msg[:len(msg)-1]
	}
	if msg != "" {
		flog.Debugf("socks5-lib: %s", msg)
	}
	return len(p), nil
}

func (s *SOCKS5) listen(ctx context.Context, cfg conf.SOCKS5) error {
	// Redirect the library's raw log.Println output to flog.Debugf
	log.SetOutput(flogWriter{})
	log.SetFlags(0)

	listenAddr, _ := net.ResolveTCPAddr("tcp", cfg.Listen.String())
	server, err := socks5.NewClassicServer(listenAddr.String(), listenAddr.IP.String(), cfg.Username, cfg.Password, 10, 10)
	if err != nil {
		flog.Fatalf("SOCKS5 server failed to create on %s: %v", listenAddr.String(), err)
	}

	// Set up rate limiter if enabled
	var rl *rateLimiter
	if cfg.RateLimit.Enabled != nil && *cfg.RateLimit.Enabled {
		rl = newRateLimiter(cfg.RateLimit.MaxFails, cfg.RateLimit.BlockFor)
		s.handle.rateLimiter = rl
		flog.Infof("SOCKS5 rate limiting enabled: max %d failures, block for %v", cfg.RateLimit.MaxFails, cfg.RateLimit.BlockFor)
	}

	// Create TCP listener ourselves for rate limiting
	tcpListener, err := net.ListenTCP("tcp", listenAddr)
	if err != nil {
		flog.Fatalf("SOCKS5 failed to listen on %s: %v", listenAddr.String(), err)
	}

	go func() {
		for {
			c, err := tcpListener.AcceptTCP()
			if err != nil {
				select {
				case <-ctx.Done():
					return
				default:
				}
				flog.Debugf("SOCKS5 accept error: %v", err)
				return
			}
			go func(c *net.TCPConn) {
				defer c.Close()

				// Rate limit check — send proper SOCKS5 rejection for blocked IPs
				if rl != nil && rl.isBlocked(c.RemoteAddr()) {
					flog.Debugf("SOCKS5 rate limit: rejected connection from blocked IP %s", extractIP(c.RemoteAddr()))
					// Send SOCKS5 "no acceptable methods" reply so the client gets
					// a clean error instead of retrying endlessly on a silent close.
					c.Write([]byte{0x05, 0xFF})
					return
				}

				if err := server.Negotiate(c); err != nil {
					// Auth failure — record it for rate limiting
					if rl != nil {
						rl.recordFail(c.RemoteAddr())
					}
					flog.Debugf("SOCKS5 auth failed from %s: %v", c.RemoteAddr(), err)
					return
				}

				// Auth succeeded — clear failures
				if rl != nil {
					rl.recordSuccess(c.RemoteAddr())
				}

				r, err := server.GetRequest(c)
				if err != nil {
					flog.Debugf("SOCKS5 bad request from %s: %v", c.RemoteAddr(), err)
					return
				}
				if err := s.handle.TCPHandle(server, c, r); err != nil {
					flog.Debugf("SOCKS5 handle error from %s: %v", c.RemoteAddr(), err)
				}
			}(c)
		}
	}()

	flog.Infof("SOCKS5 server listening on %s", listenAddr.String())
	metrics.SOCKSSessions.Add(1)

	<-ctx.Done()
	metrics.SOCKSSessions.Add(-1)
	tcpListener.Close()
	return nil
}

var _ io.Writer = flogWriter{}
