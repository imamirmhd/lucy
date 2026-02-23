package run

import (
	"context"
	"os"
	"os/signal"
	"lucy/internal/conf"
	"lucy/internal/flog"
	"lucy/internal/forward"
	"lucy/internal/server"
	"lucy/internal/socks"
	"syscall"
)

func startServer(cfg *conf.Conf) {
	flog.Infof("Starting server...")

	srv, err := server.New(cfg)
	if err != nil {
		flog.Fatalf("Failed to initialize server: %v", err)
	}

	// Start server in background so we can setup SOCKS5/Forward
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		flog.Infof("Shutdown signal received")
		cancel()
	}()

	go func() {
		if err := srv.Start(); err != nil {
			flog.Fatalf("Server encountered an error: %v", err)
		}
	}()

	// Give the server a moment to accept connections before starting SOCKS5/Forward
	// These features are optional and depend on having at least one client connection
	provider := srv.StreamProvider()

	for _, ss := range cfg.SOCKS5 {
		s, err := socks.New(provider)
		if err != nil {
			flog.Fatalf("Failed to initialize SOCKS5: %v", err)
		}
		if err := s.Start(ctx, ss); err != nil {
			flog.Fatalf("SOCKS5 encountered an error: %v", err)
		}
	}
	for _, ff := range cfg.Forward {
		f, err := forward.New(provider, ff.Listen.String(), ff.Target.String())
		if err != nil {
			flog.Fatalf("Failed to initialize Forward: %v", err)
		}
		if err := f.Start(ctx, ff.Protocol); err != nil {
			flog.Infof("Forward encountered an error: %v", err)
		}
	}

	<-ctx.Done()
}
