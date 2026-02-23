package forward

import (
	"context"
	"fmt"
	"lucy/internal/flog"
	"lucy/internal/metrics"
	"lucy/internal/tnet"
	"sync"
)

type Forward struct {
	provider   tnet.StreamProvider
	listenAddr string
	targetAddr string
	wg         sync.WaitGroup
}

func New(provider tnet.StreamProvider, listenAddr, targetAddr string) (*Forward, error) {
	return &Forward{
		provider:   provider,
		listenAddr: listenAddr,
		targetAddr: targetAddr,
	}, nil
}

func (f *Forward) Start(ctx context.Context, protocol string) error {
	flog.Debugf("starting %s forwarder: %s -> %s", protocol, f.listenAddr, f.targetAddr)
	metrics.ForwardSessions.Add(1)
	switch protocol {
	case "tcp":
		return f.startTCP(ctx)
	case "udp":
		return f.startUDP(ctx)
	default:
		flog.Errorf("unsupported protocol: %s", protocol)
		return fmt.Errorf("unsupported protocol: %s", protocol)
	}
}

func (f *Forward) startTCP(ctx context.Context) error {
	f.wg.Go(func() {
		if err := f.listenTCP(ctx); err != nil {
			flog.Debugf("TCP forwarder stopped with: %v", err)
		}
	})
	return nil
}

func (f *Forward) startUDP(ctx context.Context) error {
	f.wg.Go(func() {
		f.listenUDP(ctx)
	})
	return nil
}
