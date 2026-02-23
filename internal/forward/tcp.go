package forward

import (
	"context"
	"net"
	"lucy/internal/flog"
	"lucy/internal/metrics"
	"lucy/internal/pkg/buffer"
)

func (f *Forward) listenTCP(ctx context.Context) error {
	listener, err := net.Listen("tcp", f.listenAddr)
	if err != nil {
		flog.Errorf("failed to bind TCP socket on %s: %v", f.listenAddr, err)
		return err
	}
	defer listener.Close()
	go func() {
		<-ctx.Done()
		listener.Close()
	}()
	flog.Infof("TCP forwarder listening on %s -> %s", f.listenAddr, f.targetAddr)

	for {
		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				flog.Errorf("failed to accept TCP connection on %s: %v", f.listenAddr, err)
				continue
			}
		}

		f.wg.Go(func() {
			defer conn.Close()
			if err := f.handleTCPConn(ctx, conn); err != nil {
				flog.Errorf("TCP connection %s -> %s closed with error: %v", conn.RemoteAddr(), f.targetAddr, err)
			} else {
				flog.Debugf("TCP connection %s -> %s closed", conn.RemoteAddr(), f.targetAddr)
			}
		})
	}
}

func (f *Forward) handleTCPConn(ctx context.Context, conn net.Conn) error {
	strm, err := f.provider.TCP(f.targetAddr)
	if err != nil {
		flog.Errorf("failed to establish stream for %s -> %s: %v", conn.RemoteAddr(), f.targetAddr, err)
		return err
	}
	defer func() {
		strm.Close()
		flog.Debugf("TCP stream closed for %s -> %s", conn.RemoteAddr(), f.targetAddr)
	}()

	cid := metrics.Tracker.Register(metrics.ConnFwdTCP, conn.RemoteAddr().String(), f.targetAddr, strm.SID())
	defer metrics.Tracker.Unregister(cid)

	flog.Infof("accepted TCP connection %s -> %s", conn.RemoteAddr(), f.targetAddr)

	errCh := make(chan error, 2)
	go func() {
		err := buffer.CopyT(conn, metrics.NewTrackerReader(strm, cid))
		conn.Close() // trigger teardown of the other direction
		errCh <- err
	}()
	go func() {
		err := buffer.CopyT(metrics.NewTrackerWriter(strm, cid), conn)
		strm.Close() // trigger teardown of the other direction
		errCh <- err
	}()

	var firstErr error
	for i := 0; i < 2; i++ {
		select {
		case err := <-errCh:
			if firstErr == nil && err != nil {
				firstErr = err
			}
		case <-ctx.Done():
			return nil
		}
	}
	return firstErr
}
