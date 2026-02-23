package forward

import (
	"context"
	"net"
	"lucy/internal/flog"
	"lucy/internal/metrics"
	"lucy/internal/pkg/buffer"
	"lucy/internal/tnet"
	"sync"
	"time"
)

var udpCIDs sync.Map

func (f *Forward) listenUDP(ctx context.Context) {
	laddr, err := net.ResolveUDPAddr("udp", f.listenAddr)
	if err != nil {
		flog.Errorf("failed to resolve UDP listen address '%s': %v", f.listenAddr, err)
		return
	}

	conn, err := net.ListenUDP("udp", laddr)
	if err != nil {
		flog.Errorf("failed to bind UDP socket on %s: %v", laddr, err)
		return
	}
	defer conn.Close()
	go func() {
		<-ctx.Done()
		conn.Close()
	}()

	flog.Infof("UDP forwarder listening on %s -> %s", laddr, f.targetAddr)

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		if err := f.handleUDPPacket(ctx, conn); err != nil {
			flog.Errorf("UDP packet handling failed on %s: %v", f.listenAddr, err)
		}
	}
}

func (f *Forward) handleUDPPacket(ctx context.Context, conn *net.UDPConn) error {
	bp := buffer.GetUDP()
	defer buffer.PutUDP(bp)
	buf := *bp

	n, caddr, err := conn.ReadFromUDP(buf)
	if err != nil {
		return err
	}
	if n == 0 {
		return nil
	}

	strm, new, k, err := f.provider.UDP(caddr.String(), f.targetAddr)
	if err != nil {
		flog.Errorf("failed to establish UDP stream for %s -> %s: %v", caddr, f.targetAddr, err)
		f.provider.CloseUDP(k)
		return err
	}

	if _, err := strm.Write(buf[:n]); err != nil {
		flog.Errorf("failed to forward %d bytes from %s -> %s: %v", n, caddr, f.targetAddr, err)
		f.provider.CloseUDP(k)
		return err
	}

	var cid uint64
	if new {
		flog.Infof("accepted UDP connection %d for %s -> %s", strm.SID(), caddr, f.targetAddr)
		cid = metrics.Tracker.Register(metrics.ConnFwdUDP, caddr.String(), f.targetAddr, strm.SID())
		udpCIDs.Store(k, cid)
		go f.handleUDPStrm(ctx, k, cid, strm, conn, caddr)
	} else {
		if val, ok := udpCIDs.Load(k); ok {
			cid = val.(uint64)
		}
	}

	if info := metrics.Tracker.Get(cid); info != nil {
		info.BytesTX.Add(int64(n))
	}

	return nil
}

func (f *Forward) handleUDPStrm(ctx context.Context, k uint64, cid uint64, strm tnet.Strm, conn *net.UDPConn, caddr *net.UDPAddr) {
	bp := buffer.GetUDP()
	defer buffer.PutUDP(bp)
	buf := *bp

	defer func() {
		flog.Debugf("UDP stream %d closed for %s -> %s", strm.SID(), caddr, f.targetAddr)
		metrics.Tracker.Unregister(cid)
		udpCIDs.Delete(k)
		f.provider.CloseUDP(k)
	}()

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		strm.SetReadDeadline(time.Now().Add(8 * time.Second))
		n, err := strm.Read(buf)
		if err != nil {
			flog.Errorf("UDP stream %d read failed for %s -> %s: %v", strm.SID(), caddr, f.targetAddr, err)
			return
		}
		_, err = conn.WriteToUDP(buf[:n], caddr)
		if err != nil {
			flog.Errorf("UDP stream %d write failed for %s -> %s: %v", strm.SID(), caddr, f.targetAddr, err)
			return
		}
		if info := metrics.Tracker.Get(cid); info != nil {
			info.BytesRX.Add(int64(n))
		}
	}
}
