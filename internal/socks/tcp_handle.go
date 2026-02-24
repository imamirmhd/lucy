package socks

import (
	"io"
	"net"
	"lucy/internal/bond"
	"lucy/internal/flog"
	"lucy/internal/metrics"
	"lucy/internal/pkg/buffer"

	"github.com/txthinking/socks5"
)

func (h *Handler) TCPHandle(server *socks5.Server, conn *net.TCPConn, r *socks5.Request) error {
	if r.Cmd == socks5.CmdUDP {
		flog.Debugf("SOCKS5 UDP_ASSOCIATE from %s", conn.RemoteAddr())
		return h.handleUDPAssociate(conn)
	}

	if r.Cmd == socks5.CmdConnect {
		flog.Debugf("SOCKS5 CONNECT from %s to %s", conn.RemoteAddr(), r.Address())
		if h.streams > 1 {
			return h.handleTCPBond(conn, r)
		}
		return h.handleTCPConnect(conn, r)
	}

	flog.Debugf("unsupported SOCKS5 command %d from %s", r.Cmd, conn.RemoteAddr())
	return nil
}

func (h *Handler) handleTCPConnect(conn *net.TCPConn, r *socks5.Request) error {
	flog.Infof("SOCKS5 accepted TCP connection %s -> %s", conn.RemoteAddr(), r.Address())

	if err := sendConnectReply(conn); err != nil {
		return err
	}

	strm, err := h.provider.TCP(r.Address())
	if err != nil {
		flog.Errorf("SOCKS5 failed to establish stream for %s -> %s: %v", conn.RemoteAddr(), r.Address(), err)
		return err
	}
	defer strm.Close()

	cid := metrics.Tracker.Register(metrics.ConnSOCKSTCP, conn.RemoteAddr().String(), r.Address(), strm.SID())
	defer metrics.Tracker.Unregister(cid)

	flog.Debugf("SOCKS5 stream %d created for %s -> %s", strm.SID(), conn.RemoteAddr(), r.Address())

	errCh := make(chan error, 2)
	go func() {
		err := buffer.CopyT(conn, metrics.NewTrackerReader(strm, cid))
		errCh <- err
	}()
	go func() {
		err := buffer.CopyT(metrics.NewTrackerWriter(strm, cid), conn)
		errCh <- err
	}()

	for i := 0; i < 2; i++ {
		select {
		case <-errCh:
		case <-h.ctx.Done():
			flog.Debugf("SOCKS5 connection %s -> %s closed due to shutdown", conn.RemoteAddr(), r.Address())
			return nil
		}
	}

	flog.Debugf("SOCKS5 connection %s -> %s closed", conn.RemoteAddr(), r.Address())
	return nil
}

// handleTCPBond opens multiple streams and uses bonded I/O for higher throughput.
func (h *Handler) handleTCPBond(conn *net.TCPConn, r *socks5.Request) error {
	flog.Infof("SOCKS5 bonded TCP connection %s -> %s (%d streams)", conn.RemoteAddr(), r.Address(), h.streams)

	if err := sendConnectReply(conn); err != nil {
		return err
	}

	streams, err := h.provider.TCPBond(r.Address(), h.streams)
	if err != nil {
		flog.Errorf("SOCKS5 failed to establish bonded streams for %s -> %s: %v", conn.RemoteAddr(), r.Address(), err)
		return err
	}
	defer func() {
		for _, s := range streams {
			s.Close()
		}
	}()

	// Build io.Reader list for the bonded reader (download direction)
	readers := make([]io.Reader, len(streams))
	for i, s := range streams {
		readers[i] = s
	}
	bondR := bond.NewReader(readers)

	// Upload: curl -> stream 0 (raw, no bonding — requests are tiny)
	// Download: all streams (bonded) -> curl
	errCh := make(chan error, 2)
	go func() {
		err := buffer.CopyT(conn, bondR)
		errCh <- err
	}()
	go func() {
		err := buffer.CopyT(streams[0], conn)
		errCh <- err
	}()

	for i := 0; i < 2; i++ {
		select {
		case <-errCh:
		case <-h.ctx.Done():
			flog.Debugf("SOCKS5 bonded connection %s -> %s closed due to shutdown", conn.RemoteAddr(), r.Address())
			return nil
		}
	}

	flog.Debugf("SOCKS5 bonded connection %s -> %s closed", conn.RemoteAddr(), r.Address())
	return nil
}

// sendConnectReply writes the SOCKS5 CONNECT success response.
func sendConnectReply(conn *net.TCPConn) error {
	buf := make([]byte, 0, 4+1+255+2)
	buf = append(buf, socks5.Ver)
	buf = append(buf, socks5.RepSuccess)
	buf = append(buf, 0x00)

	addr := conn.LocalAddr().(*net.TCPAddr)
	if ip4 := addr.IP.To4(); ip4 != nil {
		buf = append(buf, socks5.ATYPIPv4)
		buf = append(buf, ip4...)
	} else if ip6 := addr.IP.To16(); ip6 != nil {
		buf = append(buf, socks5.ATYPIPv6)
		buf = append(buf, ip6...)
	} else {
		host := addr.IP.String()
		buf = append(buf, socks5.ATYPDomain)
		buf = append(buf, byte(len(host)))
		buf = append(buf, host...)
	}
	buf = append(buf, byte(addr.Port>>8), byte(addr.Port&0xff))
	_, err := conn.Write(buf)
	return err
}
