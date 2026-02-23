package socks

import (
	"io"
	"net"
	"lucy/internal/flog"
	"lucy/internal/metrics"
	"lucy/internal/pkg/buffer"
	"sync"
	"time"

	"github.com/txthinking/socks5"
)

var socksUDPCIDs sync.Map

func (h *Handler) UDPHandle(server *socks5.Server, addr *net.UDPAddr, d *socks5.Datagram) error {
	strm, new, k, err := h.provider.UDP(addr.String(), d.Address())
	if err != nil {
		flog.Errorf("SOCKS5 failed to establish UDP stream for %s -> %s: %v", addr, d.Address(), err)
		return err
	}
	strm.SetWriteDeadline(time.Now().Add(8 * time.Second))
	_, err = strm.Write(d.Data)
	strm.SetWriteDeadline(time.Time{})
	if err != nil {
		flog.Errorf("SOCKS5 failed to forward %d bytes from %s -> %s: %v", len(d.Data), addr, d.Address(), err)
		h.provider.CloseUDP(k)
		return err
	}

	var cid uint64
	if new {
		flog.Infof("SOCKS5 accepted UDP connection %s -> %s", addr, d.Address())
		cid = metrics.Tracker.Register(metrics.ConnSOCKSUDP, addr.String(), d.Address(), strm.SID())
		socksUDPCIDs.Store(k, cid)
		go func() {
			bp := buffer.GetUDP()
			defer buffer.PutUDP(bp)
			buf := *bp

			defer func() {
				flog.Debugf("SOCKS5 UDP stream %d closed for %s -> %s", strm.SID(), addr, d.Address())
				metrics.Tracker.Unregister(cid)
				socksUDPCIDs.Delete(k)
				h.provider.CloseUDP(k)
			}()
			for {
				select {
				case <-h.ctx.Done():
					return
				default:
					strm.SetDeadline(time.Now().Add(8 * time.Second))
					n, err := strm.Read(buf)
					strm.SetDeadline(time.Time{})
					if err != nil {
						flog.Debugf("SOCKS5 UDP stream %d read error for %s -> %s: %v", strm.SID(), addr, d.Address(), err)
						return
					}
					dd := socks5.NewDatagram(d.Atyp, d.DstAddr, d.DstPort, buf[:n])
					_, err = server.UDPConn.WriteToUDP(dd.Bytes(), addr)
					if err != nil {
						flog.Errorf("SOCKS5 failed to write UDP response %d bytes to %s: %v", len(dd.Bytes()), addr, err)
						return
					}
					if info := metrics.Tracker.Get(cid); info != nil {
						info.BytesRX.Add(int64(n))
					}
				}
			}
		}()
	} else {
		if val, ok := socksUDPCIDs.Load(k); ok {
			cid = val.(uint64)
		}
	}

	if info := metrics.Tracker.Get(cid); info != nil {
		info.BytesTX.Add(int64(len(d.Data)))
	}
	return nil
}

func (h *Handler) handleUDPAssociate(conn *net.TCPConn) error {
	addr := conn.LocalAddr().(*net.TCPAddr)

	buf := make([]byte, 0, 4+1+255+2)
	buf = append(buf, socks5.Ver)
	buf = append(buf, socks5.RepSuccess)
	buf = append(buf, 0x00)

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

	if _, err := conn.Write(buf); err != nil {
		return err
	}
	flog.Debugf("SOCKS5 accepted UDP_ASSOCIATE from %s, waiting for TCP connection to close", conn.RemoteAddr())

	done := make(chan error, 1)
	go func() {
		_, err := io.Copy(io.Discard, conn)
		done <- err
	}()

	select {
	case err := <-done:
		if err != nil && h.ctx.Err() == nil {
			flog.Errorf("SOCKS5 TCP connection for UDP associate closed with: %v", err)
		}
	case <-h.ctx.Done():
		conn.Close()
		<-done
		flog.Debugf("SOCKS5 UDP_ASSOCIATE connection %s closed due to shutdown", conn.RemoteAddr())
	}

	flog.Debugf("SOCKS5 UDP_ASSOCIATE TCP connection %s closed", conn.RemoteAddr())
	return nil
}
