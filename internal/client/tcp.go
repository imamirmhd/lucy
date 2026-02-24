package client

import (
	"crypto/rand"
	"encoding/binary"
	"lucy/internal/flog"
	"lucy/internal/protocol"
	"lucy/internal/tnet"
)

func (c *Client) TCP(addr string) (tnet.Strm, error) {
	strm, err := c.newStrm()
	if err != nil {
		flog.Debugf("failed to create stream for TCP %s: %v", addr, err)
		return nil, err
	}

	tAddr, err := tnet.NewAddr(addr)
	if err != nil {
		flog.Debugf("invalid TCP address %s: %v", addr, err)
		strm.Close()
		return nil, err
	}

	p := protocol.Proto{Type: protocol.PTCP, Addr: tAddr}
	err = p.Write(strm)
	if err != nil {
		flog.Debugf("failed to write TCP protocol header for %s on stream %d: %v", addr, strm.SID(), err)
		strm.Close()
		return nil, err
	}

	flog.Debugf("TCP stream %d created for %s", strm.SID(), addr)
	return strm, nil
}

// TCPBond opens count streams across different KCP connections and
// sends a PMULTI header on each, all sharing the same bond ID.
// The returned streams are indexed 0..count-1.
func (c *Client) TCPBond(addr string, count int) ([]tnet.Strm, error) {
	if count <= 1 {
		strm, err := c.TCP(addr)
		if err != nil {
			return nil, err
		}
		return []tnet.Strm{strm}, nil
	}

	tAddr, err := tnet.NewAddr(addr)
	if err != nil {
		return nil, err
	}

	// Generate random bond ID
	var idBuf [4]byte
	rand.Read(idBuf[:])
	bondID := binary.BigEndian.Uint32(idBuf[:])

	streams := make([]tnet.Strm, count)
	for i := range count {
		strm, err := c.newStrm()
		if err != nil {
			// Clean up already-opened streams
			for j := range i {
				streams[j].Close()
			}
			return nil, err
		}

		p := protocol.Proto{
			Type:      protocol.PMULTI,
			Addr:      tAddr,
			BondID:    bondID,
			BondTotal: uint8(count),
			BondIndex: uint8(i),
		}
		if err := p.Write(strm); err != nil {
			strm.Close()
			for j := range i {
				streams[j].Close()
			}
			return nil, err
		}

		streams[i] = strm
		flog.Debugf("bond %08x: stream %d/%d (sid=%d) created for %s", bondID, i, count, strm.SID(), addr)
	}

	flog.Infof("bond %08x: %d streams opened for %s", bondID, count, addr)
	return streams, nil
}
