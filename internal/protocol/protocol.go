package protocol

import (
	"encoding/binary"
	"fmt"
	"io"
	"lucy/internal/conf"
	"lucy/internal/tnet"
)

type PType = byte

const (
	PPING PType = 0x01
	PPONG PType = 0x02
	PTCPF PType = 0x03
	PTCP  PType = 0x04
	PUDP  PType = 0x05
)

type Proto struct {
	Type PType
	Addr *tnet.Addr
	TCPF []conf.TCPF
}

// Binary format:
//   [1B type]
//   If PTCP/PUDP: [2B host_len][host_bytes][2B port]
//   If PTCPF:     [1B count][ 2B flags_bitfield ]*count
//   PPING/PPONG:  type byte only

func (p *Proto) Read(r io.Reader) error {
	var hdr [1]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return err
	}
	p.Type = hdr[0]

	switch p.Type {
	case PTCP, PUDP:
		var lenBuf [2]byte
		if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
			return fmt.Errorf("read host length: %w", err)
		}
		hostLen := binary.BigEndian.Uint16(lenBuf[:])
		if hostLen > 255 {
			return fmt.Errorf("host too long: %d", hostLen)
		}

		hostBuf := make([]byte, hostLen)
		if _, err := io.ReadFull(r, hostBuf); err != nil {
			return fmt.Errorf("read host: %w", err)
		}

		var portBuf [2]byte
		if _, err := io.ReadFull(r, portBuf[:]); err != nil {
			return fmt.Errorf("read port: %w", err)
		}

		p.Addr = &tnet.Addr{
			Host: string(hostBuf),
			Port: int(binary.BigEndian.Uint16(portBuf[:])),
		}

	case PTCPF:
		var countBuf [1]byte
		if _, err := io.ReadFull(r, countBuf[:]); err != nil {
			return fmt.Errorf("read tcpf count: %w", err)
		}
		count := int(countBuf[0])
		p.TCPF = make([]conf.TCPF, count)
		for i := range count {
			var fb [2]byte
			if _, err := io.ReadFull(r, fb[:]); err != nil {
				return fmt.Errorf("read tcpf %d: %w", i, err)
			}
			bits := binary.BigEndian.Uint16(fb[:])
			p.TCPF[i] = decodeTCPF(bits)
		}

	case PPING, PPONG:
		// No additional data

	default:
		return fmt.Errorf("unknown protocol type: %d", p.Type)
	}

	return nil
}

func (p *Proto) Write(w io.Writer) error {
	if _, err := w.Write([]byte{p.Type}); err != nil {
		return err
	}

	switch p.Type {
	case PTCP, PUDP:
		if p.Addr == nil {
			return fmt.Errorf("addr required for type %d", p.Type)
		}
		host := []byte(p.Addr.Host)
		pkt := make([]byte, 2+len(host)+2)
		binary.BigEndian.PutUint16(pkt[0:2], uint16(len(host)))
		copy(pkt[2:], host)
		binary.BigEndian.PutUint16(pkt[2+len(host):], uint16(p.Addr.Port))
		if _, err := w.Write(pkt); err != nil {
			return err
		}

	case PTCPF:
		if _, err := w.Write([]byte{byte(len(p.TCPF))}); err != nil {
			return err
		}
		for _, f := range p.TCPF {
			var fb [2]byte
			binary.BigEndian.PutUint16(fb[:], encodeTCPF(f))
			if _, err := w.Write(fb[:]); err != nil {
				return err
			}
		}

	case PPING, PPONG:
		// No additional data
	}

	return nil
}

func encodeTCPF(f conf.TCPF) uint16 {
	var bits uint16
	if f.FIN {
		bits |= 1 << 0
	}
	if f.SYN {
		bits |= 1 << 1
	}
	if f.RST {
		bits |= 1 << 2
	}
	if f.PSH {
		bits |= 1 << 3
	}
	if f.ACK {
		bits |= 1 << 4
	}
	if f.URG {
		bits |= 1 << 5
	}
	if f.ECE {
		bits |= 1 << 6
	}
	if f.CWR {
		bits |= 1 << 7
	}
	if f.NS {
		bits |= 1 << 8
	}
	return bits
}

func decodeTCPF(bits uint16) conf.TCPF {
	return conf.TCPF{
		FIN: bits&(1<<0) != 0,
		SYN: bits&(1<<1) != 0,
		RST: bits&(1<<2) != 0,
		PSH: bits&(1<<3) != 0,
		ACK: bits&(1<<4) != 0,
		URG: bits&(1<<5) != 0,
		ECE: bits&(1<<6) != 0,
		CWR: bits&(1<<7) != 0,
		NS:  bits&(1<<8) != 0,
	}
}
