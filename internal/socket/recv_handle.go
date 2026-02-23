package socket

import (
	"fmt"
	"net"
	"lucy/internal/conf"
	"lucy/internal/metrics"
	"runtime"
	"sync"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
)

type RecvHandle struct {
	handle  *pcap.Handle
	parser  *gopacket.DecodingLayerParser
	eth     layers.Ethernet
	ipv4    layers.IPv4
	ipv6    layers.IPv6
	tcp     layers.TCP
	udp     layers.UDP
	payload gopacket.Payload
	decoded []gopacket.LayerType

	addrPool sync.Pool
}

func NewRecvHandle(cfg *conf.Network) (*RecvHandle, error) {
	handle, err := newHandle(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to open pcap handle: %w", err)
	}

	// SetDirection is not fully supported on Windows Npcap, so skip it
	if runtime.GOOS != "windows" {
		if err := handle.SetDirection(pcap.DirectionIn); err != nil {
			return nil, fmt.Errorf("failed to set pcap direction in: %v", err)
		}
	}

	filter := fmt.Sprintf("tcp and dst port %d", cfg.Port)
	if err := handle.SetBPFFilter(filter); err != nil {
		return nil, fmt.Errorf("failed to set BPF filter: %w", err)
	}

	rh := &RecvHandle{
		handle:  handle,
		decoded: make([]gopacket.LayerType, 0, 6),
		addrPool: sync.Pool{
			New: func() any {
				return &net.UDPAddr{IP: make(net.IP, 16)}
			},
		},
	}

	rh.parser = gopacket.NewDecodingLayerParser(
		layers.LayerTypeEthernet,
		&rh.eth,
		&rh.ipv4,
		&rh.ipv6,
		&rh.tcp,
		&rh.udp,
		&rh.payload,
	)
	rh.parser.IgnoreUnsupported = true

	return rh, nil
}

func (h *RecvHandle) Read() ([]byte, net.Addr, error) {
	data, _, err := h.handle.ReadPacketData()
	if err != nil {
		return nil, nil, err
	}

	h.decoded = h.decoded[:0]
	if err := h.parser.DecodeLayers(data, &h.decoded); err != nil {
		return nil, nil, nil
	}

	addr := h.addrPool.Get().(*net.UDPAddr)
	addr.Port = 0
	addr.Zone = ""

	var hasNetwork, hasTransport, hasPayload bool

	for _, lt := range h.decoded {
		switch lt {
		case layers.LayerTypeIPv4:
			addr.IP = append(addr.IP[:0], h.ipv4.SrcIP...)
			hasNetwork = true
		case layers.LayerTypeIPv6:
			addr.IP = append(addr.IP[:0], h.ipv6.SrcIP...)
			hasNetwork = true
		case layers.LayerTypeTCP:
			addr.Port = int(h.tcp.SrcPort)
			hasTransport = true
		case layers.LayerTypeUDP:
			addr.Port = int(h.udp.SrcPort)
			hasTransport = true
		case gopacket.LayerTypePayload:
			hasPayload = true
		}
	}

	if !hasNetwork || !hasTransport || !hasPayload {
		h.addrPool.Put(addr)
		return nil, nil, nil
	}

	p := h.payload.Payload()
	metrics.PacketsRX.Add(1)
	metrics.BytesRX.Add(int64(len(p)))

	return p, addr, nil
}

func (h *RecvHandle) Close() {
	if h.handle != nil {
		h.handle.Close()
	}
}
