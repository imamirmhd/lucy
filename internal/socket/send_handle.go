package socket

import (
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"lucy/internal/conf"
	"lucy/internal/metrics"
	"lucy/internal/pkg/hash"
	"lucy/internal/pkg/iterator"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
)

type TCPF struct {
	tcpF       iterator.Iterator[conf.TCPF]
	clientTCPF map[uint64]*iterator.Iterator[conf.TCPF]
	mu         sync.RWMutex
}

type StealthCfg struct {
	RealDstIP    net.IP
	DecoySources []net.IP
}

type StealthRegistry struct {
	configs map[uint64]*StealthCfg
	mu      sync.RWMutex
}

type SendHandle struct {
	handle      *pcap.Handle
	srcIPv4     net.IP
	srcIPv4RHWA net.HardwareAddr
	srcIPv6     net.IP
	srcIPv6RHWA net.HardwareAddr
	srcPort     uint16
	time        uint32
	tsCounter   uint32
	tcpF        TCPF
	stealth     StealthRegistry
	ethPool     sync.Pool
	ipv4Pool    sync.Pool
	ipv6Pool    sync.Pool
	tcpPool     sync.Pool
	bufPool     sync.Pool
	tsDataPool  sync.Pool

	// Batched writer
	writeCh chan []byte
	rawPool sync.Pool

	// Pre-serialized static headers
	ethIPv4Hdr [14]byte // Ethernet header for IPv4
	ethIPv6Hdr [14]byte // Ethernet header for IPv6
	ipv4Tmpl   [20]byte // IPv4 header template
	closeOnce  sync.Once
}

func NewSendHandle(cfg *conf.Network) (*SendHandle, error) {
	handle, err := newHandle(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to open pcap handle: %w", err)
	}

	// SetDirection is not fully supported on Windows Npcap, so skip it
	if runtime.GOOS != "windows" {
		if err := handle.SetDirection(pcap.DirectionOut); err != nil {
			return nil, fmt.Errorf("failed to set pcap direction out: %v", err)
		}
	}

	sh := &SendHandle{
		handle:  handle,
		srcPort: uint16(cfg.Port),
		tcpF:    TCPF{tcpF: iterator.Iterator[conf.TCPF]{Items: cfg.TCP.LF}, clientTCPF: make(map[uint64]*iterator.Iterator[conf.TCPF])},
		stealth: StealthRegistry{configs: make(map[uint64]*StealthCfg)},
		time:    uint32(time.Now().UnixNano() / int64(time.Millisecond)),
		writeCh: make(chan []byte, 4096),
		ethPool: sync.Pool{
			New: func() any {
				return &layers.Ethernet{SrcMAC: cfg.Interface.HardwareAddr}
			},
		},
		ipv4Pool: sync.Pool{
			New: func() any {
				return &layers.IPv4{}
			},
		},
		ipv6Pool: sync.Pool{
			New: func() any {
				return &layers.IPv6{}
			},
		},
		tcpPool: sync.Pool{
			New: func() any {
				return &layers.TCP{}
			},
		},
		bufPool: sync.Pool{
			New: func() any {
				return gopacket.NewSerializeBuffer()
			},
		},
		tsDataPool: sync.Pool{
			New: func() any {
				b := make([]byte, 8)
				return &b
			},
		},
		rawPool: sync.Pool{
			New: func() any {
				b := make([]byte, 0, 1600) // max MTU
				return b
			},
		},
	}

	// Pre-serialize static Ethernet headers
	if cfg.IPv4.Addr != nil {
		sh.srcIPv4 = cfg.IPv4.Addr.IP
		sh.srcIPv4RHWA = cfg.IPv4.Router
		// Ethernet: DstMAC(6) + SrcMAC(6) + Type(2)
		copy(sh.ethIPv4Hdr[0:6], cfg.IPv4.Router)
		copy(sh.ethIPv4Hdr[6:12], cfg.Interface.HardwareAddr)
		binary.BigEndian.PutUint16(sh.ethIPv4Hdr[12:14], uint16(layers.EthernetTypeIPv4))

		// Pre-serialize static IPv4 header template
		sh.ipv4Tmpl[0] = 0x45        // Version(4) + IHL(5)
		sh.ipv4Tmpl[1] = 184         // TOS/DSCP
		// [2:4] = total length (patched per packet)
		// [4:6] = identification (0)
		sh.ipv4Tmpl[6] = 0x40        // Flags: Don't Fragment
		sh.ipv4Tmpl[7] = 0x00        // Fragment offset
		sh.ipv4Tmpl[8] = 64          // TTL
		sh.ipv4Tmpl[9] = 6           // Protocol: TCP
		// [10:12] = header checksum (computed per packet)
		copy(sh.ipv4Tmpl[12:16], cfg.IPv4.Addr.IP.To4())
		// [16:20] = dst IP (patched per packet)
	}
	if cfg.IPv6.Addr != nil {
		sh.srcIPv6 = cfg.IPv6.Addr.IP
		sh.srcIPv6RHWA = cfg.IPv6.Router
		copy(sh.ethIPv6Hdr[0:6], cfg.IPv6.Router)
		copy(sh.ethIPv6Hdr[6:12], cfg.Interface.HardwareAddr)
		binary.BigEndian.PutUint16(sh.ethIPv6Hdr[12:14], uint16(layers.EthernetTypeIPv6))
	}

	// Start batched writer goroutine
	go sh.batchWriter()

	return sh, nil
}

// batchWriter is a dedicated goroutine that writes packets to the pcap handle.
// This decouples serialization from the pcap write syscall.
func (h *SendHandle) batchWriter() {
	for pkt := range h.writeCh {
		h.handle.WritePacketData(pkt)
		// Return to pool: reset length but keep capacity
		h.rawPool.Put(pkt[:0])
	}
}

func (h *SendHandle) buildIPv4Header(dstIP net.IP) *layers.IPv4 {
	ip := h.ipv4Pool.Get().(*layers.IPv4)
	*ip = layers.IPv4{
		Version:  4,
		IHL:      5,
		TOS:      184,
		TTL:      64,
		Flags:    layers.IPv4DontFragment,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    h.srcIPv4,
		DstIP:    dstIP,
	}
	return ip
}

func (h *SendHandle) buildIPv6Header(dstIP net.IP) *layers.IPv6 {
	ip := h.ipv6Pool.Get().(*layers.IPv6)
	*ip = layers.IPv6{
		Version:      6,
		TrafficClass: 184,
		HopLimit:     64,
		NextHeader:   layers.IPProtocolTCP,
		SrcIP:        h.srcIPv6,
		DstIP:        dstIP,
	}
	return ip
}

func (h *SendHandle) buildTCPHeader(dstPort uint16, f conf.TCPF) (*layers.TCP, *[]byte) {
	tcp := h.tcpPool.Get().(*layers.TCP)
	*tcp = layers.TCP{
		SrcPort: layers.TCPPort(h.srcPort),
		DstPort: layers.TCPPort(dstPort),
		FIN:     f.FIN, SYN: f.SYN, RST: f.RST, PSH: f.PSH, ACK: f.ACK, URG: f.URG, ECE: f.ECE, CWR: f.CWR, NS: f.NS,
		Window: 65535,
	}

	counter := atomic.AddUint32(&h.tsCounter, 1)
	tsVal := h.time + (counter >> 3)

	tsData := h.tsDataPool.Get().(*[]byte)
	ts := *tsData

	if f.SYN {
		binary.BigEndian.PutUint32(ts[0:4], tsVal)
		binary.BigEndian.PutUint32(ts[4:8], 0)
		tcp.Options = []layers.TCPOption{
			{OptionType: layers.TCPOptionKindMSS, OptionLength: 4, OptionData: []byte{0x05, 0xb4}},
			{OptionType: layers.TCPOptionKindSACKPermitted, OptionLength: 2},
			{OptionType: layers.TCPOptionKindTimestamps, OptionLength: 10, OptionData: ts},
			{OptionType: layers.TCPOptionKindNop},
			{OptionType: layers.TCPOptionKindWindowScale, OptionLength: 3, OptionData: []byte{8}},
		}
		tcp.Seq = 1 + (counter & 0x7)
		tcp.Ack = 0
		if f.ACK {
			tcp.Ack = tcp.Seq + 1
		}
	} else {
		tsEcr := tsVal - (counter%200 + 50)
		binary.BigEndian.PutUint32(ts[0:4], tsVal)
		binary.BigEndian.PutUint32(ts[4:8], tsEcr)
		tcp.Options = []layers.TCPOption{
			{OptionType: layers.TCPOptionKindNop},
			{OptionType: layers.TCPOptionKindNop},
			{OptionType: layers.TCPOptionKindTimestamps, OptionLength: 10, OptionData: ts},
		}
		seq := h.time + (counter << 7)
		tcp.Seq = seq
		tcp.Ack = seq - (counter & 0x3FF) + 1400
	}

	return tcp, tsData
}

// Write serializes and sends a packet. For IPv4 non-SYN packets, uses manual byte
// assembly to bypass gopacket overhead. Falls back to SerializeLayers for other cases.
func (h *SendHandle) Write(payload []byte, addr *net.UDPAddr) error {
	dstIP := addr.IP
	dstPort := uint16(addr.Port)
	f := h.getClientTCPF(dstIP, dstPort)
	srcIP, realDstIP := h.getStealthCfg(dstIP, dstPort)

	if realDstIP != nil {
		dstIP = realDstIP
	}

	// Fast path: IPv4 + non-SYN — manual byte assembly
	if dstIP4 := dstIP.To4(); dstIP4 != nil && !f.SYN {
		err := h.writeFastIPv4(payload, dstIP4, dstPort, f, srcIP)
		if err == nil {
			return nil
		}
		// Fall through to slow path on error
	}

	// Slow path: IPv6, SYN, or fast path failure
	return h.writeGopacket(payload, addr, dstIP, dstPort, f, srcIP)
}

// writeFastIPv4 builds a raw Ethernet+IPv4+TCP packet manually without gopacket.
func (h *SendHandle) writeFastIPv4(payload []byte, dstIP4 net.IP, dstPort uint16, f conf.TCPF, srcIPOverride net.IP) error {
	counter := atomic.AddUint32(&h.tsCounter, 1)
	tsVal := h.time + (counter >> 3)
	tsEcr := tsVal - (counter%200 + 50)

	// TCP options: NOP(1) + NOP(1) + Timestamps(10) = 12 bytes
	const tcpOptLen = 12
	const ethLen = 14
	const ipLen = 20
	const tcpBaseLen = 20
	const tcpLen = tcpBaseLen + tcpOptLen
	headerLen := ethLen + ipLen + tcpLen
	totalLen := headerLen + len(payload)

	pkt := h.rawPool.Get().([]byte)
	pkt = pkt[:totalLen]

	// --- Ethernet Header (14 bytes) ---
	copy(pkt[0:14], h.ethIPv4Hdr[:])

	// --- IPv4 Header (20 bytes) ---
	copy(pkt[14:34], h.ipv4Tmpl[:])
	binary.BigEndian.PutUint16(pkt[16:18], uint16(ipLen+tcpLen+len(payload))) // Total length
	copy(pkt[30:34], dstIP4) // Dst IP

	// Override source IP if decoy is active
	if srcIPOverride != nil {
		if v4 := srcIPOverride.To4(); v4 != nil {
			copy(pkt[26:30], v4)
		}
	}

	// IPv4 header checksum
	pkt[24] = 0
	pkt[25] = 0
	csum := ipChecksum(pkt[14:34])
	binary.BigEndian.PutUint16(pkt[24:26], csum)

	// --- TCP Header (32 bytes: 20 base + 12 options) ---
	tcpStart := 34
	binary.BigEndian.PutUint16(pkt[tcpStart:], h.srcPort)
	binary.BigEndian.PutUint16(pkt[tcpStart+2:], dstPort)

	seq := h.time + (counter << 7)
	ack := seq - (counter & 0x3FF) + 1400
	binary.BigEndian.PutUint32(pkt[tcpStart+4:], seq)
	binary.BigEndian.PutUint32(pkt[tcpStart+8:], ack)

	// Data offset (8 = (32 bytes / 4)) << 4
	pkt[tcpStart+12] = 8 << 4

	// TCP flags
	var flags byte
	if f.FIN { flags |= 0x01 }
	if f.SYN { flags |= 0x02 }
	if f.RST { flags |= 0x04 }
	if f.PSH { flags |= 0x08 }
	if f.ACK { flags |= 0x10 }
	if f.URG { flags |= 0x20 }
	if f.ECE { flags |= 0x40 }
	if f.CWR { flags |= 0x80 }
	pkt[tcpStart+13] = flags
	// NS flag in data offset byte
	if f.NS {
		pkt[tcpStart+12] |= 0x01
	}

	binary.BigEndian.PutUint16(pkt[tcpStart+14:], 65535) // Window
	// [tcpStart+16:18] = checksum (computed below)
	// [tcpStart+18:20] = urgent pointer (0)
	pkt[tcpStart+16] = 0
	pkt[tcpStart+17] = 0
	pkt[tcpStart+18] = 0
	pkt[tcpStart+19] = 0

	// TCP Options: NOP + NOP + Timestamps
	optStart := tcpStart + 20
	pkt[optStart] = 1   // NOP
	pkt[optStart+1] = 1 // NOP
	pkt[optStart+2] = 8 // Timestamps kind
	pkt[optStart+3] = 10 // Timestamps length
	binary.BigEndian.PutUint32(pkt[optStart+4:], tsVal)
	binary.BigEndian.PutUint32(pkt[optStart+8:], tsEcr)

	// Copy payload
	copy(pkt[headerLen:], payload)

	// TCP checksum (pseudo-header + TCP header + payload)
	tcpCsum := tcpChecksum(pkt[26:30], pkt[30:34], pkt[tcpStart:])
	binary.BigEndian.PutUint16(pkt[tcpStart+16:], tcpCsum)

	// Send via batched writer
	metrics.PacketsTX.Add(1)
	metrics.BytesTX.Add(int64(len(payload)))

	h.writeCh <- pkt
	return nil
}

// writeGopacket is the slow path using gopacket.SerializeLayers.
func (h *SendHandle) writeGopacket(payload []byte, addr *net.UDPAddr, dstIP net.IP, dstPort uint16, f conf.TCPF, srcIPOverride net.IP) error {
	buf := h.bufPool.Get().(gopacket.SerializeBuffer)
	ethLayer := h.ethPool.Get().(*layers.Ethernet)
	tcpLayer, tsData := h.buildTCPHeader(dstPort, f)

	var ipLayer gopacket.SerializableLayer
	var ipPoolPut func()

	if dstIP.To4() != nil {
		ip := h.buildIPv4Header(dstIP)
		if srcIPOverride != nil {
			if v4 := srcIPOverride.To4(); v4 != nil {
				ip.SrcIP = v4
			}
		}
		ipLayer = ip
		tcpLayer.SetNetworkLayerForChecksum(ip)
		ethLayer.DstMAC = h.srcIPv4RHWA
		ethLayer.EthernetType = layers.EthernetTypeIPv4
		ipPoolPut = func() { h.ipv4Pool.Put(ip) }
	} else {
		ip := h.buildIPv6Header(dstIP)
		if srcIPOverride != nil {
			if v6 := srcIPOverride.To16(); v6 != nil {
				ip.SrcIP = v6
			}
		}
		ipLayer = ip
		tcpLayer.SetNetworkLayerForChecksum(ip)
		ethLayer.DstMAC = h.srcIPv6RHWA
		ethLayer.EthernetType = layers.EthernetTypeIPv6
		ipPoolPut = func() { h.ipv6Pool.Put(ip) }
	}

	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, ethLayer, ipLayer, tcpLayer, gopacket.Payload(payload)); err != nil {
		buf.Clear()
		h.bufPool.Put(buf)
		h.ethPool.Put(ethLayer)
		h.tcpPool.Put(tcpLayer)
		h.tsDataPool.Put(tsData)
		ipPoolPut()
		return err
	}

	raw := h.rawPool.Get().([]byte)
	raw = append(raw[:0], buf.Bytes()...)
	metrics.PacketsTX.Add(1)
	metrics.BytesTX.Add(int64(len(payload)))
	h.writeCh <- raw

	buf.Clear()
	h.bufPool.Put(buf)
	h.ethPool.Put(ethLayer)
	h.tcpPool.Put(tcpLayer)
	h.tsDataPool.Put(tsData)
	ipPoolPut()

	return nil
}

// ipChecksum computes the IPv4 header checksum.
func ipChecksum(header []byte) uint16 {
	var sum uint32
	for i := 0; i < len(header)-1; i += 2 {
		sum += uint32(header[i])<<8 | uint32(header[i+1])
	}
	if len(header)%2 != 0 {
		sum += uint32(header[len(header)-1]) << 8
	}
	for sum > 0xFFFF {
		sum = (sum >> 16) + (sum & 0xFFFF)
	}
	return ^uint16(sum)
}

// tcpChecksum computes the TCP checksum including the pseudo-header.
func tcpChecksum(srcIP, dstIP, tcpSegment []byte) uint16 {
	var sum uint32
	// Pseudo-header
	for i := 0; i < len(srcIP)-1; i += 2 {
		sum += uint32(srcIP[i])<<8 | uint32(srcIP[i+1])
	}
	for i := 0; i < len(dstIP)-1; i += 2 {
		sum += uint32(dstIP[i])<<8 | uint32(dstIP[i+1])
	}
	sum += 6 // Protocol: TCP
	sum += uint32(len(tcpSegment))

	// TCP segment
	for i := 0; i < len(tcpSegment)-1; i += 2 {
		sum += uint32(tcpSegment[i])<<8 | uint32(tcpSegment[i+1])
	}
	if len(tcpSegment)%2 != 0 {
		sum += uint32(tcpSegment[len(tcpSegment)-1]) << 8
	}

	for sum > 0xFFFF {
		sum = (sum >> 16) + (sum & 0xFFFF)
	}
	return ^uint16(sum)
}

func (h *SendHandle) getClientTCPF(dstIP net.IP, dstPort uint16) conf.TCPF {
	h.tcpF.mu.RLock()
	ff := h.tcpF.clientTCPF[hash.IPAddr(dstIP, dstPort)]
	h.tcpF.mu.RUnlock()
	if ff != nil {
		return ff.Next()
	}
	return h.tcpF.tcpF.Next()
}

func (h *SendHandle) setClientTCPF(addr net.Addr, f []conf.TCPF) {
	a := *addr.(*net.UDPAddr)
	h.tcpF.mu.Lock()
	h.tcpF.clientTCPF[hash.IPAddr(a.IP, uint16(a.Port))] = &iterator.Iterator[conf.TCPF]{Items: f}
	h.tcpF.mu.Unlock()
}

func (h *SendHandle) getStealthCfg(dstIP net.IP, dstPort uint16) (srcIP net.IP, realDstIP net.IP) {
	if v4 := dstIP.To4(); v4 != nil {
		dstIP = v4
	}
	h.stealth.mu.RLock()
	cfg := h.stealth.configs[hash.IPAddr(dstIP, dstPort)]
	h.stealth.mu.RUnlock()
	if cfg == nil {
		return nil, nil
	}
	if len(cfg.DecoySources) > 0 {
		srcIP = cfg.DecoySources[rand.Intn(len(cfg.DecoySources))]
	}
	realDstIP = cfg.RealDstIP
	return
}

func (h *SendHandle) setStealthCfg(dstIP net.IP, dstPort uint16, realDstIP net.IP, decoySources []net.IP) {
	if v4 := dstIP.To4(); v4 != nil {
		dstIP = v4
	}
	h.stealth.mu.Lock()
	h.stealth.configs[hash.IPAddr(dstIP, dstPort)] = &StealthCfg{
		RealDstIP:    realDstIP,
		DecoySources: decoySources,
	}
	h.stealth.mu.Unlock()
}

func (h *SendHandle) Close() {
	h.closeOnce.Do(func() {
		if h.writeCh != nil {
			close(h.writeCh)
		}
		if h.handle != nil {
			h.handle.Close()
		}
	})
}
