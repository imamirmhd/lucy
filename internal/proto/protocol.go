// Package proto defines the binary framing protocol used after SMTP handshake.
package proto

import (
	"encoding/binary"
	"fmt"
	"io"
	"sync"
)

// Frame types.
const (
	FrameData        byte = 0x01
	FrameConnect     byte = 0x02
	FrameConnectOK   byte = 0x03
	FrameConnectFail byte = 0x04
	FrameClose       byte = 0x05
	FramePing        byte = 0x06
	FramePong        byte = 0x07
)

// HeaderSize is the fixed header length: type(1) + channel_id(2) + payload_len(2).
const HeaderSize = 5

// MaxPayloadSize is the maximum payload per frame.
const MaxPayloadSize = 65535

// Frame represents a single protocol frame.
type Frame struct {
	Type      byte
	ChannelID uint16
	Payload   []byte
}

// MakeConnectPayload encodes a host:port pair for a CONNECT frame.
func MakeConnectPayload(host string, port uint16) []byte {
	hostBytes := []byte(host)
	buf := make([]byte, 1+len(hostBytes)+2)
	buf[0] = byte(len(hostBytes))
	copy(buf[1:], hostBytes)
	binary.BigEndian.PutUint16(buf[1+len(hostBytes):], port)
	return buf
}

// ParseConnectPayload decodes host and port from a CONNECT frame payload.
func ParseConnectPayload(payload []byte) (string, uint16, error) {
	if len(payload) < 4 {
		return "", 0, fmt.Errorf("connect payload too short")
	}
	hostLen := int(payload[0])
	if len(payload) < 1+hostLen+2 {
		return "", 0, fmt.Errorf("connect payload truncated")
	}
	host := string(payload[1 : 1+hostLen])
	port := binary.BigEndian.Uint16(payload[1+hostLen:])
	return host, port, nil
}

// FrameWriter provides thread-safe frame writing.
type FrameWriter struct {
	w  io.Writer
	mu sync.Mutex
}

// NewFrameWriter wraps a writer with mutex-protected frame writing.
func NewFrameWriter(w io.Writer) *FrameWriter {
	return &FrameWriter{w: w}
}

// WriteFrame writes a single frame atomically.
func (fw *FrameWriter) WriteFrame(f Frame) error {
	fw.mu.Lock()
	defer fw.mu.Unlock()

	hdr := [HeaderSize]byte{}
	hdr[0] = f.Type
	binary.BigEndian.PutUint16(hdr[1:3], f.ChannelID)
	binary.BigEndian.PutUint16(hdr[3:5], uint16(len(f.Payload)))

	if _, err := fw.w.Write(hdr[:]); err != nil {
		return err
	}
	if len(f.Payload) > 0 {
		if _, err := fw.w.Write(f.Payload); err != nil {
			return err
		}
	}
	return nil
}

// ReadFrame reads a single frame from the reader.
func ReadFrame(r io.Reader) (Frame, error) {
	hdr := [HeaderSize]byte{}
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return Frame{}, err
	}

	f := Frame{
		Type:      hdr[0],
		ChannelID: binary.BigEndian.Uint16(hdr[1:3]),
	}
	payloadLen := binary.BigEndian.Uint16(hdr[3:5])

	if payloadLen > 0 {
		f.Payload = make([]byte, payloadLen)
		if _, err := io.ReadFull(r, f.Payload); err != nil {
			return Frame{}, err
		}
	}

	return f, nil
}

// TypeName returns a human-readable name for a frame type.
func TypeName(t byte) string {
	switch t {
	case FrameData:
		return "DATA"
	case FrameConnect:
		return "CONNECT"
	case FrameConnectOK:
		return "CONNECT_OK"
	case FrameConnectFail:
		return "CONNECT_FAIL"
	case FrameClose:
		return "CLOSE"
	case FramePing:
		return "PING"
	case FramePong:
		return "PONG"
	default:
		return fmt.Sprintf("UNKNOWN(0x%02x)", t)
	}
}
