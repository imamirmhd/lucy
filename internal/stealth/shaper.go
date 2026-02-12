// Package stealth implements traffic shaping for DPI evasion.
package stealth

import (
	"crypto/rand"
	"encoding/binary"
	mathrand "math/rand"
	"time"
)

// Shaper implements traffic shaping and padding.
type Shaper struct {
	MinDelayMs       int
	MaxDelayMs       int
	PaddingSizes     []int
	DummyProbability float64
	Enabled          bool
	rng              *mathrand.Rand
}

// NewShaper creates a traffic shaper from config values.
func NewShaper(enabled bool, minDelay, maxDelay int, sizes []int, dummyProb float64) *Shaper {
	return &Shaper{
		Enabled:          enabled,
		MinDelayMs:       minDelay,
		MaxDelayMs:       maxDelay,
		PaddingSizes:     sizes,
		DummyProbability: dummyProb,
		rng:              mathrand.New(mathrand.NewSource(time.Now().UnixNano())),
	}
}

// Delay introduces a random delay for traffic shaping.
func (s *Shaper) Delay() {
	if !s.Enabled || s.MinDelayMs <= 0 {
		return
	}
	delayMs := s.MinDelayMs + s.rng.Intn(s.MaxDelayMs-s.MinDelayMs+1)
	time.Sleep(time.Duration(delayMs) * time.Millisecond)
}

// PadData pads data to the next standard size.
// Format: data_length(2 bytes) + data + random_padding.
func (s *Shaper) PadData(data []byte) []byte {
	if !s.Enabled || len(s.PaddingSizes) == 0 {
		return data
	}

	dataLen := len(data)
	totalNeeded := dataLen + 2

	// Find next standard size
	targetSize := s.PaddingSizes[len(s.PaddingSizes)-1]
	for _, size := range s.PaddingSizes {
		if totalNeeded <= size {
			targetSize = size
			break
		}
	}

	result := make([]byte, targetSize)
	binary.BigEndian.PutUint16(result[:2], uint16(dataLen))
	copy(result[2:], data)

	// Fill padding with random bytes
	paddingStart := 2 + dataLen
	if paddingStart < targetSize {
		rand.Read(result[paddingStart:])
	}

	return result
}

// UnpadData removes padding from data.
func UnpadData(padded []byte) []byte {
	if len(padded) < 2 {
		return padded
	}
	dataLen := binary.BigEndian.Uint16(padded[:2])
	if int(dataLen)+2 > len(padded) {
		return padded
	}
	return padded[2 : 2+dataLen]
}

// ShouldSendDummy returns true if a dummy message should be sent.
func (s *Shaper) ShouldSendDummy() bool {
	if !s.Enabled {
		return false
	}
	return s.rng.Float64() < s.DummyProbability
}

// GenerateDummy creates random dummy data.
func (s *Shaper) GenerateDummy(minSize, maxSize int) []byte {
	size := minSize + s.rng.Intn(maxSize-minSize+1)
	data := make([]byte, size)
	rand.Read(data)
	return data
}
