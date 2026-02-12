// Package crypto provides encryption, key derivation, and authentication tokens.
package crypto

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

// TunnelCrypto handles encryption, decryption, and auth tokens.
type TunnelCrypto struct {
	secret   []byte
	sendKey  []byte
	recvKey  []byte
	sendSeq  uint64
	recvSeq  uint64
	isServer bool
}

// NewTunnelCrypto creates a new crypto instance.
// isServer determines key direction (client→server vs server→client).
func NewTunnelCrypto(secret string, isServer bool) (*TunnelCrypto, error) {
	tc := &TunnelCrypto{
		secret:   []byte(secret),
		isServer: isServer,
	}
	if err := tc.deriveKeys(); err != nil {
		return nil, err
	}
	return tc, nil
}

func (tc *TunnelCrypto) deriveKeys() error {
	// HKDF-SHA256 to derive 64 bytes of key material
	hkdfReader := hkdf.New(sha256.New, tc.secret, []byte("smtp-tunnel-v1"), []byte("tunnel-keys"))
	keyMaterial := make([]byte, 64)
	if _, err := io.ReadFull(hkdfReader, keyMaterial); err != nil {
		return fmt.Errorf("hkdf derive: %w", err)
	}

	c2sKey := keyMaterial[:32]
	s2cKey := keyMaterial[32:]

	if tc.isServer {
		tc.sendKey = s2cKey
		tc.recvKey = c2sKey
	} else {
		tc.sendKey = c2sKey
		tc.recvKey = s2cKey
	}
	return nil
}

// Encrypt encrypts plaintext with ChaCha20-Poly1305.
// Returns: nonce(12) + ciphertext + tag(16).
func (tc *TunnelCrypto) Encrypt(plaintext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(tc.sendKey)
	if err != nil {
		return nil, err
	}

	seq := atomic.AddUint64(&tc.sendSeq, 1) - 1

	// Nonce = seq(8 bytes big-endian) + random(4 bytes)
	nonce := make([]byte, chacha20poly1305.NonceSize)
	binary.BigEndian.PutUint64(nonce[:8], seq)
	if _, err := rand.Read(nonce[8:]); err != nil {
		return nil, err
	}

	ciphertext := aead.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// Decrypt decrypts data encrypted with Encrypt.
func (tc *TunnelCrypto) Decrypt(data []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(tc.recvKey)
	if err != nil {
		return nil, err
	}

	if len(data) < chacha20poly1305.NonceSize+aead.Overhead() {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce := data[:chacha20poly1305.NonceSize]
	ciphertext := data[chacha20poly1305.NonceSize:]

	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}

	atomic.AddUint64(&tc.recvSeq, 1)
	return plaintext, nil
}

// GenerateAuthToken creates an HMAC-SHA256 auth token for SMTP AUTH.
func GenerateAuthToken(secret, username string, timestamp int64) string {
	msg := fmt.Sprintf("smtp-tunnel-auth:%s:%d", username, timestamp)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(msg))
	macBytes := mac.Sum(nil)
	token := fmt.Sprintf("%s:%d:%s", username, timestamp, base64.StdEncoding.EncodeToString(macBytes))
	return base64.StdEncoding.EncodeToString([]byte(token))
}

// VerifyAuthToken verifies an auth token against known users.
// Returns (valid, username).
func VerifyAuthToken(token string, users map[string]string, maxAge int64) (bool, string) {
	decoded, err := base64.StdEncoding.DecodeString(token)
	if err != nil {
		return false, ""
	}

	parts := strings.SplitN(string(decoded), ":", 3)
	if len(parts) != 3 {
		return false, ""
	}

	username := parts[0]
	timestamp, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return false, ""
	}

	// Check freshness
	now := time.Now().Unix()
	if math.Abs(float64(now-timestamp)) > float64(maxAge) {
		return false, ""
	}

	// Look up user secret
	secret, ok := users[username]
	if !ok {
		return false, ""
	}

	// Regenerate expected token and compare
	expected := GenerateAuthToken(secret, username, timestamp)
	if hmac.Equal([]byte(token), []byte(expected)) {
		return true, username
	}
	return false, ""
}

// GenerateSecret creates a crypto-random base64url secret.
func GenerateSecret() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}
