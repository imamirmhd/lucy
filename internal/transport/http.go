package transport

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"strings"
	"time"

	"lucy/internal/config"
	"lucy/internal/crypto"
)

// Transport handles the low-level connection establishment (HTTP/HTTPS handshake).
type Transport struct {
	Config    *config.Config
	TLSConfig *tls.Config
}

// New creates a new Transport.
func New(cfg *config.Config, tlsCfg *tls.Config) *Transport {
	return &Transport{Config: cfg, TLSConfig: tlsCfg}
}

// ClientHandshake establishes an HTTP-based tunnel connection.
// It performs:
// 1. TCP/TLS connection to server.
// 2. HTTP Request with specific headers (User-Agent, etc.).
// 3. Waiting for "101 Switching Protocols" or "200 OK" with hijack.
func (t *Transport) ClientHandshake(conn net.Conn, serverHost string) (net.Conn, error) {
	// 1. Pick a random host from config for SNI/Host header
	hosts := t.Config.Transport.Hosts
	if len(hosts) == 0 {
		// Fallback if empty (should be validated in config)
		hosts = []string{serverHost}
	}
	// Simple random selection
	host := hosts[rand.Intn(len(hosts))]
	
	// If native TLS is enabled, we need to upgrade the raw conn if not already done
	// (Note: caller might have done TCP dial, but we handle TLS here to support SNI rotation)
	var processingConn net.Conn = conn
	
	if t.Config.Transport.Type == "https" {
		tlsCfg := t.TLSConfig.Clone()
		tlsCfg.ServerName = host // SNI
		tlsConn := tls.Client(conn, tlsCfg)
		if err := tlsConn.Handshake(); err != nil {
			conn.Close()
			return nil, fmt.Errorf("tls handshake to %s: %w", host, err)
		}
		processingConn = tlsConn
	}

	// 2. Generate Authentication Token
	// We use the same HMAC token logic as before, but put it in a header/cookie
	timestamp := time.Now().Unix()
	token := crypto.GenerateAuthToken(t.Config.Client.Secret, t.Config.Client.Username, timestamp)

	// 3. Construct HTTP Request
	// Method randomization
	method := "GET"
	if len(t.Config.Transport.Methods) > 0 {
		// Weighted or random mix logic here. For now simple random.
		method = t.Config.Transport.Methods[rand.Intn(len(t.Config.Transport.Methods))]
	} else {
		// Default if not set
		if rand.Float32() < 0.5 {
			method = "POST"
		}
	}

	// Path randomization
	path := "/"
	if len(t.Config.Transport.RequestPaths) > 0 {
		path = t.Config.Transport.RequestPaths[rand.Intn(len(t.Config.Transport.RequestPaths))]
	}

	req, err := http.NewRequest(method, "https://"+host+path, nil)
	if err != nil {
		processingConn.Close()
		return nil, fmt.Errorf("create request: %w", err)
	}

	// Headers
	req.Header.Set("Host", host)
	req.Header.Set("User-Agent", t.Config.Transport.UserAgent)
	
	// Default fake headers
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket") // Or custom value
	
	// Auth Header (X-Auth-Token or Cookie)
	req.Header.Set("X-Lucy-Token", token)

	// Custom headers from config
	for k, v := range t.Config.Transport.Headers {
		req.Header.Set(k, v)
	}

	// Write Request
	if err := req.Write(processingConn); err != nil {
		processingConn.Close()
		return nil, fmt.Errorf("write request: %w", err)
	}

	// 4. Read Response
	resp, err := http.ReadResponse(bufio.NewReader(processingConn), req)
	if err != nil {
		processingConn.Close()
		return nil, fmt.Errorf("read response: %w", err)
	}
	
	// Expect 101 Switching Protocols
	if resp.StatusCode != 101 {
		// Reads body to be polite before closing (mimic browser)
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		processingConn.Close()
		return nil, fmt.Errorf("unexpected status: %s", resp.Status)
	}

	// Connection upgraded!
	return processingConn, nil
}

// ServerHandshake handles the server-side HTTP request.
// It returns (username, upgraded_conn, error).
// If auth fails, it handles the "fake" response internally and returns error.
func ServerHandshake(conn net.Conn, tlsConfig *tls.Config, config *config.Config, users map[string]string) (string, net.Conn, error) {
	// If HTTPS, perform handshake
	var processingConn net.Conn = conn
	
	if config.Transport.Type == "https" {
		tlsConn := tls.Server(conn, tlsConfig)
		// We can't verify SNI here strictly against one host if we support "domain fronting" / mix_host.
		// So we just handshake.
		if err := tlsConn.Handshake(); err != nil {
			return "", nil, fmt.Errorf("tls handshake: %w", err)
		}
		processingConn = tlsConn
	}

	// Read HTTP Request
	// We need to use bufio to read request but keep the buffer for the connection
	bufConn := bufio.NewReader(processingConn)
	req, err := http.ReadRequest(bufConn)
	if err != nil {
		processingConn.Close()
		return "", nil, fmt.Errorf("read request: %w", err)
	}

	// Check for Auth Token
	token := req.Header.Get("X-Lucy-Token")
	if token == "" {
		// Fallback to cookie?
		// checkCookie(req)
	}

	valid, username := crypto.VerifyAuthToken(token, users, 300)
	if !valid {
		// --- STEALTH ACTION ---
		// Serve fake content based on request path
		// For now, simple 404 or static HTML
		// For now, simple 404 or static HTML
		serveFakeContent(processingConn, req, config)
		processingConn.Close()
		return "", nil, fmt.Errorf("auth failed")
	}

	// Auth Success - Upgrade Connection
	resp := &http.Response{
		StatusCode: 101,
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     make(http.Header),
	}
	resp.Header.Set("Connection", "Upgrade")
	resp.Header.Set("Upgrade", "websocket")
	resp.Header.Set("X-Lucy-Version", "1.0")

	// Write response
	if err := resp.Write(processingConn); err != nil {
		processingConn.Close()
		return "", nil, fmt.Errorf("write response: %w", err)
	}

	// Return raw connection (unbuffered if possible, but we read into bufio)
	// We need to wrap it if bufio has buffered data (unlikely after ReadRequest if no body)
	if bufConn.Buffered() > 0 {
		return username, &bufferedConn{processingConn, bufConn}, nil
	}

	return username, processingConn, nil
}

func serveFakeContent(conn net.Conn, req *http.Request, config *config.Config) {
	// If redirect mode is enabled and a RedirectTo URL is set
	if config.Transport.Type == "redirect" && config.Transport.RedirectTo != "" {
		location := config.Transport.RedirectTo
		resp := &http.Response{
			StatusCode:    301,
			ProtoMajor:    1,
			ProtoMinor:    1,
			ContentLength: 0,
			Body:          io.NopCloser(strings.NewReader("")),
			Header:        make(http.Header),
		}
		resp.Header.Set("Location", location)
		resp.Header.Set("Server", "Apache/2.4.41 (Ubuntu)")
		resp.Header.Set("Connection", "close")
		resp.Write(conn)
		return
	}

	// Simple fake Apache/Nginx response
	body := "<html><body><h1>It works!</h1></body></html>"
	resp := &http.Response{
		StatusCode:    200,
		ProtoMajor:    1,
		ProtoMinor:    1,
		ContentLength: int64(len(body)),
		Body:          io.NopCloser(strings.NewReader(body)),
		Header:        make(http.Header),
	}
	resp.Header.Set("Content-Type", "text/html")
	resp.Header.Set("Server", "Apache/2.4.41 (Ubuntu)")
	resp.Header.Set("Date", time.Now().Format(http.TimeFormat))
	
	resp.Write(conn)
}

type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (b *bufferedConn) Read(p []byte) (int, error) {
	return b.r.Read(p)
}
