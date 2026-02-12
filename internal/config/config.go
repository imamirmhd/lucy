// Package config provides unified TOML configuration for lucy.
package config

import (
	"fmt"
	"os"
	"time"

	"github.com/BurntSushi/toml"
)

// Config is the top-level configuration.
type Config struct {
	Server  ServerConfig    `toml:"server"`
	Client  ClientConfig    `toml:"client"`
	Transport TransportConfig `toml:"transport"`
	Stealth StealthConfig   `toml:"stealth"`
}

// TransportConfig defines the underlying transport mechanism.
type TransportConfig struct {
	Type          string            `toml:"type"`            // "http", "https", "redirect"
	Hosts         []string          `toml:"hosts"`           // List of SNI/Host values
	MixHost       string            `toml:"mix_host"`        // "random", "round-robin"
	Headers       map[string]string `toml:"headers"`         // Custom headers
	UserAgent     string            `toml:"user_agent"`      // "static", "random-desktop", "random-mobile"
	RequestPaths  []string          `toml:"request_paths"`   // List of paths to simulate
	Methods       []string          `toml:"methods"`         // Allowed methods
	MethodMix     string            `toml:"method_mix"`      // "random", "weighted"
	RedirectTo    string            `toml:"redirect_to"`     // For "redirect" mode: where to redirect normal traffic
}

// ServerConfig holds server-side settings.
type ServerConfig struct {
	Listen   string      `toml:"listen"`
	Hostname string      `toml:"hostname"`
	CertFile string      `toml:"cert_file"`
	KeyFile  string      `toml:"key_file"`
	LogLevel string      `toml:"log_level"`
	// TLS removed from here, handled in TransportConfig or per-client/server logic if needed for specific mTLS
	Users    []UserEntry `toml:"users"`
}



// UserEntry defines a single user in the config.
type UserEntry struct {
	Username  string   `toml:"username"`
	Secret    string   `toml:"secret"`
	Whitelist []string `toml:"whitelist"`
	Logging   bool     `toml:"logging"`
}

// ClientConfig holds client-side settings.
type ClientConfig struct {
	Server             string         `toml:"server"`
	Username           string         `toml:"username"`
	Secret             string         `toml:"secret"`
	CACert             string         `toml:"ca_cert"`
	InsecureSkipVerify bool           `toml:"insecure_skip_verify"`
	ReconnectDelay     Duration       `toml:"reconnect_delay"`
	MaxReconnectDelay  Duration       `toml:"max_reconnect_delay"`
	Socks              []SocksEntry   `toml:"socks"`
	Forward            []ForwardEntry `toml:"forward"`
}

// SocksEntry defines a single SOCKS5 listener.
type SocksEntry struct {
	Listen   string `toml:"listen"`
	Username string `toml:"username"`
	Password string `toml:"password"`
}

// ForwardEntry defines a port-forwarding rule.
type ForwardEntry struct {
	Listen   string `toml:"listen"`
	Forward  string `toml:"forward"`
	Protocol string `toml:"protocol"` // "tcp" or "udp"
}

// StealthConfig controls DPI evasion features.
type StealthConfig struct {
	Enabled          bool    `toml:"enabled"`
	MinDelayMs       int     `toml:"min_delay_ms"`
	MaxDelayMs       int     `toml:"max_delay_ms"`
	PaddingSizes     []int   `toml:"padding_sizes"`
	DummyProbability float64 `toml:"dummy_probability"`
}

// Duration wraps time.Duration for TOML string parsing.
type Duration struct {
	time.Duration
}

func (d *Duration) UnmarshalText(text []byte) error {
	var err error
	d.Duration, err = time.ParseDuration(string(text))
	return err
}

func (d Duration) MarshalText() ([]byte, error) {
	return []byte(d.Duration.String()), nil
}

// Load reads and parses a TOML configuration file.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	cfg := &Config{}
	// Set defaults
	cfg.Server.Listen = "0.0.0.0:587"
	cfg.Server.Hostname = "mail.example.com"
	cfg.Server.LogLevel = "info"
	cfg.Server.LogLevel = "info"

	cfg.Transport.Type = "https"
	cfg.Transport.Hosts = []string{"www.google.com"}
	cfg.Transport.MixHost = "random"
	cfg.Transport.UserAgent = "random-desktop"
	cfg.Transport.MethodMix = "random"

	cfg.Client.ReconnectDelay = Duration{2 * time.Second}
	cfg.Client.MaxReconnectDelay = Duration{30 * time.Second}

	cfg.Stealth.MinDelayMs = 50
	cfg.Stealth.MaxDelayMs = 500
	cfg.Stealth.PaddingSizes = []int{4096, 8192, 16384, 32768}
	cfg.Stealth.DummyProbability = 0.1

	if err := toml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	// Set default Logging=true for users if not explicitly set
	for i := range cfg.Server.Users {
		if cfg.Server.Users[i].Secret == "" {
			return nil, fmt.Errorf("user %q has no secret", cfg.Server.Users[i].Username)
		}
	}

	return cfg, nil
}

// Validate checks the config for obvious errors.
func (c *Config) Validate(mode string) error {
	switch mode {
	case "server":
		if c.Server.Listen == "" {
			return fmt.Errorf("server.listen is required")
		}
		if c.Server.CertFile == "" {
			return fmt.Errorf("server.cert_file is required")
		}
		if c.Server.KeyFile == "" {
			return fmt.Errorf("server.key_file is required")
		}
		if len(c.Server.Users) == 0 {
			return fmt.Errorf("at least one [[server.users]] entry is required")
		}
	case "client":
		if c.Client.Server == "" {
			return fmt.Errorf("client.server is required")
		}
		if c.Client.Username == "" {
			return fmt.Errorf("client.username is required")
		}
		if c.Client.Secret == "" {
			return fmt.Errorf("client.secret is required")
		}
		if len(c.Client.Socks) == 0 && len(c.Client.Forward) == 0 {
			return fmt.Errorf("at least one [[client.socks]] or [[client.forward]] entry is required")
		}
		for i, f := range c.Client.Forward {
			if f.Listen == "" {
				return fmt.Errorf("client.forward[%d].listen is required", i)
			}
			if f.Forward == "" {
				return fmt.Errorf("client.forward[%d].forward is required", i)
			}
			proto := f.Protocol
			if proto == "" {
				proto = "tcp"
			}
			if proto != "tcp" && proto != "udp" {
				return fmt.Errorf("client.forward[%d].protocol must be 'tcp' or 'udp'", i)
			}
		}
	}
	return nil
}

// FindUser looks up a user by username.
func (c *Config) FindUser(username string) *UserEntry {
	for i := range c.Server.Users {
		if c.Server.Users[i].Username == username {
			return &c.Server.Users[i]
		}
	}
	return nil
}

// WriteDefault writes a default config file to the given path.
func WriteDefault(path string) error {
	content := `# Lucy Stealth Tunnel Configuration (unified)
# All settings for server, client, transport, stealth, and users in one file.

[server]
listen = "0.0.0.0:443"
hostname = "www.example.com"
cert_file = "server.crt"
key_file = "server.key"
log_level = "info"

# Add users with: lucy-server adduser <name> -c config.toml
# [[server.users]]
# username = "alice"
# secret = "auto-generated-secret"
# whitelist = ["0.0.0.0/0"]
# logging = true

[client]
server = "www.example.com:443"
username = ""
secret = ""
ca_cert = "ca.crt"
insecure_skip_verify = false
reconnect_delay = "2s"
max_reconnect_delay = "30s"

[[client.socks]]
listen = "127.0.0.1:1080"
username = ""
password = ""

# Port forwarding (alternative to SOCKS)
# [[client.forward]]
# listen = "127.0.0.1:8080"
# forward = "internal-server:80"
# protocol = "tcp"  # or "udp"

[transport]
type = "https"
hosts = ["www.google.com", "www.microsoft.com"]
mix_host = "random"
user_agent = "random-desktop"

[stealth]
enabled = true
min_delay_ms = 50
max_delay_ms = 500
padding_sizes = [4096, 8192, 16384, 32768]
dummy_probability = 0.1
`
	return os.WriteFile(path, []byte(content), 0644)
}
