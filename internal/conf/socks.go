package conf

import (
	"net"
	"time"
)

type SOCKS5 struct {
	Listen_   string       `yaml:"listen"`
	Username  string       `yaml:"username"`
	Password  string       `yaml:"password"`
	RateLimit RateLimit    `yaml:"rate_limit"`
	Listen    *net.UDPAddr `yaml:"-"`
}

type RateLimit struct {
	Enabled    *bool  `yaml:"enabled"`
	MaxFails   int    `yaml:"max_fails"`
	BlockFor_  string `yaml:"block_for"`
	BlockFor   time.Duration `yaml:"-"`
}

func (c *SOCKS5) setDefaults() {
	if c.RateLimit.Enabled == nil {
		t := true
		c.RateLimit.Enabled = &t
	}
	if c.RateLimit.MaxFails == 0 {
		c.RateLimit.MaxFails = 5
	}
	if c.RateLimit.BlockFor_ == "" {
		c.RateLimit.BlockFor_ = "5m"
	}
}

func (c *SOCKS5) validate() []error {
	var errors []error

	addr, err := validateAddr(c.Listen_, true)
	if err != nil {
		errors = append(errors, err)
	}
	c.Listen = addr

	if c.RateLimit.MaxFails < 1 {
		c.RateLimit.MaxFails = 1
	}

	dur, err := time.ParseDuration(c.RateLimit.BlockFor_)
	if err != nil {
		errors = append(errors, err)
	} else {
		c.RateLimit.BlockFor = dur
	}

	return errors
}
