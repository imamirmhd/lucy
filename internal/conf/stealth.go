package conf

import (
	"fmt"
	"net"
)

type Stealth struct {
	DecoySources_   []string `yaml:"decoy_sources"`
	DecoyResponses_ []string `yaml:"decoy_responses"`
	RealIP_         string   `yaml:"real_ip"`
	DecoySources    []net.IP `yaml:"-"`
	DecoyResponses  []net.IP `yaml:"-"`
	RealIP          net.IP   `yaml:"-"`
}

func (s *Stealth) Enabled() bool {
	return len(s.DecoySources) > 0
}

func (s *Stealth) setDefaults() {}

func (s *Stealth) validate() []error {
	var errors []error

	for i, addr := range s.DecoySources_ {
		ip := net.ParseIP(addr)
		if ip == nil {
			errors = append(errors, fmt.Errorf("stealth decoy_sources[%d]: invalid IP address '%s'", i, addr))
			continue
		}
		s.DecoySources = append(s.DecoySources, ip)
	}

	for i, addr := range s.DecoyResponses_ {
		ip := net.ParseIP(addr)
		if ip == nil {
			errors = append(errors, fmt.Errorf("stealth decoy_responses[%d]: invalid IP address '%s'", i, addr))
			continue
		}
		s.DecoyResponses = append(s.DecoyResponses, ip)
	}

	// real_ip is mandatory when stealth is enabled
	if s.Enabled() {
		if s.RealIP_ == "" {
			errors = append(errors, fmt.Errorf("stealth real_ip is required when decoy_sources are configured"))
		} else {
			ip := net.ParseIP(s.RealIP_)
			if ip == nil {
				errors = append(errors, fmt.Errorf("stealth real_ip: invalid IP address '%s'", s.RealIP_))
			}
			s.RealIP = ip
		}
	}

	return errors
}
