// Package certs generates self-signed TLS certificates.
package certs

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Options for certificate generation.
type Options struct {
	Hostname  string
	OutputDir string
	Days      int
	KeySize   int
}

// Generate creates CA + server certificates and writes them to disk.
func Generate(opts Options) error {
	if opts.KeySize == 0 {
		opts.KeySize = 2048
	}
	if opts.Days == 0 {
		opts.Days = 1095
	}

	os.MkdirAll(opts.OutputDir, 0755)

	// --- CA ---
	caKey, err := rsa.GenerateKey(rand.Reader, opts.KeySize)
	if err != nil {
		return fmt.Errorf("generate CA key: %w", err)
	}

	caSerial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	caTemplate := &x509.Certificate{
		SerialNumber: caSerial,
		Subject: pkix.Name{
			Country:      []string{"US"},
			Province:     []string{"California"},
			Locality:     []string{"San Francisco"},
			Organization: []string{"SMTP Tunnel"},
			CommonName:   "SMTP Tunnel CA",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(time.Duration(opts.Days*10) * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
	}

	caCertDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return fmt.Errorf("create CA cert: %w", err)
	}
	caCert, err := x509.ParseCertificate(caCertDER)
	if err != nil {
		return fmt.Errorf("parse CA cert: %w", err)
	}

	// --- Server ---
	serverKey, err := rsa.GenerateKey(rand.Reader, opts.KeySize)
	if err != nil {
		return fmt.Errorf("generate server key: %w", err)
	}

	serverSerial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))

	// Build SANs
	dnsNames := []string{opts.Hostname, "localhost"}
	if parts := strings.SplitN(opts.Hostname, ".", 2); len(parts) == 2 {
		dnsNames = append(dnsNames, "smtp."+parts[1])
	}

	var ipAddrs []net.IP
	if ip := net.ParseIP(opts.Hostname); ip != nil {
		ipAddrs = append(ipAddrs, ip)
	}
	ipAddrs = append(ipAddrs, net.IPv4(127, 0, 0, 1))

	serverTemplate := &x509.Certificate{
		SerialNumber: serverSerial,
		Subject: pkix.Name{
			Country:      []string{"US"},
			Province:     []string{"California"},
			Locality:     []string{"San Francisco"},
			Organization: []string{"Example Mail Services"},
			CommonName:   opts.Hostname,
		},
		DNSNames:    dnsNames,
		IPAddresses: ipAddrs,
		NotBefore:   time.Now().Add(-1 * time.Hour),
		NotAfter:    time.Now().Add(time.Duration(opts.Days) * 24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}

	serverCertDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, caCert, &serverKey.PublicKey, caKey)
	if err != nil {
		return fmt.Errorf("create server cert: %w", err)
	}

	// --- Write files ---
	files := map[string]func() error{
		"ca.key": func() error {
			return writeKey(filepath.Join(opts.OutputDir, "ca.key"), caKey)
		},
		"ca.crt": func() error {
			return writeCert(filepath.Join(opts.OutputDir, "ca.crt"), caCertDER)
		},
		"server.key": func() error {
			return writeKey(filepath.Join(opts.OutputDir, "server.key"), serverKey)
		},
		"server.crt": func() error {
			return writeCert(filepath.Join(opts.OutputDir, "server.crt"), serverCertDER)
		},
	}

	for name, fn := range files {
		if err := fn(); err != nil {
			return fmt.Errorf("write %s: %w", name, err)
		}
		fmt.Printf("  Written: %s/%s\n", opts.OutputDir, name)
	}

	return nil
}

func writeKey(path string, key *rsa.PrivateKey) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	return pem.Encode(f, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
}

func writeCert(path string, der []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	defer f.Close()
	return pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: der})
}
