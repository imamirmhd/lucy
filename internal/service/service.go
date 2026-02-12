// Package service provides install, service management, and wizard functionality.
package service

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const (
	// BinDir is the default installation directory for binaries.
	BinDir = "/usr/local/bin"
	// BaseDir is the root config directory.
	BaseDir = "/etc/lucy"
	// ConfigsDir stores per-instance config files.
	ConfigsDir = "/etc/lucy/configs"
	// CertsDir stores generated certificates.
	CertsDir = "/etc/lucy/certs"
	// ServicePrefix is the systemd service name prefix.
	ServicePrefix = "lucy"
)

// EnsureDirectories creates all required directories.
func EnsureDirectories() error {
	dirs := []string{BaseDir, ConfigsDir, CertsDir}
	for _, d := range dirs {
		if err := os.MkdirAll(d, 0755); err != nil {
			return fmt.Errorf("create %s: %w", d, err)
		}
	}
	return nil
}

// InstallBinary copies the currently running binary to /usr/local/bin/<name>.
func InstallBinary(name string) error {
	src, err := os.Executable()
	if err != nil {
		return fmt.Errorf("find executable: %w", err)
	}
	src, err = filepath.EvalSymlinks(src)
	if err != nil {
		return fmt.Errorf("resolve symlink: %w", err)
	}

	dst := filepath.Join(BinDir, name)

	// Don't copy if already in place
	if src == dst {
		fmt.Printf("Binary already at %s\n", dst)
		return nil
	}

	if err := copyFile(src, dst, 0755); err != nil {
		return fmt.Errorf("copy binary: %w", err)
	}
	fmt.Printf("Installed %s -> %s\n", filepath.Base(src), dst)
	return nil
}

// Install registers a config file as a systemd service.
func Install(configFile, binaryName string) error {
	if err := EnsureDirectories(); err != nil {
		return err
	}

	// Determine unique service name from config filename
	base := filepath.Base(configFile)
	name := strings.TrimSuffix(base, filepath.Ext(base))
	serviceName := fmt.Sprintf("%s-%s-%s", ServicePrefix, binaryName, name)

	// Copy config file
	dstConfig := filepath.Join(ConfigsDir, base)
	if err := copyFile(configFile, dstConfig, 0644); err != nil {
		return fmt.Errorf("copy config: %w", err)
	}
	fmt.Printf("Config copied to %s\n", dstConfig)

	// Generate systemd unit
	binPath := filepath.Join(BinDir, fmt.Sprintf("%s-%s", ServicePrefix, binaryName))
	unit := generateUnit(serviceName, binPath, dstConfig, binaryName)

	unitPath := fmt.Sprintf("/etc/systemd/system/%s.service", serviceName)
	if err := os.WriteFile(unitPath, []byte(unit), 0644); err != nil {
		return fmt.Errorf("write service file: %w", err)
	}
	fmt.Printf("Service file written to %s\n", unitPath)

	// Reload and enable
	if err := systemctl("daemon-reload"); err != nil {
		return err
	}
	if err := systemctl("enable", "--now", serviceName); err != nil {
		return err
	}
	fmt.Printf("Service %s enabled and started\n", serviceName)
	return nil
}

// List lists all lucy systemd services.
func List() error {
	files, err := filepath.Glob("/etc/systemd/system/lucy-*.service")
	if err != nil {
		return err
	}

	if len(files) == 0 {
		fmt.Println("No lucy services registered.")
		return nil
	}

	fmt.Printf("%-40s  %-10s\n", "SERVICE", "STATUS")
	fmt.Println(strings.Repeat("-", 55))

	for _, f := range files {
		name := strings.TrimSuffix(filepath.Base(f), ".service")
		status := getServiceStatus(name)
		fmt.Printf("%-40s  %-10s\n", name, status)
	}
	return nil
}

// Remove stops, disables, and removes a service.
func Remove(name string) error {
	serviceName := resolveServiceName(name)

	_ = systemctl("stop", serviceName)
	_ = systemctl("disable", serviceName)

	unitPath := fmt.Sprintf("/etc/systemd/system/%s.service", serviceName)
	if err := os.Remove(unitPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove service file: %w", err)
	}

	_ = systemctl("daemon-reload")
	fmt.Printf("Service %s removed\n", serviceName)
	return nil
}

// Logs shows journal logs for a service.
func Logs(name string, lines int) error {
	serviceName := resolveServiceName(name)
	if lines <= 0 {
		lines = 50
	}
	cmd := exec.Command("journalctl", "-u", serviceName, "-n", fmt.Sprintf("%d", lines), "--no-pager")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// Stop stops a service.
func Stop(name string) error {
	serviceName := resolveServiceName(name)
	if err := systemctl("stop", serviceName); err != nil {
		return err
	}
	fmt.Printf("Service %s stopped\n", serviceName)
	return nil
}

// Restart restarts a service.
func Restart(name string) error {
	serviceName := resolveServiceName(name)
	if err := systemctl("restart", serviceName); err != nil {
		return err
	}
	fmt.Printf("Service %s restarted\n", serviceName)
	return nil
}

func resolveServiceName(name string) string {
	if strings.HasPrefix(name, ServicePrefix) {
		return name
	}
	return fmt.Sprintf("%s-%s", ServicePrefix, name)
}

func generateUnit(serviceName, binPath, configPath, role string) string {
	desc := "SMTP Tunnel Server"
	if role == "client" {
		desc = "SMTP Tunnel Client"
	}

	extra := ""
	if role == "server" {
		extra = "LimitNOFILE=65535\n"
	}

	return fmt.Sprintf(`[Unit]
Description=%s (%s)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=%s run -c %s
Restart=on-failure
RestartSec=5
%sStandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
`, desc, serviceName, binPath, configPath, extra)
}

func getServiceStatus(name string) string {
	out, err := exec.Command("systemctl", "is-active", name).CombinedOutput()
	if err != nil {
		return "inactive"
	}
	return strings.TrimSpace(string(out))
}

func systemctl(args ...string) error {
	cmd := exec.Command("systemctl", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func copyFile(src, dst string, perm os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	defer out.Close()

	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	return out.Sync()
}
