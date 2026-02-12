// Package users provides user management for the unified TOML config.
package users

import (
	"fmt"
	"os"
	"strings"

	"lucy/internal/config"
	"lucy/internal/crypto"

	"github.com/BurntSushi/toml"
)

// AddUser adds a new user to the config file.
func AddUser(configPath, username, secret string, whitelist []string, logging bool) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		// If file doesn't exist, create with defaults
		if os.IsNotExist(err) {
			cfg = &config.Config{}
		} else {
			// Try to load raw TOML to preserve structure
			cfg = &config.Config{}
		}
	}

	// Check if user already exists
	for _, u := range cfg.Server.Users {
		if u.Username == username {
			return fmt.Errorf("user %q already exists", username)
		}
	}

	// Generate secret if empty
	if secret == "" {
		var err error
		secret, err = crypto.GenerateSecret()
		if err != nil {
			return fmt.Errorf("generate secret: %w", err)
		}
	}

	if whitelist == nil {
		whitelist = []string{"0.0.0.0/0"}
	}

	// Add user
	cfg.Server.Users = append(cfg.Server.Users, config.UserEntry{
		Username:  username,
		Secret:    secret,
		Whitelist: whitelist,
		Logging:   logging,
	})

	// Write back
	return writeConfig(configPath, cfg)
}

// DelUser removes a user from the config file.
func DelUser(configPath, username string) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}

	found := false
	newUsers := make([]config.UserEntry, 0, len(cfg.Server.Users))
	for _, u := range cfg.Server.Users {
		if u.Username == username {
			found = true
			continue
		}
		newUsers = append(newUsers, u)
	}

	if !found {
		return fmt.Errorf("user %q not found", username)
	}

	cfg.Server.Users = newUsers
	return writeConfig(configPath, cfg)
}

// ListUsers returns user information as formatted strings.
func ListUsers(configPath string, verbose bool) (string, error) {
	cfg, err := config.Load(configPath)
	if err != nil {
		return "", err
	}

	if len(cfg.Server.Users) == 0 {
		return "No users configured.\nUse 'lucy-server adduser <name>' to add users.", nil
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Users (%d):\n", len(cfg.Server.Users)))
	sb.WriteString(strings.Repeat("-", 60) + "\n")

	for _, u := range cfg.Server.Users {
		if verbose {
			sb.WriteString(fmt.Sprintf("\n  %s:\n", u.Username))
			secretPreview := u.Secret
			if len(secretPreview) > 12 {
				secretPreview = secretPreview[:8] + "..." + secretPreview[len(secretPreview)-4:]
			}
			sb.WriteString(fmt.Sprintf("    Secret: %s\n", secretPreview))
			if len(u.Whitelist) > 0 {
				sb.WriteString(fmt.Sprintf("    Whitelist: %s\n", strings.Join(u.Whitelist, ", ")))
			} else {
				sb.WriteString("    Whitelist: (any IP)\n")
			}
			logStr := "enabled"
			if !u.Logging {
				logStr = "disabled"
			}
			sb.WriteString(fmt.Sprintf("    Logging: %s\n", logStr))
		} else {
			extras := ""
			if len(u.Whitelist) > 0 && !(len(u.Whitelist) == 1 && u.Whitelist[0] == "0.0.0.0/0") {
				extras += fmt.Sprintf(" [%d IPs]", len(u.Whitelist))
			}
			if !u.Logging {
				extras += " [no-log]"
			}
			sb.WriteString(fmt.Sprintf("  %s%s\n", u.Username, extras))
		}
	}

	return sb.String(), nil
}

func writeConfig(path string, cfg *config.Config) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	enc := toml.NewEncoder(f)
	return enc.Encode(cfg)
}
