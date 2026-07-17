// Package config handles persistence of CLI credentials in ~/.postq/config.json.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// DefaultEndpoint is the production PostQ API base URL.
const DefaultEndpoint = "https://api.postq.dev"

// Config is what gets written to ~/.postq/config.json.
type Config struct {
	APIEndpoint string `json:"apiEndpoint"`
	APIKey      string `json:"apiKey"`
}

// Path returns the absolute path to the config file.
func Path() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("home dir: %w", err)
	}
	return filepath.Join(home, ".postq", "config.json"), nil
}

// Load reads ~/.postq/config.json. Returns an empty Config if the file
// doesn't exist (so the caller can decide whether that's an error).
func Load() (*Config, error) {
	path, err := Path()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return &Config{APIEndpoint: DefaultEndpoint}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var c Config
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if c.APIEndpoint == "" {
		c.APIEndpoint = DefaultEndpoint
	}
	return &c, nil
}

// Save writes the config file with mode 0600.
func Save(c *Config) error {
	if err := ValidateEndpoint(c.APIEndpoint); err != nil {
		return err
	}
	path, err := Path()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("mkdir: %w", err)
	}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".config-*")
	if err != nil {
		return fmt.Errorf("create config temp file: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod config: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write config: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync config: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close config: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("replace config: %w", err)
	}
	if runtime.GOOS == "windows" {
		return nil
	}
	dirHandle, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("open config directory: %w", err)
	}
	defer dirHandle.Close()
	if err := dirHandle.Sync(); err != nil {
		return fmt.Errorf("sync config directory: %w", err)
	}
	return nil
}

// Delete removes the config file (used by `postq auth logout`).
func Delete() error {
	path, err := Path()
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// Resolve returns the effective endpoint and API key, layering env vars over
// the saved config and finally over flags (which the caller passes in).
func Resolve(flagEndpoint, flagKey string) (*Config, error) {
	c, err := Load()
	if err != nil {
		return nil, err
	}
	if v := os.Getenv("POSTQ_API_ENDPOINT"); v != "" {
		c.APIEndpoint = v
	}
	if v := os.Getenv("POSTQ_API_KEY"); v != "" {
		c.APIKey = v
	}
	if flagEndpoint != "" {
		c.APIEndpoint = flagEndpoint
	}
	if flagKey != "" {
		c.APIKey = flagKey
	}
	if err := ValidateEndpoint(c.APIEndpoint); err != nil {
		return nil, err
	}
	return c, nil
}

// ValidateEndpoint prevents credentials from being sent over plaintext HTTP.
// Loopback HTTP remains available for local API development and tests.
func ValidateEndpoint(endpoint string) error {
	if strings.TrimSpace(endpoint) == "" {
		return errors.New("API endpoint is required")
	}
	u, err := url.Parse(endpoint)
	if err != nil || u.Host == "" {
		return fmt.Errorf("invalid API endpoint %q", endpoint)
	}
	if u.User != nil {
		return errors.New("API endpoint must not contain embedded credentials")
	}
	if u.Scheme == "https" {
		return nil
	}
	host := u.Hostname()
	if u.Scheme == "http" && (host == "localhost" || isLoopback(host)) {
		return nil
	}
	return fmt.Errorf("API endpoint must use HTTPS (HTTP is allowed only for loopback development)")
}

func isLoopback(host string) bool {
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// MaskKey returns a redacted version safe to print (e.g. `pq_live_a1b2…`).
func MaskKey(key string) string {
	if len(key) <= 12 {
		return "(none)"
	}
	return key[:12] + "…"
}
