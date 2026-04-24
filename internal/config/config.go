// Package config handles persistence of CLI credentials in ~/.postq/config.json.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
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
	return os.WriteFile(path, data, 0o600)
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
	return c, nil
}

// MaskKey returns a redacted version safe to print (e.g. `pq_live_a1b2…`).
func MaskKey(key string) string {
	if len(key) <= 12 {
		return "(none)"
	}
	return key[:12] + "…"
}
