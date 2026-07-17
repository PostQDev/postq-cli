package config

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestValidateEndpoint(t *testing.T) {
	tests := []struct {
		name     string
		endpoint string
		wantErr  bool
	}{
		{name: "production HTTPS", endpoint: "https://api.postq.dev"},
		{name: "localhost HTTP", endpoint: "http://localhost:4000"},
		{name: "IPv4 loopback HTTP", endpoint: "http://127.0.0.1:4000"},
		{name: "IPv6 loopback HTTP", endpoint: "http://[::1]:4000"},
		{name: "remote HTTP", endpoint: "http://api.example.com", wantErr: true},
		{name: "embedded credentials", endpoint: "https://user:pass@example.com", wantErr: true},
		{name: "missing scheme", endpoint: "api.example.com", wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateEndpoint(tc.endpoint)
			if (err != nil) != tc.wantErr {
				t.Fatalf("ValidateEndpoint(%q) error = %v, wantErr=%v", tc.endpoint, err, tc.wantErr)
			}
		})
	}
}

func TestSaveReplacesPermissiveConfigWithMode0600(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not expose POSIX permission bits")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	dir := filepath.Join(home, ".postq")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte(`{"apiEndpoint":"https://api.postq.dev"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := Save(&Config{APIEndpoint: DefaultEndpoint, APIKey: "pq_live_test"}); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("config mode = %o, want 600", got)
	}
}
