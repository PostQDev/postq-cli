package apiclient

import (
	"bytes"
	"strings"
	"testing"
)

func TestReadResponseBodyRejectsOversize(t *testing.T) {
	_, err := readResponseBody(bytes.NewReader(make([]byte, maxResponseBytes+1)))
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("readResponseBody() error = %v, want size-limit error", err)
	}
}

func TestRedactAPIKeys(t *testing.T) {
	input := "invalid key pq_live_abcdefghijklmnopqrstuvwxyz and pq_test_123456789"
	got := redact(input)
	if strings.Contains(got, "pq_live_") || strings.Contains(got, "pq_test_") {
		t.Fatalf("redact() leaked API key: %q", got)
	}
	if strings.Count(got, "[REDACTED_API_KEY]") != 2 {
		t.Fatalf("redact() = %q", got)
	}
}
