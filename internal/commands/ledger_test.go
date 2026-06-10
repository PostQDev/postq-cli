package commands

import (
	"crypto/sha512"
	"encoding/hex"
	"testing"
)

// Mirrors apps/api/src/lib/ledger/index.ts entryHash: H(prev || canonical(payload)).
func TestCanonicalizeMatchesEntryHashSHA512(t *testing.T) {
	payload := map[string]interface{}{
		"eventType": "key.created",
		"data":      map[string]interface{}{"b": float64(2), "a": float64(1)},
	}
	canon := canonicalize(payload)
	// keys must be sorted at every level, no whitespace.
	want := `{"data":{"a":1,"b":2},"eventType":"key.created"}`
	if canon != want {
		t.Fatalf("canonicalize mismatch:\n got: %s\nwant: %s", canon, want)
	}

	prev := make([]byte, sha512.Size) // SHA-512 genesis = 64 zero bytes
	h := sha512.New()
	h.Write(prev)
	h.Write([]byte(canon))
	got := hex.EncodeToString(h.Sum(nil))
	if len(got) != sha512.Size*2 {
		t.Fatalf("expected 128 hex chars, got %d", len(got))
	}
}

func TestHashForHexLen(t *testing.T) {
	if _, err := hashForHexLen(64); err != nil {
		t.Fatalf("64 hex (SHA-256) should be recognized: %v", err)
	}
	if _, err := hashForHexLen(128); err != nil {
		t.Fatalf("128 hex (SHA-512) should be recognized: %v", err)
	}
	if _, err := hashForHexLen(40); err == nil {
		t.Fatal("unrecognized length must error")
	}
}

// Merkle math must be hash-agnostic and produce the right digest size.
func TestMerkleRootBothHashes(t *testing.T) {
	entries := [][]byte{[]byte("a"), []byte("b"), []byte("c")}

	sha512Hash, _ := hashForHexLen(128)
	r512 := merkleRoot(entries, sha512Hash)
	if len(r512) != sha512.Size {
		t.Fatalf("SHA-512 merkle root should be 64 bytes, got %d", len(r512))
	}

	sha256Hash, _ := hashForHexLen(64)
	r256 := merkleRoot(entries, sha256Hash)
	if len(r256) != 32 {
		t.Fatalf("SHA-256 merkle root should be 32 bytes, got %d", len(r256))
	}

	// Different hash functions must yield different roots (no accidental reuse).
	if hex.EncodeToString(r512[:32]) == hex.EncodeToString(r256) {
		t.Fatal("SHA-512 and SHA-256 roots collided — impossible")
	}

	// Single-leaf tree returns the leaf hash directly (RFC 6962).
	one := merkleRoot([][]byte{[]byte("x")}, sha512Hash)
	leaf := leafHash([]byte("x"), sha512Hash)
	if hex.EncodeToString(one) != hex.EncodeToString(leaf) {
		t.Fatal("single-leaf merkle root must equal the leaf hash")
	}
}
