package commands

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"hash"
	"testing"
)

// buildGoldenBundle constructs a ledger bundle exactly the way the API's
// lib/ledger/index.ts produces one (hash chain + RFC 6962 checkpoint), for a
// chosen hash function. This is the CLI↔API contract: the CLI verifier must
// accept what the API emits, for both the legacy SHA-256 and current SHA-512.
func buildGoldenBundle(t *testing.T, newHash func() hash.Hash) ledgerBundle {
	t.Helper()
	hexLen := newHash().Size()

	payloads := []map[string]interface{}{
		{"eventType": "key.created", "subjectId": "k1"},
		{"eventType": "signature.issued", "subjectId": "k1", "data": map[string]interface{}{"alg": "mldsa65+ed25519"}},
		{"eventType": "key.rotated", "subjectId": "k1"},
	}

	prev := make([]byte, hexLen)
	entries := make([]bundleEntry, len(payloads))
	entryHashes := make([][]byte, len(payloads))
	for i, p := range payloads {
		h := newHash()
		h.Write(prev)
		h.Write([]byte(canonicalize(p)))
		eh := h.Sum(nil)
		entries[i] = bundleEntry{
			ID:           "e" + string(rune('0'+i)),
			Seq:          i,
			PrevHashHex:  hex.EncodeToString(prev),
			EntryHashHex: hex.EncodeToString(eh),
			Payload:      p,
		}
		entryHashes[i] = eh
		prev = eh
	}

	// One checkpoint sealing all entries.
	root := merkleRoot(entryHashes, newHash)
	cp := bundleCheckpoint{
		TreeSize:        len(entries),
		MerkleRootHex:   hex.EncodeToString(root),
		SignatureBase64: base64.StdEncoding.EncodeToString([]byte("not-verified-here")),
		SigningKeyID:    "key-1",
	}

	return ledgerBundle{
		Version:     1,
		Org:         "org-test",
		GeneratedAt: "2026-06-09T00:00:00Z",
		Entries:     entries,
		Checkpoints: []bundleCheckpoint{cp},
	}
}

func TestVerifyBundleAcceptsSHA512(t *testing.T) {
	b := buildGoldenBundle(t, sha512.New)
	if err := verifyBundle(b); err != nil {
		t.Fatalf("CLI rejected a valid SHA-512 API bundle: %v", err)
	}
}

func TestVerifyBundleAcceptsLegacySHA256(t *testing.T) {
	b := buildGoldenBundle(t, sha256.New)
	if err := verifyBundle(b); err != nil {
		t.Fatalf("CLI rejected a valid legacy SHA-256 bundle: %v", err)
	}
}

func TestVerifyBundleDetectsTamperedEntry(t *testing.T) {
	b := buildGoldenBundle(t, sha512.New)
	// Flip a payload value without recomputing hashes — must be caught.
	b.Entries[1].Payload["subjectId"] = "k2-TAMPERED"
	if err := verifyBundle(b); err == nil {
		t.Fatal("CLI accepted a bundle with a tampered entry payload")
	}
}

func TestVerifyBundleDetectsTamperedRoot(t *testing.T) {
	b := buildGoldenBundle(t, sha512.New)
	// Corrupt the checkpoint root.
	bad := []byte(b.Checkpoints[0].MerkleRootHex)
	if bad[0] == 'a' {
		bad[0] = 'b'
	} else {
		bad[0] = 'a'
	}
	b.Checkpoints[0].MerkleRootHex = string(bad)
	if err := verifyBundle(b); err == nil {
		t.Fatal("CLI accepted a bundle with a tampered checkpoint root")
	}
}

func TestVerifyBundleDetectsBrokenChain(t *testing.T) {
	b := buildGoldenBundle(t, sha512.New)
	// Break the prev-hash linkage.
	b.Entries[2].PrevHashHex = hex.EncodeToString(make([]byte, sha512.Size))
	if err := verifyBundle(b); err == nil {
		t.Fatal("CLI accepted a bundle with a broken hash chain")
	}
}
