// PostQ Ledger client commands.
//
//	postq ledger verify <bundle.json>     verify a downloaded ledger bundle
//	                                      offline. Exit 0 = intact, 1 = error,
//	                                      2 = tampering detected.
//
// The bundle is whatever GET /v1/ledger/bundle returned. We re-do the chain
// hash + Merkle root computation; we DO NOT verify the hybrid ML-DSA
// signature here (that's a much larger lift — pure Go ML-DSA is not in the
// Go stdlib yet). The chain + Merkle check is enough to prove that no
// historical entry was modified between when the bundle was issued and now.
package commands

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"os"
	"sort"
	"strings"
)

func runLedger(args []string) error {
	if len(args) == 0 {
		printLedgerHelp()
		return nil
	}
	switch args[0] {
	case "verify":
		if len(args) < 2 {
			return fmt.Errorf("usage: postq ledger verify <bundle.json>")
		}
		return ledgerVerify(args[1])
	case "entries":
		return runLedgerEntries(args[1:])
	case "append":
		return runLedgerAppend(args[1:])
	case "checkpoints":
		return runLedgerCheckpoints(args[1:])
	case "seal":
		return runLedgerSeal(args[1:])
	case "proof":
		return runLedgerProof(args[1:])
	case "bundle":
		return runLedgerBundle(args[1:])
	case "help", "--help", "-h":
		printLedgerHelp()
		return nil
	default:
		printLedgerHelp()
		return fmt.Errorf("unknown ledger subcommand: %s", args[0])
	}
}

func printLedgerHelp() {
	fmt.Println(`postq ledger — PostQ tamper-evident audit log

Subcommands:
  entries [--since N] [--limit N] [--type T] [--json]
                         List recent ledger entries.
  append --name NAME [--message M] [--subject ID] [--data @file|JSON]
                         Append a custom entry to the org ledger.
  checkpoints [--limit N] [--json]
                         List signed Merkle-root checkpoints.
  seal                   Force a new checkpoint over current entries.
  proof <entryId>        Get a Merkle inclusion proof (auto-seals if needed).
  bundle [--out file]    Download a verifiable bundle. Defaults to stdout.
  verify <bundle.json>   Re-derive the chain + Merkle root from a bundle and
                         confirm every entry hashes to its stored entry_hash
                         and that each checkpoint's root matches.

Quick offline verify after download:
  postq ledger bundle --out bundle.json
  postq ledger verify bundle.json

Exit codes:
  0   bundle intact
  1   read / parse error
  2   tampering detected (hash chain or Merkle root mismatch)`)
}

// ── Bundle types ────────────────────────────────────────────────────────────

type bundleEntry struct {
	ID           string                 `json:"id"`
	Seq          int                    `json:"seq"`
	PrevHashHex  string                 `json:"prevHashHex"`
	EntryHashHex string                 `json:"entryHashHex"`
	Payload      map[string]interface{} `json:"payload"`
	CreatedAt    string                 `json:"createdAt"`
}

type bundleCheckpoint struct {
	TreeSize        int    `json:"treeSize"`
	MerkleRootHex   string `json:"merkleRootHex"`
	SignatureBase64 string `json:"signatureBase64"`
	SigningKeyID    string `json:"signingKeyId"`
	CreatedAt       string `json:"createdAt"`
}

type bundleSigningKey struct {
	ID                    string `json:"id"`
	Algorithm             string `json:"algorithm"`
	PublicClassicalBase64 string `json:"publicClassicalBase64"`
	PublicPqBase64        string `json:"publicPqBase64"`
}

type ledgerBundle struct {
	Version     int                `json:"version"`
	Org         string             `json:"org"`
	GeneratedAt string             `json:"generatedAt"`
	Entries     []bundleEntry      `json:"entries"`
	Checkpoints []bundleCheckpoint `json:"checkpoints"`
	SigningKeys []bundleSigningKey `json:"signingKeys"`
}

// ── Verifier ────────────────────────────────────────────────────────────────

func ledgerVerify(path string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read bundle: %w", err)
	}
	// Accept either { "data": {...} } from a raw API response or the bare bundle.
	var envelope struct {
		Success bool          `json:"success"`
		Data    *ledgerBundle `json:"data"`
	}
	var bundle ledgerBundle
	if err := json.Unmarshal(raw, &envelope); err == nil && envelope.Data != nil {
		bundle = *envelope.Data
	} else if err := json.Unmarshal(raw, &bundle); err != nil {
		return fmt.Errorf("parse bundle: %w", err)
	}

	fmt.Printf("PostQ Ledger bundle — org=%s generated=%s\n", bundle.Org, bundle.GeneratedAt)
	fmt.Printf("  entries:     %d\n", len(bundle.Entries))
	fmt.Printf("  checkpoints: %d\n", len(bundle.Checkpoints))
	fmt.Printf("  signers:     %d\n\n", len(bundle.SigningKeys))

	if err := verifyBundle(bundle); err != nil {
		fmt.Printf("FAIL: %v\n", err)
		os.Exit(2)
	}
	fmt.Printf("✓ hash chain intact (%d entries)\n", len(bundle.Entries))
	fmt.Printf("✓ all %d checkpoints' merkle roots match the entry chain\n", len(bundle.Checkpoints))

	// Note: hybrid signature (ML-DSA + Ed25519/ECDSA) verification requires
	// pulling in liboqs/CIRCL — kept out of this stdlib-only CLI on purpose.
	// Ship the bundle to /v1/verify or use the Python/JS SDK to confirm.
	fmt.Println("\nbundle intact. (Hybrid signature verification: pipe a checkpoint into")
	fmt.Println("`postq` API /v1/verify or the JS/Python SDK to confirm the ML-DSA half.)")
	return nil
}

// verifyBundle is the pure, testable core of `postq ledger verify`: it
// re-derives the hash chain and every checkpoint's Merkle root and returns a
// non-nil error describing the first inconsistency (tampering). It performs no
// I/O and never exits the process.
//
// The ledger hashes entries with SHA-256 (legacy) or SHA-512 (current,
// post-quantum longevity); the function detects which per entry/checkpoint from
// the stored hex length so both old and new bundles verify.
func verifyBundle(bundle ledgerBundle) error {
	// 1) Hash chain.
	var prev []byte // genesis prev-hash; sized from entry 0's stored prev-hash
	if len(bundle.Entries) > 0 {
		prev = make([]byte, len(bundle.Entries[0].PrevHashHex)/2)
	}
	entryHashes := make([][]byte, len(bundle.Entries))
	for i, e := range bundle.Entries {
		if e.Seq != i {
			return fmt.Errorf("entry #%d has seq=%d (expected %d)", i, e.Seq, i)
		}
		expectedPrev := hex.EncodeToString(prev)
		if e.PrevHashHex != expectedPrev {
			return fmt.Errorf("entry #%d prev_hash mismatch\n        stored: %s\n        chain:  %s", i, e.PrevHashHex, expectedPrev)
		}
		newHash, err := hashForHexLen(len(e.EntryHashHex))
		if err != nil {
			return fmt.Errorf("entry #%d has an unrecognized hash length (%d hex chars)", i, len(e.EntryHashHex))
		}
		canonical := canonicalize(e.Payload)
		h := newHash()
		h.Write(prev)
		h.Write([]byte(canonical))
		recomputed := h.Sum(nil)
		if e.EntryHashHex != hex.EncodeToString(recomputed) {
			return fmt.Errorf("entry #%d hash mismatch\n        stored:    %s\n        recomputed: %s", i, e.EntryHashHex, hex.EncodeToString(recomputed))
		}
		entryHashes[i] = recomputed
		prev = recomputed
	}

	// 2) Each checkpoint's Merkle root over [0..treeSize-1].
	for _, c := range bundle.Checkpoints {
		if c.TreeSize > len(entryHashes) {
			return fmt.Errorf("checkpoint at tree_size=%d exceeds entry count %d", c.TreeSize, len(entryHashes))
		}
		newHash, err := hashForHexLen(len(c.MerkleRootHex))
		if err != nil {
			return fmt.Errorf("checkpoint at tree_size=%d has an unrecognized root hash length", c.TreeSize)
		}
		root := merkleRoot(entryHashes[:c.TreeSize], newHash)
		if hex.EncodeToString(root) != c.MerkleRootHex {
			return fmt.Errorf("checkpoint at tree_size=%d merkle root mismatch\n        stored:    %s\n        recomputed: %s", c.TreeSize, c.MerkleRootHex, hex.EncodeToString(root))
		}
		if _, err := base64.StdEncoding.DecodeString(c.SignatureBase64); err != nil {
			return fmt.Errorf("checkpoint at tree_size=%d signature is not valid base64: %v", c.TreeSize, err)
		}
	}
	return nil
}

// ── Canonical JSON (matches lib/ledger/index.ts canonicalize) ───────────────

func canonicalize(v interface{}) string {
	if v == nil {
		return "null"
	}
	switch x := v.(type) {
	case bool:
		if x {
			return "true"
		}
		return "false"
	case string:
		b, _ := json.Marshal(x)
		return string(b)
	case float64:
		// JSON numbers come out as float64. Match JS canonical form.
		b, _ := json.Marshal(x)
		return string(b)
	case []interface{}:
		parts := make([]string, len(x))
		for i, e := range x {
			parts[i] = canonicalize(e)
		}
		return "[" + strings.Join(parts, ",") + "]"
	case map[string]interface{}:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		parts := make([]string, len(keys))
		for i, k := range keys {
			b, _ := json.Marshal(k)
			parts[i] = string(b) + ":" + canonicalize(x[k])
		}
		return "{" + strings.Join(parts, ",") + "}"
	default:
		// Fallback to stdlib json (won't be deterministic but shouldn't happen
		// for our well-typed payloads).
		b, _ := json.Marshal(v)
		return string(b)
	}
}

// ── RFC 6962 Merkle (matches lib/ledger merkleRoot) ─────────────────────────

// hashForHexLen returns the hash constructor matching a stored hex digest:
// 64 hex chars → SHA-256 (legacy), 128 hex chars → SHA-512 (current).
func hashForHexLen(hexLen int) (func() hash.Hash, error) {
	switch hexLen {
	case sha256.Size * 2:
		return sha256.New, nil
	case sha512.Size * 2:
		return sha512.New, nil
	default:
		return nil, fmt.Errorf("unrecognized digest length: %d hex chars", hexLen)
	}
}

func merkleRoot(entries [][]byte, newHash func() hash.Hash) []byte {
	if len(entries) == 0 {
		return newHash().Sum(nil)
	}
	leaves := make([][]byte, len(entries))
	for i, e := range entries {
		leaves[i] = leafHash(e, newHash)
	}
	return treeHash(leaves, newHash)
}

func leafHash(entry []byte, newHash func() hash.Hash) []byte {
	h := newHash()
	h.Write([]byte{0x00})
	h.Write(entry)
	return h.Sum(nil)
}

func nodeHash(left, right []byte, newHash func() hash.Hash) []byte {
	h := newHash()
	h.Write([]byte{0x01})
	h.Write(left)
	h.Write(right)
	return h.Sum(nil)
}

func treeHash(leaves [][]byte, newHash func() hash.Hash) []byte {
	if len(leaves) == 1 {
		return leaves[0]
	}
	n := len(leaves)
	k := 1
	for k*2 < n {
		k *= 2
	}
	return nodeHash(treeHash(leaves[:k], newHash), treeHash(leaves[k:], newHash), newHash)
}
