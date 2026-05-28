// Package attest implements client-side verification of PostQ attestation
// documents. Mirrors postq-site/apps/api/src/lib/vault/attestation-verifier.ts.
//
// Today only the `mock` vendor (Phase 1) is implemented — that's the
// JWS-shaped doc produced by postq-enclave. Real vendor backends (Nitro,
// Azure CVM, GCP Confidential Space) are reserved and will be added with
// the corresponding cloud provider integrations.
//
// Stdlib-only — Go ships ed25519 and SHA-256 natively, no external deps.
package attest

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Vendor identifies which TEE backend produced the document.
type Vendor string

const (
	VendorMock              Vendor = "mock"
	VendorAWSNitro          Vendor = "aws-nitro-enclave"
	VendorAzureConfidential Vendor = "azure-confidential-vm"
	VendorGCPConfidential   Vendor = "gcp-confidential-space"
)

// Policy is the verification policy (one vendor per policy). Mirror of the
// API's `signing_attestation_policies` row, narrowed to the fields the
// verifier needs.
type Policy struct {
	Vendor           Vendor          `json:"vendor"`
	MatchRules       json.RawMessage `json:"matchRules"`
	MaxDocAgeSeconds int             `json:"maxDocAgeSeconds"`
}

// Input is what the caller hands to Verify().
type Input struct {
	// DocB64 is the raw vendor-specific attestation document (base64).
	// For the `mock` vendor this decodes to a 3-part JWS string.
	DocB64 string
	Vendor Vendor
	Policy Policy
	// Optional sha256-hex bindings the caller wants enforced against the
	// doc's `claims.sigSha256` / `claims.payloadSha256`. Leave empty to skip.
	ExpectedSigSha256     string
	ExpectedPayloadSha256 string
	// EnforceFreshness, when true, rejects docs older than
	// Policy.MaxDocAgeSeconds. Default true; set false when re-verifying
	// historic signatures from the audit ledger.
	EnforceFreshness bool
}

// Result is what Verify() returns.
type Result struct {
	OK        bool           `json:"ok"`
	Reason    string         `json:"reason,omitempty"`
	Vendor    Vendor         `json:"vendor"`
	ImageHash string         `json:"imageHash,omitempty"`
	Counter   int            `json:"counter,omitempty"`
	Claims    map[string]any `json:"claims,omitempty"`
}

// Verify checks the attestation doc against the policy.
func Verify(in Input) (Result, error) {
	if in.Policy.Vendor != in.Vendor {
		return Result{
			OK:     false,
			Vendor: in.Vendor,
			Reason: fmt.Sprintf("policy vendor %s != doc vendor %s", in.Policy.Vendor, in.Vendor),
		}, nil
	}
	switch in.Vendor {
	case VendorMock:
		return verifyMock(in)
	case VendorAWSNitro, VendorAzureConfidential, VendorGCPConfidential:
		return Result{
			OK:     false,
			Vendor: in.Vendor,
			Reason: fmt.Sprintf("vendor %s not implemented in postq-cli yet", in.Vendor),
		}, nil
	default:
		return Result{}, fmt.Errorf("unknown vendor: %s", in.Vendor)
	}
}

// ── mock vendor ──────────────────────────────────────────────────────────────

type mockMatchRules struct {
	AllowedImageHashes []string `json:"allowedImageHashes"`
	RootPublicKeyB64   string   `json:"rootPublicKeyB64"`
}

type mockPayload struct {
	Vendor    string         `json:"vendor"`
	ImageHash string         `json:"imageHash"`
	Claims    map[string]any `json:"claims"`
	Nonce     string         `json:"nonce"`
	IssuedAt  string         `json:"issuedAt"`
	RootKeyID string         `json:"rootKeyId"`
}

type mockHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
}

func verifyMock(in Input) (Result, error) {
	res := Result{Vendor: VendorMock}

	var rules mockMatchRules
	if len(in.Policy.MatchRules) > 0 {
		if err := json.Unmarshal(in.Policy.MatchRules, &rules); err != nil {
			res.Reason = "policy.matchRules unparseable: " + err.Error()
			return res, nil
		}
	}
	if rules.RootPublicKeyB64 == "" {
		res.Reason = "policy.matchRules.rootPublicKeyB64 missing"
		return res, nil
	}
	rootPub, err := base64.StdEncoding.DecodeString(rules.RootPublicKeyB64)
	if err != nil {
		res.Reason = "rootPublicKeyB64 invalid base64: " + err.Error()
		return res, nil
	}
	if len(rootPub) != ed25519.PublicKeySize {
		res.Reason = fmt.Sprintf("rootPublicKeyB64 is not a %d-byte ed25519 key", ed25519.PublicKeySize)
		return res, nil
	}

	docBytes, err := base64.StdEncoding.DecodeString(in.DocB64)
	if err != nil {
		res.Reason = "docB64 invalid base64: " + err.Error()
		return res, nil
	}
	parts := strings.Split(string(docBytes), ".")
	if len(parts) != 3 {
		res.Reason = "mock doc not in 3-part JWS shape"
		return res, nil
	}
	headerB64u, payloadB64u, sigB64u := parts[0], parts[1], parts[2]

	headerBytes, err := base64.RawURLEncoding.DecodeString(headerB64u)
	if err != nil {
		res.Reason = "mock header b64u decode: " + err.Error()
		return res, nil
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(payloadB64u)
	if err != nil {
		res.Reason = "mock payload b64u decode: " + err.Error()
		return res, nil
	}
	sig, err := base64.RawURLEncoding.DecodeString(sigB64u)
	if err != nil {
		res.Reason = "mock sig b64u decode: " + err.Error()
		return res, nil
	}

	var header mockHeader
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		res.Reason = "mock header parse: " + err.Error()
		return res, nil
	}
	if header.Alg != "EdDSA" || header.Typ != "PostQ-Attestation-Mock" {
		res.Reason = fmt.Sprintf("mock doc header mismatch: alg=%s typ=%s", header.Alg, header.Typ)
		return res, nil
	}
	if len(sig) != ed25519.SignatureSize {
		res.Reason = fmt.Sprintf("mock sig length != %d bytes", ed25519.SignatureSize)
		return res, nil
	}

	signingInput := []byte(headerB64u + "." + payloadB64u)
	if !ed25519.Verify(rootPub, signingInput, sig) {
		res.Reason = "mock signature does not verify under pinned root"
		return res, nil
	}

	var pl mockPayload
	if err := json.Unmarshal(payloadBytes, &pl); err != nil {
		res.Reason = "mock payload parse: " + err.Error()
		return res, nil
	}
	if pl.Vendor != "mock" {
		res.Reason = fmt.Sprintf("payload.vendor=%s, expected mock", pl.Vendor)
		return res, nil
	}
	if pl.ImageHash == "" {
		res.Reason = "payload.imageHash missing"
		return res, nil
	}
	res.ImageHash = pl.ImageHash
	if len(rules.AllowedImageHashes) > 0 {
		ok := false
		for _, h := range rules.AllowedImageHashes {
			if h == pl.ImageHash {
				ok = true
				break
			}
		}
		if !ok {
			res.Reason = fmt.Sprintf("imageHash %s… not in allowlist", short(pl.ImageHash))
			return res, nil
		}
	}
	if pl.IssuedAt == "" {
		res.Reason = "payload.issuedAt missing"
		return res, nil
	}
	if in.EnforceFreshness {
		t, terr := time.Parse(time.RFC3339Nano, pl.IssuedAt)
		if terr != nil {
			// Try the plain RFC3339 as a fallback.
			t, terr = time.Parse(time.RFC3339, pl.IssuedAt)
		}
		if terr != nil {
			res.Reason = "payload.issuedAt unparseable: " + terr.Error()
			return res, nil
		}
		age := time.Since(t)
		if age < 0 {
			age = -age
		}
		if int(age.Seconds()) > in.Policy.MaxDocAgeSeconds {
			res.Reason = fmt.Sprintf("doc age %ds > max %ds",
				int(age.Seconds()), in.Policy.MaxDocAgeSeconds)
			return res, nil
		}
	}

	if pl.Claims != nil {
		if kind, _ := pl.Claims["kind"].(string); kind == "sign" {
			if in.ExpectedSigSha256 != "" {
				if got, _ := pl.Claims["sigSha256"].(string); got != in.ExpectedSigSha256 {
					res.Reason = "claims.sigSha256 mismatch"
					return res, nil
				}
			}
			if in.ExpectedPayloadSha256 != "" {
				if got, _ := pl.Claims["payloadSha256"].(string); got != in.ExpectedPayloadSha256 {
					res.Reason = "claims.payloadSha256 mismatch"
					return res, nil
				}
			}
			if c, ok := pl.Claims["counter"].(float64); ok {
				res.Counter = int(c)
			}
		}
	}

	res.OK = true
	res.Claims = pl.Claims
	return res, nil
}

// ── helpers ──────────────────────────────────────────────────────────────────

func short(s string) string {
	if len(s) <= 12 {
		return s
	}
	return s[:12]
}

// HexSha256 returns the lowercase hex sha256 of b. Exported for use by the
// commands package when binding sig/payload to attestation claims.
func HexSha256(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
