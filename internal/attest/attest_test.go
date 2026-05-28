package attest

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// buildMockDoc forges a mock attestation doc with a freshly-generated root
// key and returns (docB64, rootPubB64, imageHash).
func buildMockDoc(t *testing.T, mutate func(payload map[string]any)) (string, string, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	imageHash := strings.Repeat("a", 64)
	payload := map[string]any{
		"vendor":    "mock",
		"imageHash": imageHash,
		"nonce":     base64.StdEncoding.EncodeToString([]byte("01234567")),
		"issuedAt":  time.Now().UTC().Format(time.RFC3339Nano),
		"rootKeyId": "test-root",
		"claims": map[string]any{
			"kind":          "sign",
			"counter":       1,
			"sigSha256":     strings.Repeat("s", 64),
			"payloadSha256": strings.Repeat("p", 64),
		},
	}
	if mutate != nil {
		mutate(payload)
	}
	header := map[string]any{"alg": "EdDSA", "typ": "PostQ-Attestation-Mock"}

	hb, _ := json.Marshal(header)
	pb, _ := json.Marshal(payload)
	headerB64u := base64.RawURLEncoding.EncodeToString(hb)
	payloadB64u := base64.RawURLEncoding.EncodeToString(pb)
	sig := ed25519.Sign(priv, []byte(headerB64u+"."+payloadB64u))
	jws := headerB64u + "." + payloadB64u + "." + base64.RawURLEncoding.EncodeToString(sig)
	docB64 := base64.StdEncoding.EncodeToString([]byte(jws))
	return docB64, base64.StdEncoding.EncodeToString(pub), imageHash
}

func policy(t *testing.T, rootPubB64, imageHash string) Policy {
	t.Helper()
	rules := map[string]any{
		"rootPublicKeyB64":   rootPubB64,
		"allowedImageHashes": []string{imageHash},
	}
	rb, _ := json.Marshal(rules)
	return Policy{
		Vendor:           VendorMock,
		MatchRules:       rb,
		MaxDocAgeSeconds: 300,
	}
}

func TestVerifyMockHappyPath(t *testing.T) {
	doc, root, img := buildMockDoc(t, nil)
	res, err := Verify(Input{
		DocB64:           doc,
		Vendor:           VendorMock,
		Policy:           policy(t, root, img),
		EnforceFreshness: true,
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !res.OK {
		t.Fatalf("expected ok, got reason=%q", res.Reason)
	}
	if res.ImageHash != img {
		t.Errorf("imageHash mismatch: %s vs %s", res.ImageHash, img)
	}
	if res.Counter != 1 {
		t.Errorf("counter = %d, want 1", res.Counter)
	}
}

func TestVerifyMockWrongRoot(t *testing.T) {
	doc, _, img := buildMockDoc(t, nil)
	wrongPub, _, _ := ed25519.GenerateKey(rand.Reader)
	res, _ := Verify(Input{
		DocB64:           doc,
		Vendor:           VendorMock,
		Policy:           policy(t, base64.StdEncoding.EncodeToString(wrongPub), img),
		EnforceFreshness: true,
	})
	if res.OK {
		t.Fatalf("expected fail")
	}
	if !strings.Contains(res.Reason, "does not verify") {
		t.Errorf("unexpected reason: %s", res.Reason)
	}
}

func TestVerifyMockImageNotAllowed(t *testing.T) {
	doc, root, _ := buildMockDoc(t, nil)
	res, _ := Verify(Input{
		DocB64:           doc,
		Vendor:           VendorMock,
		Policy:           policy(t, root, strings.Repeat("z", 64)),
		EnforceFreshness: true,
	})
	if res.OK {
		t.Fatalf("expected fail")
	}
	if !strings.Contains(res.Reason, "not in allowlist") {
		t.Errorf("unexpected reason: %s", res.Reason)
	}
}

func TestVerifyMockSigBindingMismatch(t *testing.T) {
	doc, root, img := buildMockDoc(t, nil)
	res, _ := Verify(Input{
		DocB64:                doc,
		Vendor:                VendorMock,
		Policy:                policy(t, root, img),
		ExpectedSigSha256:     strings.Repeat("z", 64),
		EnforceFreshness:      true,
	})
	if res.OK {
		t.Fatalf("expected fail")
	}
	if !strings.Contains(res.Reason, "sigSha256 mismatch") {
		t.Errorf("unexpected reason: %s", res.Reason)
	}
}

func TestVerifyMockStaleDoc(t *testing.T) {
	doc, root, img := buildMockDoc(t, func(p map[string]any) {
		p["issuedAt"] = time.Now().Add(-1 * time.Hour).UTC().Format(time.RFC3339Nano)
	})
	res, _ := Verify(Input{
		DocB64:           doc,
		Vendor:           VendorMock,
		Policy:           policy(t, root, img),
		EnforceFreshness: true,
	})
	if res.OK {
		t.Fatalf("expected fail")
	}
	if !strings.Contains(res.Reason, "doc age") {
		t.Errorf("unexpected reason: %s", res.Reason)
	}
}

func TestVerifyMockStaleAllowedWhenNotEnforced(t *testing.T) {
	doc, root, img := buildMockDoc(t, func(p map[string]any) {
		p["issuedAt"] = time.Now().Add(-1 * time.Hour).UTC().Format(time.RFC3339Nano)
	})
	res, _ := Verify(Input{
		DocB64: doc,
		Vendor: VendorMock,
		Policy: policy(t, root, img),
	})
	if !res.OK {
		t.Fatalf("expected ok, got %q", res.Reason)
	}
}

func TestVerifyVendorMismatch(t *testing.T) {
	doc, root, img := buildMockDoc(t, nil)
	p := policy(t, root, img)
	p.Vendor = VendorAWSNitro
	res, _ := Verify(Input{DocB64: doc, Vendor: VendorMock, Policy: p, EnforceFreshness: true})
	if res.OK {
		t.Fatalf("expected fail")
	}
	if !strings.Contains(res.Reason, "policy vendor") {
		t.Errorf("unexpected reason: %s", res.Reason)
	}
}

func TestVerifyUnimplementedVendors(t *testing.T) {
	for _, v := range []Vendor{VendorAWSNitro, VendorAzureConfidential, VendorGCPConfidential} {
		res, _ := Verify(Input{
			DocB64: base64.StdEncoding.EncodeToString([]byte("x")),
			Vendor: v,
			Policy: Policy{Vendor: v, MaxDocAgeSeconds: 300},
		})
		if res.OK {
			t.Errorf("vendor %s: expected fail", v)
		}
		if !strings.Contains(res.Reason, "not implemented") {
			t.Errorf("vendor %s: unexpected reason: %s", v, res.Reason)
		}
	}
}
