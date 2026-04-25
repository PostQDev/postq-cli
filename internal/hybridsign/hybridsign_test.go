package hybridsign

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func newTestServer(t *testing.T, handler http.HandlerFunc) (*httptest.Server, *Client) {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return srv, New(srv.URL, "pq_live_test", "postq-cli/test")
}

func TestSignSendsBase64Payload(t *testing.T) {
	_, cl := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/sign" {
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer pq_live_test" {
			t.Fatalf("auth header: %q", got)
		}
		body, _ := io.ReadAll(r.Body)
		var parsed struct {
			KeyID   string `json:"keyId"`
			Payload string `json:"payload"`
		}
		if err := json.Unmarshal(body, &parsed); err != nil {
			t.Fatalf("bad body: %v", err)
		}
		if parsed.KeyID != "key-123" {
			t.Fatalf("keyId: %q", parsed.KeyID)
		}
		raw, err := base64.StdEncoding.DecodeString(parsed.Payload)
		if err != nil {
			t.Fatalf("payload not base64: %v", err)
		}
		if string(raw) != "ship it" {
			t.Fatalf("payload: %q", raw)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true,"data":{
			"keyId":"key-123","algorithm":"mldsa65+ed25519",
			"signature":"AAAA","publicKey":"{}",
			"payloadSha256":"abc","payloadSize":7
		}}`))
	})

	res, err := cl.Sign(context.Background(), "key-123", []byte("ship it"))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if res.Signature != "AAAA" || res.Algorithm != "mldsa65+ed25519" {
		t.Fatalf("unexpected result: %+v", res)
	}
}

func TestVerifyHappyPath(t *testing.T) {
	_, cl := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var parsed map[string]any
		_ = json.Unmarshal(body, &parsed)
		if _, ok := parsed["keyId"]; !ok {
			t.Fatalf("expected keyId in body, got %v", parsed)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true,"data":{
			"ok":true,"algorithm":"mldsa65+ed25519",
			"classicalOk":true,"pqOk":true
		}}`))
	})

	res, err := cl.Verify(context.Background(), "key-1", "", []byte("hi"), "sig")
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !res.OK || !res.ClassicalOK || !res.PqOK {
		t.Fatalf("expected all ok, got %+v", res)
	}
}

func TestSurfacedAPIError(t *testing.T) {
	_, cl := newTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"success":false,"error":"API key missing required scope: sign:write"}`))
	})
	_, err := cl.Sign(context.Background(), "key-1", []byte("x"))
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "sign:write") {
		t.Fatalf("error did not include API message: %v", err)
	}
}

func TestListKeysIncludeRevoked(t *testing.T) {
	_, cl := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("includeRevoked"); got != "true" {
			t.Fatalf("includeRevoked: %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true,"data":[
			{"id":"k1","name":"a","algorithm":"mldsa65+ed25519","createdAt":"2026-01-01T00:00:00Z"}
		],"pagination":{"limit":20,"nextCursor":null}}`))
	})

	keys, err := cl.ListKeys(context.Background(), 20, true)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(keys) != 1 || keys[0].ID != "k1" {
		t.Fatalf("unexpected keys: %+v", keys)
	}
}
