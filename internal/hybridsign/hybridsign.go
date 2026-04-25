// Package hybridsign is a thin stdlib-only HTTP wrapper around the PostQ
// hybrid signing endpoints (/v1/hybrid-keys, /v1/sign, /v1/verify).
//
// The CLI never sees private key material; everything is sealed inside
// PostQ. We send payloads base64-encoded and receive composite signatures
// back as opaque base64 strings to be passed to /v1/verify or distributed
// alongside the artifact.
package hybridsign

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// Client talks to the PostQ hybrid signing API.
type Client struct {
	endpoint  string
	apiKey    string
	userAgent string
	http      *http.Client
}

// New constructs a Client. timeout is per-request.
func New(endpoint, apiKey, userAgent string) *Client {
	if userAgent == "" {
		userAgent = "postq-cli/dev"
	}
	return &Client{
		endpoint:  endpoint,
		apiKey:    apiKey,
		userAgent: userAgent,
		http:      &http.Client{Timeout: 60 * time.Second},
	}
}

// ── Types ────────────────────────────────────────────────────────────────────

// Key is a managed signing key (without secret material).
type Key struct {
	ID         string                 `json:"id"`
	Name       string                 `json:"name"`
	Algorithm  string                 `json:"algorithm"`
	CreatedAt  string                 `json:"createdAt"`
	RevokedAt  *string                `json:"revokedAt,omitempty"`
	LastUsedAt *string                `json:"lastUsedAt,omitempty"`
	Metadata   map[string]any         `json:"metadata,omitempty"`
	PublicKey  string                 `json:"publicKey,omitempty"` // present on create / get
}

// SignResult is what /v1/sign returns.
type SignResult struct {
	KeyID         string `json:"keyId"`
	Algorithm     string `json:"algorithm"`
	Signature     string `json:"signature"` // base64 composite envelope
	PublicKey     string `json:"publicKey"`
	PayloadSha256 string `json:"payloadSha256"`
	PayloadSize   int    `json:"payloadSize"`
}

// VerifyResult is what /v1/verify returns.
type VerifyResult struct {
	OK          bool   `json:"ok"`
	Algorithm   string `json:"algorithm"`
	ClassicalOK bool   `json:"classicalOk"`
	PqOK        bool   `json:"pqOk"`
}

// ── Calls ────────────────────────────────────────────────────────────────────

// CreateKey calls POST /v1/hybrid-keys.
func (c *Client) CreateKey(ctx context.Context, name, algorithm string) (*Key, error) {
	body := map[string]any{"name": name}
	if algorithm != "" {
		body["algorithm"] = algorithm
	}
	var env struct {
		Success bool   `json:"success"`
		Data    Key    `json:"data"`
		Error   string `json:"error,omitempty"`
	}
	if err := c.do(ctx, http.MethodPost, "/v1/hybrid-keys", nil, body, &env); err != nil {
		return nil, err
	}
	return &env.Data, nil
}

// ListKeys calls GET /v1/hybrid-keys.
func (c *Client) ListKeys(ctx context.Context, limit int, includeRevoked bool) ([]Key, error) {
	if limit <= 0 {
		limit = 20
	}
	q := url.Values{}
	q.Set("limit", fmt.Sprintf("%d", limit))
	if includeRevoked {
		q.Set("includeRevoked", "true")
	}
	var env struct {
		Success bool   `json:"success"`
		Data    []Key  `json:"data"`
		Error   string `json:"error,omitempty"`
	}
	if err := c.do(ctx, http.MethodGet, "/v1/hybrid-keys", q, nil, &env); err != nil {
		return nil, err
	}
	return env.Data, nil
}

// GetKey calls GET /v1/hybrid-keys/:id.
func (c *Client) GetKey(ctx context.Context, id string) (*Key, error) {
	var env struct {
		Success bool   `json:"success"`
		Data    Key    `json:"data"`
		Error   string `json:"error,omitempty"`
	}
	if err := c.do(ctx, http.MethodGet, "/v1/hybrid-keys/"+url.PathEscape(id), nil, nil, &env); err != nil {
		return nil, err
	}
	return &env.Data, nil
}

// RevokeKey calls DELETE /v1/hybrid-keys/:id.
func (c *Client) RevokeKey(ctx context.Context, id string) error {
	var env struct {
		Success bool   `json:"success"`
		Error   string `json:"error,omitempty"`
	}
	return c.do(ctx, http.MethodDelete, "/v1/hybrid-keys/"+url.PathEscape(id), nil, nil, &env)
}

// Sign calls POST /v1/sign with the given raw payload bytes (base64-encoded for transit).
func (c *Client) Sign(ctx context.Context, keyID string, payload []byte) (*SignResult, error) {
	body := map[string]any{
		"keyId":   keyID,
		"payload": base64.StdEncoding.EncodeToString(payload),
	}
	var env struct {
		Success bool       `json:"success"`
		Data    SignResult `json:"data"`
		Error   string     `json:"error,omitempty"`
	}
	if err := c.do(ctx, http.MethodPost, "/v1/sign", nil, body, &env); err != nil {
		return nil, err
	}
	return &env.Data, nil
}

// Verify calls POST /v1/verify. Either keyID or publicKey must be set.
func (c *Client) Verify(ctx context.Context, keyID, publicKey string, payload []byte, signature string) (*VerifyResult, error) {
	body := map[string]any{
		"payload":   base64.StdEncoding.EncodeToString(payload),
		"signature": signature,
	}
	if keyID != "" {
		body["keyId"] = keyID
	}
	if publicKey != "" {
		body["publicKey"] = publicKey
	}
	var env struct {
		Success bool         `json:"success"`
		Data    VerifyResult `json:"data"`
		Error   string       `json:"error,omitempty"`
	}
	if err := c.do(ctx, http.MethodPost, "/v1/verify", nil, body, &env); err != nil {
		return nil, err
	}
	return &env.Data, nil
}

// ── plumbing ─────────────────────────────────────────────────────────────────

func (c *Client) do(ctx context.Context, method, path string, query url.Values, body any, out any) error {
	u := c.endpoint + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}

	var reader io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("marshal: %w", err)
		}
		reader = bytes.NewReader(buf)
	}

	req, err := http.NewRequestWithContext(ctx, method, u, reader)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", c.userAgent)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("%s %s: %w", method, path, err)
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(resp.Body)
	if len(raw) == 0 && resp.StatusCode < 400 {
		return nil
	}

	// First try to parse into the success envelope.
	if out != nil {
		if err := json.Unmarshal(raw, out); err == nil && resp.StatusCode < 400 {
			return nil
		}
	}

	// Failure path: try to surface the API error message.
	var errEnv struct {
		Success bool   `json:"success"`
		Error   string `json:"error"`
	}
	_ = json.Unmarshal(raw, &errEnv)
	msg := errEnv.Error
	if msg == "" {
		msg = fmt.Sprintf("status %d: %s", resp.StatusCode, string(raw))
	}
	return fmt.Errorf("api error: %s", msg)
}
