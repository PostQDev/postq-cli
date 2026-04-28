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
	ID         string         `json:"id"`
	Name       string         `json:"name"`
	Algorithm  string         `json:"algorithm"`
	CreatedAt  string         `json:"createdAt"`
	RevokedAt  *string        `json:"revokedAt,omitempty"`
	LastUsedAt *string        `json:"lastUsedAt,omitempty"`
	Metadata   map[string]any `json:"metadata,omitempty"`
	PublicKey  string         `json:"publicKey,omitempty"` // present on create / get
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

// ─────────────────────────── Rotate / Audit ───────────────────────────

// AuditEntry is a row from /v1/hybrid-keys/:id/audit.
type AuditEntry struct {
	ID        string         `json:"id"`
	Seq       int64          `json:"seq"`
	EventType string         `json:"eventType"`
	CreatedAt string         `json:"createdAt"`
	Actor     *string        `json:"actor,omitempty"`
	SubjectID *string        `json:"subjectId,omitempty"`
	Data      map[string]any `json:"data,omitempty"`
}

// RotateKey calls POST /v1/hybrid-keys/:id/rotate.
func (c *Client) RotateKey(ctx context.Context, id, name string) (*Key, error) {
	body := map[string]any{}
	if name != "" {
		body["name"] = name
	}
	var env struct {
		Success bool   `json:"success"`
		Data    Key    `json:"data"`
		Error   string `json:"error,omitempty"`
	}
	if err := c.do(ctx, http.MethodPost, "/v1/hybrid-keys/"+url.PathEscape(id)+"/rotate", nil, body, &env); err != nil {
		return nil, err
	}
	return &env.Data, nil
}

// AuditKey calls GET /v1/hybrid-keys/:id/audit.
func (c *Client) AuditKey(ctx context.Context, id string, limit int) ([]AuditEntry, error) {
	q := url.Values{}
	if limit > 0 {
		q.Set("limit", fmt.Sprintf("%d", limit))
	}
	var env struct {
		Success bool         `json:"success"`
		Data    []AuditEntry `json:"data"`
		Error   string       `json:"error,omitempty"`
	}
	if err := c.do(ctx, http.MethodGet, "/v1/hybrid-keys/"+url.PathEscape(id)+"/audit", q, nil, &env); err != nil {
		return nil, err
	}
	return env.Data, nil
}

// ─────────────────────────── Policies ───────────────────────────

// PolicyRule is the typed rule body.
type PolicyRule struct {
	Operations           []string `json:"operations"`
	Action               string   `json:"action"`
	Algorithms           []string `json:"algorithms,omitempty"`
	KeyIDs               []string `json:"keyIds,omitempty"`
	MaxPayloadBytes      *int64   `json:"maxPayloadBytes,omitempty"`
	RequireMetadataKeys  []string `json:"requireMetadataKeys,omitempty"`
	Message              string   `json:"message,omitempty"`
}

// Policy is an org-level policy rule.
type Policy struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	Description *string    `json:"description,omitempty"`
	Enabled     bool       `json:"enabled"`
	Rule        PolicyRule `json:"rule"`
	CreatedAt   string     `json:"createdAt"`
	UpdatedAt   string     `json:"updatedAt"`
}

// ListPolicies calls GET /v1/policies.
func (c *Client) ListPolicies(ctx context.Context) ([]Policy, error) {
	var env struct {
		Success bool     `json:"success"`
		Data    []Policy `json:"data"`
		Error   string   `json:"error,omitempty"`
	}
	if err := c.do(ctx, http.MethodGet, "/v1/policies", nil, nil, &env); err != nil {
		return nil, err
	}
	return env.Data, nil
}

// GetPolicy calls GET /v1/policies/:id.
func (c *Client) GetPolicy(ctx context.Context, id string) (*Policy, error) {
	var env struct {
		Success bool   `json:"success"`
		Data    Policy `json:"data"`
		Error   string `json:"error,omitempty"`
	}
	if err := c.do(ctx, http.MethodGet, "/v1/policies/"+url.PathEscape(id), nil, nil, &env); err != nil {
		return nil, err
	}
	return &env.Data, nil
}

// CreatePolicy calls POST /v1/policies.
func (c *Client) CreatePolicy(ctx context.Context, body map[string]any) (*Policy, error) {
	var env struct {
		Success bool   `json:"success"`
		Data    Policy `json:"data"`
		Error   string `json:"error,omitempty"`
	}
	if err := c.do(ctx, http.MethodPost, "/v1/policies", nil, body, &env); err != nil {
		return nil, err
	}
	return &env.Data, nil
}

// UpdatePolicy calls PATCH /v1/policies/:id.
func (c *Client) UpdatePolicy(ctx context.Context, id string, body map[string]any) (*Policy, error) {
	var env struct {
		Success bool   `json:"success"`
		Data    Policy `json:"data"`
		Error   string `json:"error,omitempty"`
	}
	if err := c.do(ctx, http.MethodPatch, "/v1/policies/"+url.PathEscape(id), nil, body, &env); err != nil {
		return nil, err
	}
	return &env.Data, nil
}

// DeletePolicy calls DELETE /v1/policies/:id.
func (c *Client) DeletePolicy(ctx context.Context, id string) error {
	var env struct {
		Success bool   `json:"success"`
		Error   string `json:"error,omitempty"`
	}
	return c.do(ctx, http.MethodDelete, "/v1/policies/"+url.PathEscape(id), nil, nil, &env)
}

// ─────────────────────────── Ledger ───────────────────────────

// LedgerEntry is one row in the org's tamper-evident hash chain.
type LedgerEntry struct {
	ID        string         `json:"id"`
	Seq       int64          `json:"seq"`
	EventType string         `json:"eventType"`
	CreatedAt string         `json:"createdAt"`
	PrevHash  string         `json:"prevHash,omitempty"`
	LeafHash  string         `json:"leafHash,omitempty"`
	Actor     *string        `json:"actor,omitempty"`
	SubjectID *string        `json:"subjectId,omitempty"`
	Data      map[string]any `json:"data,omitempty"`
}

// LedgerCheckpoint is a signed Merkle root over a range of entries.
type LedgerCheckpoint struct {
	ID           string  `json:"id"`
	Seq          int64   `json:"seq"`
	MerkleRoot   string  `json:"merkleRoot"`
	EntriesCount int64   `json:"entriesCount"`
	SignedAt     string  `json:"signedAt"`
	SigningKeyID string  `json:"signingKeyId,omitempty"`
	Signature    string  `json:"signature,omitempty"`
	Algorithm    string  `json:"algorithm,omitempty"`
}

// InclusionProof is what /v1/ledger/proof/:entryId returns.
type InclusionProof struct {
	EntryID    string           `json:"entryId"`
	Seq        int64            `json:"seq"`
	LeafHash   string           `json:"leafHash"`
	MerklePath []string         `json:"merklePath"`
	Checkpoint LedgerCheckpoint `json:"checkpoint"`
}

// SealResult is what /v1/ledger/seal returns.
type SealResult struct {
	Checkpoint     *LedgerCheckpoint `json:"checkpoint,omitempty"`
	Sealed         bool              `json:"sealed"`
	EntriesCovered int64             `json:"entriesCovered"`
}

// ListLedgerEntries calls GET /v1/ledger/entries.
func (c *Client) ListLedgerEntries(ctx context.Context, since int64, limit int, eventType string) ([]LedgerEntry, error) {
	q := url.Values{}
	if since > 0 {
		q.Set("since", fmt.Sprintf("%d", since))
	}
	if limit > 0 {
		q.Set("limit", fmt.Sprintf("%d", limit))
	}
	if eventType != "" {
		q.Set("eventType", eventType)
	}
	var env struct {
		Success bool          `json:"success"`
		Data    []LedgerEntry `json:"data"`
		Error   string        `json:"error,omitempty"`
	}
	if err := c.do(ctx, http.MethodGet, "/v1/ledger/entries", q, nil, &env); err != nil {
		return nil, err
	}
	return env.Data, nil
}

// AppendLedgerEntry calls POST /v1/ledger/entries with a custom payload.
func (c *Client) AppendLedgerEntry(ctx context.Context, body map[string]any) (*LedgerEntry, error) {
	var env struct {
		Success bool        `json:"success"`
		Data    LedgerEntry `json:"data"`
		Error   string      `json:"error,omitempty"`
	}
	if err := c.do(ctx, http.MethodPost, "/v1/ledger/entries", nil, body, &env); err != nil {
		return nil, err
	}
	return &env.Data, nil
}

// ListCheckpoints calls GET /v1/ledger/checkpoints.
func (c *Client) ListCheckpoints(ctx context.Context, limit int) ([]LedgerCheckpoint, error) {
	q := url.Values{}
	if limit > 0 {
		q.Set("limit", fmt.Sprintf("%d", limit))
	}
	var env struct {
		Success bool               `json:"success"`
		Data    []LedgerCheckpoint `json:"data"`
		Error   string             `json:"error,omitempty"`
	}
	if err := c.do(ctx, http.MethodGet, "/v1/ledger/checkpoints", q, nil, &env); err != nil {
		return nil, err
	}
	return env.Data, nil
}

// LatestCheckpoint calls GET /v1/ledger/checkpoints/latest.
func (c *Client) LatestCheckpoint(ctx context.Context) (*LedgerCheckpoint, error) {
	var env struct {
		Success bool              `json:"success"`
		Data    *LedgerCheckpoint `json:"data"`
		Error   string            `json:"error,omitempty"`
	}
	if err := c.do(ctx, http.MethodGet, "/v1/ledger/checkpoints/latest", nil, nil, &env); err != nil {
		return nil, err
	}
	return env.Data, nil
}

// SealLedger calls POST /v1/ledger/seal.
func (c *Client) SealLedger(ctx context.Context) (*SealResult, error) {
	var env struct {
		Success bool       `json:"success"`
		Data    SealResult `json:"data"`
		Error   string     `json:"error,omitempty"`
	}
	if err := c.do(ctx, http.MethodPost, "/v1/ledger/seal", nil, nil, &env); err != nil {
		return nil, err
	}
	return &env.Data, nil
}

// LedgerProof calls GET /v1/ledger/proof/:entryId.
func (c *Client) LedgerProof(ctx context.Context, entryID string) (*InclusionProof, error) {
	var env struct {
		Success bool           `json:"success"`
		Data    InclusionProof `json:"data"`
		Error   string         `json:"error,omitempty"`
	}
	if err := c.do(ctx, http.MethodGet, "/v1/ledger/proof/"+url.PathEscape(entryID), nil, nil, &env); err != nil {
		return nil, err
	}
	return &env.Data, nil
}

// LedgerBundle calls GET /v1/ledger/bundle and returns the raw JSON bytes,
// suitable for direct use with `postq ledger verify`.
func (c *Client) LedgerBundle(ctx context.Context) ([]byte, error) {
	u := c.endpoint + "/v1/ledger/bundle"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", c.userAgent)
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("GET /v1/ledger/bundle: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		var errEnv struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(raw, &errEnv)
		if errEnv.Error == "" {
			return nil, fmt.Errorf("api error: status %d: %s", resp.StatusCode, string(raw))
		}
		return nil, fmt.Errorf("api error: %s", errEnv.Error)
	}
	// API returns {"success":true,"data":{...}} — unwrap to the inner bundle.
	var env struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, fmt.Errorf("parse bundle: %w", err)
	}
	if len(env.Data) == 0 {
		return raw, nil
	}
	return env.Data, nil
}

// ─────────────────────────── Vault ───────────────────────────

// VaultSettings is per-org BYOK / KMS configuration. The encrypted secret
// is never returned in plaintext.
type VaultSettings struct {
	KekProvider  string         `json:"kekProvider"`
	Aws          map[string]any `json:"aws,omitempty"`
	Azure        map[string]any `json:"azure,omitempty"`
	ConfiguredAt *string        `json:"configuredAt,omitempty"`
	UpdatedAt    *string        `json:"updatedAt,omitempty"`
}

// GetVaultSettings calls GET /v1/vault/settings. Returns nil if unset.
func (c *Client) GetVaultSettings(ctx context.Context) (*VaultSettings, error) {
	var env struct {
		Success bool           `json:"success"`
		Data    *VaultSettings `json:"data"`
		Error   string         `json:"error,omitempty"`
	}
	if err := c.do(ctx, http.MethodGet, "/v1/vault/settings", nil, nil, &env); err != nil {
		return nil, err
	}
	return env.Data, nil
}

// PutVaultSettings calls PUT /v1/vault/settings.
func (c *Client) PutVaultSettings(ctx context.Context, body map[string]any) (*VaultSettings, error) {
	var env struct {
		Success bool          `json:"success"`
		Data    VaultSettings `json:"data"`
		Error   string        `json:"error,omitempty"`
	}
	if err := c.do(ctx, http.MethodPut, "/v1/vault/settings", nil, body, &env); err != nil {
		return nil, err
	}
	return &env.Data, nil
}

// ClearVaultSettings calls DELETE /v1/vault/settings.
func (c *Client) ClearVaultSettings(ctx context.Context) error {
	var env struct {
		Success bool   `json:"success"`
		Error   string `json:"error,omitempty"`
	}
	return c.do(ctx, http.MethodDelete, "/v1/vault/settings", nil, nil, &env)
}
