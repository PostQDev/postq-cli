// Package apiclient submits scan reports to the PostQ API.
package apiclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/postqdev/postq-cli/internal/report"
)

// Client posts scan submissions to /v1/scans on the PostQ API.
type Client struct {
	endpoint  string
	apiKey    string
	userAgent string
	http      *http.Client
}

// New creates a Client. userAgent is sent in the User-Agent header so
// the server can correlate uploads with CLI versions.
func New(endpoint, apiKey, userAgent string) *Client {
	if userAgent == "" {
		userAgent = "postq-cli/dev"
	}
	return &Client{
		endpoint:  endpoint,
		apiKey:    apiKey,
		userAgent: userAgent,
		http:      &http.Client{Timeout: 30 * time.Second},
	}
}

// SubmitResponse is the API's success payload.
type SubmitResponse struct {
	Success bool `json:"success"`
	Data    struct {
		ID        string `json:"id"`
		CreatedAt string `json:"createdAt"`
		URL       string `json:"url"`
	} `json:"data"`
	Error string `json:"error,omitempty"`
}

// ListResponse is the API's response for GET /v1/scans.
type ListResponse struct {
	Success bool `json:"success"`
	Data    []struct {
		ID            string `json:"id"`
		Type          string `json:"type"`
		Target        string `json:"target"`
		RiskScore     int    `json:"riskScore"`
		RiskLevel     string `json:"riskLevel"`
		FindingsCount int    `json:"findingsCount"`
		Source        string `json:"source"`
		CreatedAt     string `json:"createdAt"`
		URL           string `json:"url"`
	} `json:"data"`
	Error string `json:"error,omitempty"`
}

// Submit POSTs the report to /v1/scans and returns the parsed response.
func (c *Client) Submit(ctx context.Context, sub *report.Submission) (*SubmitResponse, error) {
	body, err := json.Marshal(sub)
	if err != nil {
		return nil, fmt.Errorf("marshal: %w", err)
	}

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		c.endpoint+"/v1/scans",
		bytes.NewReader(body),
	)
	if err != nil {
		return nil, err
	}
	c.setHeaders(req)

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("post /v1/scans: %w", err)
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(resp.Body)

	var parsed SubmitResponse
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil, fmt.Errorf("parse response (status %d): %s", resp.StatusCode, string(raw))
	}
	if resp.StatusCode >= 400 || !parsed.Success {
		msg := parsed.Error
		if msg == "" {
			msg = fmt.Sprintf("status %d: %s", resp.StatusCode, string(raw))
		}
		return nil, fmt.Errorf("api error: %s", msg)
	}
	return &parsed, nil
}

// List GETs /v1/scans and returns recent scans visible to the API key.
func (c *Client) List(ctx context.Context, limit int) (*ListResponse, error) {
	url := fmt.Sprintf("%s/v1/scans?limit=%d", c.endpoint, limit)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	c.setHeaders(req)

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("get /v1/scans: %w", err)
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(resp.Body)
	var parsed ListResponse
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil, fmt.Errorf("parse response (status %d): %s", resp.StatusCode, string(raw))
	}
	if resp.StatusCode >= 400 || !parsed.Success {
		msg := parsed.Error
		if msg == "" {
			msg = fmt.Sprintf("status %d: %s", resp.StatusCode, string(raw))
		}
		return nil, fmt.Errorf("api error: %s", msg)
	}
	return &parsed, nil
}

func (c *Client) setHeaders(req *http.Request) {
	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", c.userAgent)
}

// CloudScanRequest is the body for POST /v1/scans/cloud.
type CloudScanRequest struct {
	Provider string                 `json:"provider"`        // aws | azure | kubernetes
	Target   string                 `json:"target"`          // account id / subscription id / cluster name
	AWS      *CloudScanAWSOptions   `json:"aws,omitempty"`   // AWS-only options
	Azure    *CloudScanAzureOptions `json:"azure,omitempty"` // Azure-only options
}

// CloudScanAWSOptions tunes a server-side AWS scan.
type CloudScanAWSOptions struct {
	Regions    []string `json:"regions,omitempty"`
	RoleArn    string   `json:"roleArn,omitempty"`
	ExternalID string   `json:"externalId,omitempty"`
}

// CloudScanAzureOptions tunes a server-side Azure Key Vault scan.
type CloudScanAzureOptions struct {
	SubscriptionID string   `json:"subscriptionId"`
	TenantID       string   `json:"tenantId,omitempty"`
	ClientID       string   `json:"clientId,omitempty"`
	ClientSecret   string   `json:"clientSecret,omitempty"`
	VaultNames     []string `json:"vaultNames,omitempty"`
}

// CloudScanResponse is the API's success payload for POST /v1/scans/cloud.
type CloudScanResponse struct {
	Success bool `json:"success"`
	Data    struct {
		ID             string `json:"id"`
		CreatedAt      string `json:"createdAt"`
		Provider       string `json:"provider"`
		Target         string `json:"target"`
		Mode           string `json:"mode"`
		RiskScore      int    `json:"riskScore"`
		RiskLevel      string `json:"riskLevel"`
		FindingsCount  int    `json:"findingsCount"`
		ResourcesCount int    `json:"resourcesCount"`
		Summary        struct {
			TotalEndpoints    int `json:"totalEndpoints"`
			QuantumVulnerable int `json:"quantumVulnerable"`
			HybridEnabled     int `json:"hybridEnabled"`
			PqReady           int `json:"pqReady"`
		} `json:"summary"`
		URL string `json:"url"`
	} `json:"data"`
	Error string `json:"error,omitempty"`
}

// ScanCloud POSTs to /v1/scans/cloud asking the API to run a server-side
// cloud scan and persist findings.
func (c *Client) ScanCloud(ctx context.Context, req *CloudScanRequest) (*CloudScanResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		c.endpoint+"/v1/scans/cloud",
		bytes.NewReader(body),
	)
	if err != nil {
		return nil, err
	}
	c.setHeaders(httpReq)

	// Cloud scans can take longer than the default 30s (per-region KMS calls).
	httpClient := &http.Client{Timeout: 5 * time.Minute}
	resp, err := httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("post /v1/scans/cloud: %w", err)
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(resp.Body)
	var parsed CloudScanResponse
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil, fmt.Errorf("parse response (status %d): %s", resp.StatusCode, string(raw))
	}
	if resp.StatusCode >= 400 || !parsed.Success {
		msg := parsed.Error
		if msg == "" {
			msg = fmt.Sprintf("status %d: %s", resp.StatusCode, string(raw))
		}
		return nil, fmt.Errorf("api error: %s", msg)
	}
	return &parsed, nil
}

// URLScanRequest is the body for POST /v1/scans/url.
type URLScanRequest struct {
	Target             string `json:"target"`
	InsecureSkipVerify bool   `json:"insecureSkipVerify,omitempty"`
	TimeoutMS          int    `json:"timeoutMs,omitempty"`
}

// URLScanFinding mirrors a row from the inline findings array on /v1/scans/url.
type URLScanFinding struct {
	Severity    string `json:"severity"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Location    string `json:"location"`
	Algorithm   string `json:"algorithm,omitempty"`
	Remediation string `json:"remediation"`
	Vulnerable  bool   `json:"vulnerable"`
}

// URLScanResponse is the API's success payload for POST /v1/scans/url.
type URLScanResponse struct {
	Success bool `json:"success"`
	Data    struct {
		ID             string            `json:"id"`
		CreatedAt      string            `json:"createdAt"`
		Target         string            `json:"target"`
		Mode           string            `json:"mode"`
		RiskScore      int               `json:"riskScore"`
		RiskLevel      string            `json:"riskLevel"`
		FindingsCount  int               `json:"findingsCount"`
		Metadata       map[string]string `json:"metadata"`
		Findings       []URLScanFinding  `json:"findings"`
		ScanDurationMS int64             `json:"scanDurationMs"`
		URL            string            `json:"url"`
	} `json:"data"`
	Error string `json:"error,omitempty"`
}

// ScanURL POSTs to /v1/scans/url asking the API to run a server-side
// TLS / cert / HNDL scan and persist findings.
func (c *Client) ScanURL(ctx context.Context, req *URLScanRequest) (*URLScanResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		c.endpoint+"/v1/scans/url",
		bytes.NewReader(body),
	)
	if err != nil {
		return nil, err
	}
	c.setHeaders(httpReq)

	// URL scans run server-side and may take a few seconds for a TLS
	// handshake + PQ probe — give them more headroom than the default 30s.
	httpClient := &http.Client{Timeout: 90 * time.Second}
	resp, err := httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("post /v1/scans/url: %w", err)
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(resp.Body)
	var parsed URLScanResponse
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil, fmt.Errorf("parse response (status %d): %s", resp.StatusCode, string(raw))
	}
	if resp.StatusCode >= 400 || !parsed.Success {
		msg := parsed.Error
		if msg == "" {
			msg = fmt.Sprintf("status %d: %s", resp.StatusCode, string(raw))
		}
		return nil, fmt.Errorf("api error: %s", msg)
	}
	return &parsed, nil
}
