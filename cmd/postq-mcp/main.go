// Command postq-mcp is a Model Context Protocol (MCP) server that exposes
// PostQ's cryptographic-posture tools to AI agents (Claude Desktop, Cursor,
// etc.). It speaks MCP over stdio (newline-delimited JSON-RPC 2.0) and is a
// pure-stdlib single Go binary — no runtime, no dependencies.
//
// Each tool is a thin adapter over the `postq` CLI, so an agent gets exactly
// the same scanner, scoring, and behaviour a human does at the terminal. Point
// it at a specific CLI build with the POSTQ_BIN environment variable (defaults
// to `postq` on PATH).
//
// Protocol: https://modelcontextprotocol.io — stdio transport, JSON-RPC 2.0.
// IMPORTANT: stdout carries the protocol; only JSON-RPC may be written there.
// All human/log output goes to stderr.
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

const (
	serverName        = "postq-mcp"
	defaultProto      = "2024-11-05"
	maxFrameBytes     = 2 << 20
	maxOutputBytes    = 4 << 20
	maxPayloadBytes   = 1 << 20
	defaultCmdTimeout = 2 * time.Minute
)

var serverVersion = "dev"

// ── JSON-RPC 2.0 envelopes ───────────────────────────────────────────────────

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  interface{}     `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

func main() {
	fmt.Fprintf(os.Stderr, "%s %s ready (POSTQ_BIN=%s)\n", serverName, serverVersion, postqBin())

	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 0, 64*1024), maxFrameBytes)
	out := bufio.NewWriter(os.Stdout)

	for in.Scan() {
		line := bytes.TrimSpace(in.Bytes())
		if len(line) == 0 {
			continue
		}
		var req rpcRequest
		if err := json.Unmarshal(line, &req); err != nil {
			writeRPCResponse(out, rpcResponse{
				JSONRPC: "2.0",
				ID:      json.RawMessage("null"),
				Error:   &rpcError{Code: -32700, Message: "parse error"},
			})
			continue
		}
		isNotification := len(req.ID) == 0
		result, rerr := dispatch(req)
		if isNotification {
			continue // notifications get no response
		}
		resp := rpcResponse{JSONRPC: "2.0", ID: req.ID}
		if rerr != nil {
			resp.Error = rerr
		} else {
			resp.Result = result
		}
		writeRPCResponse(out, resp)
	}
	if err := in.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "%s input closed: %v\n", serverName, err)
	}
}

func writeRPCResponse(out *bufio.Writer, resp rpcResponse) {
	b, err := json.Marshal(resp)
	if err != nil {
		return
	}
	_, _ = out.Write(b)
	_ = out.WriteByte('\n')
	_ = out.Flush()
}

func dispatch(req rpcRequest) (interface{}, *rpcError) {
	switch req.Method {
	case "initialize":
		return initializeResult(req.Params), nil
	case "notifications/initialized":
		return nil, nil
	case "ping":
		return map[string]interface{}{}, nil
	case "tools/list":
		return map[string]interface{}{"tools": toolList()}, nil
	case "tools/call":
		return toolsCall(req.Params)
	default:
		return nil, &rpcError{Code: -32601, Message: "method not found: " + req.Method}
	}
}

func initializeResult(params json.RawMessage) interface{} {
	proto := defaultProto
	if len(params) > 0 {
		var p struct {
			ProtocolVersion string `json:"protocolVersion"`
		}
		if json.Unmarshal(params, &p) == nil && p.ProtocolVersion != "" {
			proto = p.ProtocolVersion
		}
	}
	return map[string]interface{}{
		"protocolVersion": proto,
		"capabilities": map[string]interface{}{
			"tools": map[string]interface{}{},
		},
		"serverInfo": map[string]interface{}{
			"name":    serverName,
			"version": serverVersion,
		},
	}
}

// ── Tool catalogue ───────────────────────────────────────────────────────────

func toolList() []map[string]interface{} {
	strProp := func(desc string) map[string]interface{} {
		return map[string]interface{}{"type": "string", "description": desc}
	}
	boolProp := func(desc string, defaultValue bool) map[string]interface{} {
		return map[string]interface{}{"type": "boolean", "description": desc, "default": defaultValue}
	}
	obj := func(props map[string]interface{}, required ...string) map[string]interface{} {
		return map[string]interface{}{
			"type":       "object",
			"properties": props,
			"required":   required,
		}
	}
	return []map[string]interface{}{
		{
			"name": "scan_url",
			"description": "Scan a host's live TLS configuration for quantum-vulnerable cryptography " +
				"(RSA/ECDSA certificate keys, ECDHE key exchange, weak signature algorithms). " +
				"Uses the authenticated PostQ API by default, persists the scan, and returns a dashboard URL. " +
				"Set upload=false for an offline local scan. Returns JSON findings with severity and remediation guidance.",
			"inputSchema": obj(map[string]interface{}{
				"host":   strProp("Hostname or host:port to scan, e.g. example.com"),
				"upload": boolProp("Persist the scan to the authenticated PostQ organization and return a dashboard URL", true),
			}, "host"),
			"annotations": map[string]interface{}{"readOnlyHint": false},
		},
		{
			"name": "scan_code",
			"description": "Scan a local directory for cryptographic-misuse patterns (weak RNG, " +
				"MD5/SHA-1 in signing paths, JWT alg:none, AES-ECB, hardcoded private keys, " +
				"classical-only signing). Runs locally; no credentials required. Returns JSON findings.",
			"inputSchema": obj(map[string]interface{}{
				"path": strProp("Filesystem path to a directory or file to scan, e.g. ."),
			}, "path"),
			"annotations": map[string]interface{}{"readOnlyHint": true},
		},
		{
			"name": "sign",
			"description": "Sign a UTF-8 payload with a hybrid post-quantum key (ML-DSA + classical) " +
				"managed by PostQ. Requires an API key (POSTQ_API_KEY). Returns the composite signature JSON.",
			"inputSchema": obj(map[string]interface{}{
				"key_id":  strProp("Hybrid key ID to sign with"),
				"payload": strProp("UTF-8 text to sign"),
			}, "key_id", "payload"),
			"annotations": map[string]interface{}{"readOnlyHint": false},
		},
		{
			"name": "verify",
			"description": "Verify a hybrid post-quantum signature over a UTF-8 payload. Requires an " +
				"API key (POSTQ_API_KEY). Returns the verification result JSON (classical + PQ halves).",
			"inputSchema": obj(map[string]interface{}{
				"key_id":    strProp("Hybrid key ID the payload was signed with"),
				"payload":   strProp("The original UTF-8 payload"),
				"signature": strProp("The composite signature string produced by sign"),
			}, "key_id", "payload", "signature"),
			"annotations": map[string]interface{}{"readOnlyHint": true},
		},
	}
}

// ── Tool dispatch ────────────────────────────────────────────────────────────

func toolsCall(params json.RawMessage) (interface{}, *rpcError) {
	var p struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, &rpcError{Code: -32602, Message: "invalid tools/call params"}
	}
	switch p.Name {
	case "scan_url":
		return callScanURL(p.Arguments), nil
	case "scan_code":
		return callScanCode(p.Arguments), nil
	case "sign":
		return callSign(p.Arguments), nil
	case "verify":
		return callVerify(p.Arguments), nil
	default:
		return toolError("unknown tool: " + p.Name), nil
	}
}

func callScanURL(args json.RawMessage) interface{} {
	var a struct {
		Host   string `json:"host"`
		Upload *bool  `json:"upload"`
	}
	if err := json.Unmarshal(args, &a); err != nil {
		return toolError("arguments must be a JSON object")
	}
	if strings.TrimSpace(a.Host) == "" {
		return toolError("host is required")
	}
	if len(a.Host) > 500 {
		return toolError("host exceeds 500 characters")
	}
	upload := true
	if a.Upload != nil {
		upload = *a.Upload
	}
	so, se, code := runPostq(nil, scanURLArgs(a.Host, upload)...)
	// `scan url` exits 2 when it finds High/Critical risk — that is a successful
	// scan, not a failure. Only treat a spawn failure / empty output as an error.
	if code < 0 {
		return toolError("could not run postq: " + firstNonEmpty(se, "unknown error"))
	}
	if strings.TrimSpace(so) == "" {
		return toolError(firstNonEmpty(se, "scan produced no output"))
	}
	return toolText(so)
}

func scanURLArgs(host string, upload bool) []string {
	args := []string{"scan", "url", host}
	if !upload {
		args = append(args, "--local", "--no-upload")
	}
	return append(args, "--json")
}

func callScanCode(args json.RawMessage) interface{} {
	var a struct {
		Path string `json:"path"`
	}
	if err := json.Unmarshal(args, &a); err != nil {
		return toolError("arguments must be a JSON object")
	}
	if strings.TrimSpace(a.Path) == "" {
		return toolError("path is required")
	}
	if len(a.Path) > 4096 {
		return toolError("path exceeds 4096 characters")
	}
	so, se, code := runPostq(nil, "scan", "code", a.Path, "--json")
	if code < 0 {
		return toolError("could not run postq: " + firstNonEmpty(se, "unknown error"))
	}
	if strings.TrimSpace(so) == "" {
		return toolError(firstNonEmpty(se, "scan produced no output"))
	}
	return toolText(so)
}

func callSign(args json.RawMessage) interface{} {
	var a struct {
		KeyID   string `json:"key_id"`
		Payload string `json:"payload"`
	}
	if err := json.Unmarshal(args, &a); err != nil {
		return toolError("arguments must be a JSON object")
	}
	if a.KeyID == "" || a.Payload == "" {
		return toolError("key_id and payload are required")
	}
	if len(a.KeyID) > 128 || len(a.Payload) > maxPayloadBytes {
		return toolError("key_id or payload exceeds the supported size")
	}
	so, se, code := runPostq([]byte(a.Payload), "sign", "--key", a.KeyID, "--in", "-", "--json")
	if code < 0 {
		return toolError("could not run postq: " + firstNonEmpty(se, "unknown error"))
	}
	if code != 0 {
		return toolError(firstNonEmpty(se, "sign failed"))
	}
	return toolText(firstNonEmpty(so, se))
}

func callVerify(args json.RawMessage) interface{} {
	var a struct {
		KeyID     string `json:"key_id"`
		Payload   string `json:"payload"`
		Signature string `json:"signature"`
	}
	if err := json.Unmarshal(args, &a); err != nil {
		return toolError("arguments must be a JSON object")
	}
	if a.KeyID == "" || a.Payload == "" || a.Signature == "" {
		return toolError("key_id, payload and signature are required")
	}
	if len(a.KeyID) > 128 || len(a.Payload) > maxPayloadBytes || len(a.Signature) > maxFrameBytes {
		return toolError("key_id, payload or signature exceeds the supported size")
	}
	// verify needs two inputs; only one can be stdin. Write the payload to a
	// temp file and stream the signature over stdin.
	tmp, err := os.CreateTemp("", "postq-mcp-payload-*")
	if err != nil {
		return toolError("could not create temp file: " + err.Error())
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.WriteString(a.Payload); err != nil {
		tmp.Close()
		return toolError("could not write temp file: " + err.Error())
	}
	tmp.Close()

	so, se, code := runPostq([]byte(a.Signature), "verify", "--key", a.KeyID, "--in", tmp.Name(), "--sig", "-", "--json")
	if code < 0 {
		return toolError("could not run postq: " + firstNonEmpty(se, "unknown error"))
	}
	// verify exits non-zero when the signature is invalid; the JSON result on
	// stdout still describes the outcome, so surface it as text when present.
	if strings.TrimSpace(so) != "" {
		return toolText(so)
	}
	return toolError(firstNonEmpty(se, "verification failed"))
}

// ── MCP result helpers ───────────────────────────────────────────────────────

func toolText(s string) interface{} {
	return map[string]interface{}{
		"content": []map[string]interface{}{
			{"type": "text", "text": s},
		},
	}
}

func toolError(s string) interface{} {
	return map[string]interface{}{
		"content": []map[string]interface{}{
			{"type": "text", "text": s},
		},
		"isError": true,
	}
}

// ── postq subprocess ─────────────────────────────────────────────────────────

func postqBin() string {
	if b := os.Getenv("POSTQ_BIN"); b != "" {
		return b
	}
	return "postq"
}

// runPostq executes the postq CLI and returns stdout, stderr, and the exit
// code. A code of -1 means the process could not be started at all.
func runPostq(stdin []byte, args ...string) (string, string, int) {
	ctx, cancel := context.WithTimeout(context.Background(), commandTimeout())
	defer cancel()
	cmd := exec.CommandContext(ctx, postqBin(), args...)
	cmd.WaitDelay = 5 * time.Second
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	so := newCappedBuffer(maxOutputBytes)
	se := newCappedBuffer(maxOutputBytes)
	cmd.Stdout = &so
	cmd.Stderr = &se
	err := cmd.Run()
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return so.String(), "postq command timed out", -1
	}
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			return so.String(), se.String(), ee.ExitCode()
		}
		return "", err.Error(), -1
	}
	return so.String(), se.String(), 0
}

func commandTimeout() time.Duration {
	raw := strings.TrimSpace(os.Getenv("POSTQ_MCP_TIMEOUT"))
	if raw == "" {
		return defaultCmdTimeout
	}
	if seconds, err := strconv.Atoi(raw); err == nil {
		return clampDuration(time.Duration(seconds) * time.Second)
	}
	if parsed, err := time.ParseDuration(raw); err == nil {
		return clampDuration(parsed)
	}
	return defaultCmdTimeout
}

func clampDuration(value time.Duration) time.Duration {
	if value < time.Second {
		return time.Second
	}
	if value > 10*time.Minute {
		return 10 * time.Minute
	}
	return value
}

type cappedBuffer struct {
	buf       bytes.Buffer
	remaining int
	truncated bool
}

func newCappedBuffer(limit int) cappedBuffer {
	return cappedBuffer{remaining: limit}
}

func (b *cappedBuffer) Write(p []byte) (int, error) {
	originalLen := len(p)
	if len(p) > b.remaining {
		p = p[:b.remaining]
		b.truncated = true
	}
	if len(p) > 0 {
		_, _ = b.buf.Write(p)
		b.remaining -= len(p)
	}
	return originalLen, nil
}

func (b *cappedBuffer) String() string {
	if b.truncated {
		return b.buf.String() + "\n[output truncated by postq-mcp]"
	}
	return b.buf.String()
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}
