package main

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestInitializeEchoesProtocolAndAdvertisesTools(t *testing.T) {
	params := json.RawMessage(`{"protocolVersion":"2025-06-18"}`)
	result := initializeResult(params).(map[string]interface{})
	if result["protocolVersion"] != "2025-06-18" {
		t.Fatalf("protocolVersion = %v", result["protocolVersion"])
	}
	if got := len(toolList()); got != 4 {
		t.Fatalf("tool count = %d, want 4", got)
	}
}

func TestDispatchRejectsUnknownMethod(t *testing.T) {
	_, rpcErr := dispatch(rpcRequest{Method: "unknown/method"})
	if rpcErr == nil || rpcErr.Code != -32601 {
		t.Fatalf("dispatch error = %+v", rpcErr)
	}
}

func TestSignRejectsOversizePayload(t *testing.T) {
	args, _ := json.Marshal(map[string]string{
		"key_id":  "key-1",
		"payload": strings.Repeat("x", maxPayloadBytes+1),
	})
	result := callSign(args).(map[string]interface{})
	if result["isError"] != true {
		t.Fatalf("callSign result = %+v, want tool error", result)
	}
}

func TestCappedBufferBoundsOutput(t *testing.T) {
	buf := newCappedBuffer(4)
	n, err := buf.Write([]byte("abcdefgh"))
	if err != nil || n != 8 {
		t.Fatalf("Write() = %d, %v", n, err)
	}
	if got := buf.String(); !strings.HasPrefix(got, "abcd") || !strings.Contains(got, "truncated") {
		t.Fatalf("String() = %q", got)
	}
}

func TestCommandTimeoutIsBounded(t *testing.T) {
	t.Setenv("POSTQ_MCP_TIMEOUT", "0")
	if got := commandTimeout(); got != time.Second {
		t.Fatalf("timeout = %s, want 1s", got)
	}
	t.Setenv("POSTQ_MCP_TIMEOUT", "24h")
	if got := commandTimeout(); got != 10*time.Minute {
		t.Fatalf("timeout = %s, want 10m", got)
	}
}
