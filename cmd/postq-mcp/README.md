# postq-mcp

A [Model Context Protocol](https://modelcontextprotocol.io) server that exposes PostQ's cryptographic-posture tools to AI agents (Claude Desktop, Cursor, Claude Code, …).

It is a **pure-stdlib, single Go binary** — no runtime, no `node_modules`, nothing to `npm install`. It speaks MCP over stdio (newline-delimited JSON-RPC 2.0) and each tool is a thin adapter over the `postq` CLI, so an agent gets exactly the same scanner and scoring a human gets at the terminal.

## Tools

| Tool | What it does | Needs API key? |
|---|---|---|
| `scan_url` | Live TLS handshake against a host; reports quantum-vulnerable keys/ciphers/signatures | No (offline) |
| `scan_code` | Scans a local directory for crypto-misuse patterns (weak RNG, MD5/SHA-1 signing, JWT `alg:none`, hardcoded keys, …) | No (offline) |
| `sign` | Signs a payload with a hybrid post-quantum key (ML-DSA + classical) | Yes (`POSTQ_API_KEY`) |
| `verify` | Verifies a hybrid post-quantum signature | Yes (`POSTQ_API_KEY`) |

`scan_url` and `scan_code` run fully offline and need no credentials — ideal for a live demo.

## Build

```bash
go build -o ~/go/bin/postq-mcp ./cmd/postq-mcp
go build -o ~/go/bin/postq      ./cmd/postq   # the CLI the server drives
```

## Configure

The server locates the CLI via the `POSTQ_BIN` environment variable (default: `postq` on `PATH`). Set it to an explicit, trusted build to pin exactly which binary executes. Do not let untrusted users control the MCP process environment.

### Claude Desktop

`~/Library/Application Support/Claude/claude_desktop_config.json`

```json
{
  "mcpServers": {
    "postq": {
      "command": "/Users/pallab/go/bin/postq-mcp",
      "env": {
        "POSTQ_BIN": "/Users/pallab/go/bin/postq",
        "POSTQ_API_KEY": "pq_live_...   // only needed for sign / verify"
      }
    }
  }
}
```

Restart Claude Desktop, then ask: *"Use postq to scan example.com for quantum-vulnerable cryptography."*

### Cursor

`~/.cursor/mcp.json` (same shape):

```json
{
  "mcpServers": {
    "postq": {
      "command": "/Users/pallab/go/bin/postq-mcp",
      "env": { "POSTQ_BIN": "/Users/pallab/go/bin/postq" }
    }
  }
}
```

## Environment

| Variable | Purpose |
|---|---|
| `POSTQ_BIN` | Path to the `postq` CLI the server drives (default `postq`) |
| `POSTQ_API_KEY` | Passed through to `postq` for `sign` / `verify` |
| `POSTQ_MCP_TIMEOUT` | Per-tool subprocess deadline; default `2m`, bounded to `1s`–`10m` |

## Protocol notes

- stdio transport, JSON-RPC 2.0, newline-delimited.
- Handles `initialize`, `notifications/initialized`, `tools/list`, `tools/call`, `ping`.
- stdout carries the protocol only; all logs go to stderr.
- Frames are capped at 2 MiB, signed payloads at 1 MiB, and subprocess output at 4 MiB per stream.
- Every subprocess has a deadline and is terminated with its process context.

## Manual smoke test

```bash
printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{}}}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' \
  '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"scan_url","arguments":{"host":"example.com"}}}' \
  | POSTQ_BIN="$HOME/go/bin/postq" postq-mcp
```
