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

## Install

Homebrew installs both binaries:

```bash
brew install PostQDev/tap/postq
```

Or install directly with Go:

```bash
go install github.com/postqdev/postq-cli/cmd/postq@latest
go install github.com/postqdev/postq-cli/cmd/postq-mcp@latest
```

Release archives contain both static binaries and are covered by the release
checksums, SBOM, and provenance attestation.

### Build from source

```bash
go build -o ~/go/bin/postq-mcp ./cmd/postq-mcp
go build -o ~/go/bin/postq      ./cmd/postq   # the CLI the server drives
```

## Configure

The server locates the CLI via the `POSTQ_BIN` environment variable (default: `postq` on `PATH`). Set it to an explicit, trusted build to pin exactly which binary executes. Do not let untrusted users control the MCP process environment. Run `postq auth login` once if you want to use `sign` and `verify`; offline scans need no credentials.

### VS Code / GitHub Copilot

Run **MCP: Add Server** from the Command Palette, choose **stdio**, and enter
`postq-mcp`. Or create `.vscode/mcp.json`:

```json
{
  "servers": {
    "postq": {
      "type": "stdio",
      "command": "postq-mcp",
      "env": { "POSTQ_BIN": "postq" }
    }
  }
}
```

Start the server from the inline action in that file. In Copilot Chat, select
**Configure Tools**, enable the PostQ tools, and ask: *"Use PostQ to scan
example.com for quantum-vulnerable cryptography."* Use absolute binary paths in
shared or production configurations. Never commit an API key to `mcp.json`.

### Claude Desktop

`~/Library/Application Support/Claude/claude_desktop_config.json`

```json
{
  "mcpServers": {
    "postq": {
      "command": "/absolute/path/to/postq-mcp",
      "env": {
        "POSTQ_BIN": "/absolute/path/to/postq"
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
      "command": "/absolute/path/to/postq-mcp",
      "env": { "POSTQ_BIN": "/absolute/path/to/postq" }
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

## Security boundary

- `scan_url` makes an outbound TLS connection to the requested host.
- `scan_code` reads the requested local file or directory. Client tool approval
  is the authorization boundary; do not approve paths the agent should not read.
- `sign` and `verify` may call `https://api.postq.dev` using the API key resolved
  by the CLI. Prefer `postq auth login` or your client's secret-input facility
  over hardcoding credentials in JSON.
- The server never invokes a shell. It executes the pinned `POSTQ_BIN` directly,
  bounds requests and output, and enforces a per-call timeout.
- This is a local stdio server, not a hosted remote MCP endpoint.

## Troubleshooting

| Symptom | Fix |
|---|---|
| Server starts but tools fail with `postq` not found | Set `POSTQ_BIN` to the absolute CLI path. Check with `command -v postq`. |
| Client cannot start `postq-mcp` | Use the absolute server path and confirm it is executable. Check with `command -v postq-mcp`. |
| `sign` or `verify` returns an auth error | Run `postq auth login`, or provide `POSTQ_API_KEY` through the MCP client's secret facility. |
| Scan times out | Increase `POSTQ_MCP_TIMEOUT`, for example `5m`; values are bounded to 1 second–10 minutes. |
| Tools do not appear after editing config | Restart the server or run **MCP: List Servers**, then refresh/restart it. |
| Need protocol diagnostics | Use the smoke test below and inspect the client's MCP output log; protocol data is stdout and diagnostics are stderr. |

## Manual smoke test

```bash
printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{}}}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' \
  '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"scan_url","arguments":{"host":"example.com"}}}' \
  | POSTQ_BIN="$HOME/go/bin/postq" postq-mcp
```
