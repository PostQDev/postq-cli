# PostQ CLI

A single Go binary for running [PostQ](https://postq.dev) quantum-risk scans from your laptop, CI pipeline, Kubernetes CronJob, AWS Lambda, or Azure Container Instance.

```
postq auth login --api-key pq_live_…
postq scan url example.com
postq scan url a.com b.com c.com --concurrency 5
postq scan url example.com --no-upload --json
postq scan list --limit 10
```

Scan results are uploaded to the PostQ portal at `https://app.postq.dev/scans/<id>`. Use `--no-upload` to keep results local.

## Install

### Homebrew (macOS / Linux)

```bash
brew install PostQDev/tap/postq
```

### Go (any platform)

```bash
go install github.com/postqdev/postq-cli/cmd/postq@latest
```

### Pre-built binary (Linux / macOS / Windows)

Download from the [latest release](https://github.com/PostQDev/postq-cli/releases/latest), extract, and put `postq` (or `postq.exe`) on your `PATH`.

| Platform            | Asset                                   |
|---------------------|-----------------------------------------|
| macOS Apple Silicon | `postq_<v>_darwin_arm64.tar.gz`         |
| macOS Intel         | `postq_<v>_darwin_amd64.tar.gz`         |
| Linux x86_64        | `postq_<v>_linux_amd64.tar.gz`          |
| Linux arm64         | `postq_<v>_linux_arm64.tar.gz`          |
| Windows x86_64      | `postq_<v>_windows_amd64.zip`           |
| Windows arm64       | `postq_<v>_windows_arm64.zip`           |

## Quick start

```bash
# 1. Generate an API key at https://app.postq.dev/settings/api-keys
postq auth login --api-key pq_live_xxxxxxxxxxxxxxxxxxxxxxxx

# 2. Scan something
postq scan url example.com

# 3. Open the URL printed at the bottom to view findings in the portal
```

## Commands

```
postq <command> [subcommand] [flags] [args]

  scan url <host>...        TLS handshake + cert quantum-risk scan
  scan list                 Recent scans uploaded to your org
  auth login                Save API key for uploads
  auth whoami               Show active credentials (masked)
  auth logout               Forget saved credentials
  config path               Print path to config.json
  version                   Print version + build info
```

Run `postq <command> --help` for full per-command help with examples.

## Configuration

Auth is stored at `~/.postq/config.json` (file mode `0600`). Override with:

| Flag / env                              | Purpose                                                       |
|-----------------------------------------|---------------------------------------------------------------|
| `--api-key` / `POSTQ_API_KEY`           | Bearer key used for `/v1/scans`                               |
| `--api-endpoint` / `POSTQ_API_ENDPOINT` | API base URL (default `https://api.postq.dev`)                |
| `--no-upload`                           | Run scan locally only — print results, don't POST             |
| `--json`                                | Machine-readable output for CI                                |
| `--no-color` / `NO_COLOR`               | Disable ANSI colors                                           |
| `--insecure` (`scan url`)               | Skip TLS certificate verification                             |
| `--timeout <dur>` (`scan url`)          | Per-host TLS timeout (e.g. `5s`, `1m`)                        |
| `--concurrency <n>` (`scan url`)        | Number of hosts to scan in parallel (default 4)               |

## Exit codes

| Code | Meaning                                                          |
|------|------------------------------------------------------------------|
| 0    | Success — no Critical or High risk findings                      |
| 1    | Error (network, auth, unknown command, etc.)                     |
| 2    | Scan completed but found Critical or High risk (CI gate)         |

Use this in CI:

```yaml
- run: postq scan url ${{ env.PROD_DOMAIN }} --no-upload
  # exits 2 → job fails if quantum-vulnerable findings are Critical/High
```

## Development

```bash
git clone https://github.com/PostQDev/postq-cli
cd postq-cli
go build -o postq ./cmd/postq
./postq --help
go test ./...
```

### Cutting a release

```bash
git tag v0.1.0
git push origin v0.1.0
```

GitHub Actions runs GoReleaser, which:
1. Builds binaries for `darwin/{amd64,arm64}`, `linux/{amd64,arm64}`, `windows/{amd64,arm64}`.
2. Creates a GitHub Release with archives + checksums.
3. Updates `PostQDev/homebrew-tap` so `brew install PostQDev/tap/postq` works.

Required GitHub Secret on this repo: `HOMEBREW_TAP_TOKEN` (PAT with `contents:write` on `PostQDev/homebrew-tap`).

## Roadmap

- `postq scan github <repo>` — static analysis of source for RSA/ECDSA/MD5
- `postq scan k8s [--context …]` — TLS secrets, ingress certs, mTLS policies
- `postq scan aws [--regions …]` — KMS, ACM, ALB, S3, Secrets Manager
- `postq scan azure [--subscription …]` — Key Vault, App Service, Storage
- `postq scan bulk --file targets.txt` — fan-out over many targets
- Scoop bucket for Windows
- Native packages (`.deb`, `.rpm`, `.apk`)

## License

MIT — see [LICENSE](LICENSE).
