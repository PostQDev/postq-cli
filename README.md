# PostQ CLI

A single Go binary for running [PostQ](https://postq.dev) cryptographic-posture scans from your laptop, CI pipeline, Kubernetes CronJob, AWS Lambda, or Azure Container Instance.

Run it with no arguments and you drop into an interactive shell:

```
postq
```

```
  ██████╗  ██████╗ ███████╗████████╗   ▄▄▄▄▄
  ██╔══██╗██╔═══██╗██╔════╝╚══██╔══╝  █     █
  ██████╔╝██║   ██║███████╗   ██║     █  ◆  █
  ██╔═══╝ ██║   ██║╚════██║   ██║     █     █
  ██║     ╚██████╔╝███████║   ██║      ▀▀█▄▀
  ╚═╝      ╚═════╝ ╚══════╝   ╚═╝         ▀▀

  cryptographic posture for whatever Q-Day comes next
  what's your [Quantum]?

  postq  ›
```

The first launch walks you through pasting an API key and saves it to `~/.postq/config.json` (mode 0600). After that, type `help` for the command palette.

Or use the same commands one-shot from your shell:

```
postq scan url example.com
postq scan url a.com b.com c.com --concurrency 5
postq scan code ./             # NEW — local crypto-misuse scan (beta)
postq scan cloud aws --account 123456789012 --role-arn arn:aws:iam::123456789012:role/PostQScanner
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

After any install method, start the interactive CLI:

```bash
postq
```

First launch asks for your API key, saves it to `~/.postq/config.json`, and then drops you into the boxed PostQ shell.

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
# 1. Install
brew install PostQDev/tap/postq

# 2. Start PostQ — first launch prompts for your API key
postq

# 3. In the interactive shell, run a scan
scan url example.com

# 4. Open the URL printed at the bottom to view findings in the portal
```

## Commands

```
postq <command> [subcommand] [flags] [args]

  scan url <host>...        TLS handshake + cert quantum-risk scan
  scan cloud aws            Scan AWS KMS keys for quantum-vulnerable algorithms
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
| `--account <id>` (`scan cloud aws`)     | AWS account ID to scan (defaults to caller identity)          |
| `--regions <list>` (`scan cloud aws`)   | Comma-separated regions (default: `us-east-1,us-west-2,eu-west-1`) |
| `--role-arn <arn>` (`scan cloud aws`)   | IAM role to assume in the target account                      |
| `--external-id <id>` (`scan cloud aws`) | External ID for cross-account role assumption                 |

The `scan cloud aws` subcommand uses your local AWS credentials (env vars, `~/.aws/credentials`, IMDS, etc.) and submits results to `POST /v1/scans/cloud`. It enumerates KMS keys across the requested regions and flags RSA / ECC keys as quantum-vulnerable.

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
- `postq scan cloud aws` — KMS keys (shipped); ACM, ALB, S3, Secrets Manager next
- `postq scan cloud azure [--subscription …]` — Key Vault, App Service, Storage
- `postq scan bulk --file targets.txt` — fan-out over many targets
- Scoop bucket for Windows
- Native packages (`.deb`, `.rpm`, `.apk`)

## License

MIT — see [LICENSE](LICENSE).
