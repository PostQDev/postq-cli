# AGENTS.md — postq-cli

Single-binary Go CLI for PostQ. Lives in its own repo (`PostQDev/postq-cli`) so the install path is clean (`brew install PostQDev/tap/postq`, `go install github.com/postqdev/postq-cli/cmd/postq@latest`).

## Layout

```
cmd/postq/main.go              Entrypoint. Parses ldflag-injected version/commit/date.
internal/commands/             Subcommand dispatcher + help text.
internal/config/               ~/.postq/config.json (mode 0600). Resolve order: flag > env > file.
internal/scanurl/              Real TLS handshake + cert + cipher analysis.
internal/apiclient/            POST /v1/scans, GET /v1/scans → PostQ API.
internal/report/               Wire format. Mirrors postq-site/apps/api/src/routes/v1-scans.ts.
internal/ui/                   TTY-aware ANSI colors, severity/risk badges.
.goreleaser.yaml               Cross-platform release config.
.github/workflows/ci.yml       go vet/build/test on linux/macos/windows.
.github/workflows/release.yml  GoReleaser on tag push v*.
```

## Build & test

```bash
go build -o postq ./cmd/postq
./postq --help
go test ./...
go vet ./...
```

Stdlib only — **no external Go dependencies**. Keep it that way for fast cold-start in Lambda / minimal Docker images.

## Conventions

- `CGO_ENABLED=0` everywhere → fully static binaries.
- Wire format in `internal/report` must mirror Zod schema in `postq-site/apps/api/src/routes/v1-scans.ts`. If you change one, change the other.
- All output goes through `internal/ui` so `--no-color` / `NO_COLOR` works everywhere.
- Exit codes are part of the contract: 0 OK, 1 error, 2 Critical/High found. Don't break.
- Per-command help: every `runFooBar` parses with a `flag.NewFlagSet` and sets a custom `Usage` showing examples.

## Cutting a release

```bash
git tag v0.X.Y
git push origin v0.X.Y
```

That's it — GitHub Actions runs GoReleaser, which builds 6 binaries, makes a GitHub release, and updates the Homebrew tap. Requires `HOMEBREW_TAP_TOKEN` secret (PAT with `contents:write` on `PostQDev/homebrew-tap`).

## Adding a new `scan` subcommand

1. Add a package under `internal/scan<thing>/`.
2. Add `runScan<Thing>` in `internal/commands/commands.go`, register in `runScan` switch.
3. Update `printScanHelp()` example list.
4. Append to roadmap in [README.md](README.md).
5. Update `Type` field of submission to match a value the API accepts (`url|github|aws|azure|kubernetes|bulk`).

## Cross-repo touch points

- **API contract**: `internal/report/report.go` ↔ `postq-site/apps/api/src/routes/v1-scans.ts` Zod schema.
- **Portal URL**: built server-side from `PORTAL_BASE_URL` env on Render. CLI just prints `resp.data.url`.
- **API key format**: `pq_live_<24-base32>` / `pq_test_<…>`. Generated in `postq-site/apps/web/src/lib/api-keys.ts`, hashed in `postq-site/apps/api/src/lib/api-key-auth.ts`.
