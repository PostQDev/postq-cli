// Package commands wires CLI subcommands together.
package commands

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/postqdev/postq-cli/internal/apiclient"
	"github.com/postqdev/postq-cli/internal/config"
	"github.com/postqdev/postq-cli/internal/report"
	"github.com/postqdev/postq-cli/internal/scancode"
	"github.com/postqdev/postq-cli/internal/scanurl"
	"github.com/postqdev/postq-cli/internal/tui"
	"github.com/postqdev/postq-cli/internal/ui"
)

// BuildInfo is injected from main via -ldflags.
type BuildInfo struct {
	Version string
	Commit  string
	Date    string
}

func (b BuildInfo) userAgent() string {
	return "postq-cli/" + b.Version
}

// interactive is true while we're running inside the TUI shell. Lets
// long-running scan commands skip os.Exit so a Critical finding doesn't
// kill the whole REPL session.
var interactive bool

// exitOrReturn calls os.Exit(code) in batch mode, or just returns in
// interactive shell mode.
func exitOrReturn(code int) {
	if interactive {
		return
	}
	os.Exit(code) //nolint:revive // intentional CI gate
}

// runShell launches the TUI, wiring it back into the existing dispatcher.
func runShell(build BuildInfo) error {
	interactive = true
	defer func() { interactive = false }()
	return tui.Run(os.Stdin, os.Stdout, tui.Build{
		Version: build.Version,
		Commit:  build.Commit,
		Date:    build.Date,
	}, func(args []string) error {
		switch args[0] {
		case "auth":
			return runAuth(args[1:])
		case "scan":
			return runScan(args[1:], build)
		case "config":
			return runConfig(args[1:])
		case "sign":
			return runSign(args[1:], build)
		case "verify":
			return runVerify(args[1:], build)
		case "keys":
			return runKeys(args[1:], build)
		case "policies":
			return runPolicies(args[1:], build)
		case "vault":
			return runVault(args[1:], build)
		case "ledger":
			return runLedger(args[1:])
		case "version":
			printVersion(build)
			return nil
		default:
			return fmt.Errorf("unknown command: %s (try `help`)", args[0])
		}
	})
}

// Run dispatches to the appropriate subcommand.
func Run(args []string, build BuildInfo) error {
	args = stripNoColor(args)

	// `postq` with no args (and a TTY) launches the interactive shell.
	if len(args) == 0 {
		if isInteractive() {
			return runShell(build)
		}
		printRootHelp()
		return nil
	}
	if args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		printRootHelp()
		return nil
	}
	if args[0] == "-v" || args[0] == "--version" || args[0] == "version" {
		printVersion(build)
		return nil
	}

	switch args[0] {
	case "shell", "interactive", "repl":
		return runShell(build)
	case "auth":
		return runAuth(args[1:])
	case "scan":
		return runScan(args[1:], build)
	case "config":
		return runConfig(args[1:])
	case "sign":
		return runSign(args[1:], build)
	case "verify":
		return runVerify(args[1:], build)
	case "keys":
		return runKeys(args[1:], build)
	case "policies":
		return runPolicies(args[1:], build)
	case "vault":
		return runVault(args[1:], build)
	case "ledger":
		return runLedger(args[1:])
	default:
		printRootHelp()
		return fmt.Errorf("unknown command: %s", args[0])
	}
}

func isInteractive() bool {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	if (fi.Mode() & os.ModeCharDevice) == 0 {
		return false // piped/redirected
	}
	fo, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return (fo.Mode() & os.ModeCharDevice) != 0
}

func stripNoColor(args []string) []string {
	out := args[:0]
	for _, a := range args {
		switch a {
		case "--no-color", "--no-colour":
			ui.SetColor(false)
		default:
			out = append(out, a)
		}
	}
	return out
}

// ── help / version ───────────────────────────────────────────────────────────

func printRootHelp() {
	fmt.Println(ui.Bold("PostQ CLI") + " — interactive cryptographic-posture scanning")
	fmt.Println()
	fmt.Println(ui.Bold("USAGE"))
	fmt.Println("  postq                         Start the interactive shell")
	fmt.Println("  postq <command> [subcommand] [flags] [args]")
	fmt.Println()
	fmt.Println(ui.Bold("COMMANDS"))
	fmt.Println("  " + ui.Cyan("shell") + "                  Start the boxed PostQ shell")
	fmt.Println("  " + ui.Cyan("scan url") + " <host>...     TLS handshake + cert quantum-risk scan")
	fmt.Println("  " + ui.Cyan("scan code") + " <path>       Static crypto-misuse scan (beta)")
	fmt.Println("  " + ui.Cyan("scan cloud aws") + "        Server-side AWS KMS inventory")
	fmt.Println("  " + ui.Cyan("scan cloud azure") + "     Server-side Azure Key Vault inventory")
	fmt.Println("  " + ui.Cyan("scan list") + "              Recent scans uploaded to your org")
	fmt.Println("  " + ui.Cyan("sign") + "                   Sign a payload with a managed hybrid key")
	fmt.Println("  " + ui.Cyan("verify") + "                 Verify a composite hybrid signature")
	fmt.Println("  " + ui.Cyan("keys") + "                   Manage hybrid (PQ + classical) signing keys")
	fmt.Println("  " + ui.Cyan("policies") + "               Manage org-level signing policies")
	fmt.Println("  " + ui.Cyan("ledger") + "                 Inspect, seal, and verify the audit ledger")
	fmt.Println("  " + ui.Cyan("vault") + "                  Configure per-org KMS / BYOK settings")
	fmt.Println("  " + ui.Cyan("auth login") + "             Save API key for uploads")
	fmt.Println("  " + ui.Cyan("auth whoami") + "            Show active credentials (masked)")
	fmt.Println("  " + ui.Cyan("auth logout") + "            Forget saved credentials")
	fmt.Println("  " + ui.Cyan("config path") + "            Print path to config.json")
	fmt.Println("  " + ui.Cyan("version") + "                Print version + build info")
	fmt.Println()
	fmt.Println(ui.Bold("GLOBAL FLAGS"))
	fmt.Println("  --no-color                  Disable ANSI colors (or set NO_COLOR=1)")
	fmt.Println("  -h, --help                  Show help for any command")
	fmt.Println("  -v, --version               Print version")
	fmt.Println()
	fmt.Println(ui.Bold("ENVIRONMENT"))
	fmt.Println("  POSTQ_API_KEY               Override saved API key")
	fmt.Println("  POSTQ_API_ENDPOINT          Override API endpoint")
	fmt.Println()
	fmt.Println(ui.Bold("EXAMPLES"))
	fmt.Println("  postq")
	fmt.Println("  postq auth login --api-key pq_live_…")
	fmt.Println("  postq scan url example.com")
	fmt.Println("  postq scan code ./")
	fmt.Println("  postq scan cloud aws --account 123456789012 --role-arn arn:aws:iam::123456789012:role/PostQScanner")
	fmt.Println("  postq scan url example.com api.example.com --json")
	fmt.Println("  postq scan url example.com --no-upload")
	fmt.Println("  postq scan list --limit 20")
	fmt.Println("  postq keys create --name release-signing")
	fmt.Println("  postq sign --key <id> --in artifact.tar.gz --out artifact.sig")
	fmt.Println("  postq verify --key <id> --in artifact.tar.gz --sig artifact.sig")
	fmt.Println()
	fmt.Println(ui.Dim("Generate an API key at https://postq.dev/settings/api-keys"))
}

func printVersion(b BuildInfo) {
	fmt.Printf("postq %s\n", b.Version)
	fmt.Printf("  commit:  %s\n", b.Commit)
	fmt.Printf("  built:   %s\n", b.Date)
	fmt.Printf("  go:      %s\n", runtime.Version())
	fmt.Printf("  os/arch: %s/%s\n", runtime.GOOS, runtime.GOARCH)
}

// ── auth ─────────────────────────────────────────────────────────────────────

func runAuth(args []string) error {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" {
		printAuthHelp()
		return nil
	}
	switch args[0] {
	case "login":
		return runAuthLogin(args[1:])
	case "whoami":
		return runAuthWhoami()
	case "logout":
		return runAuthLogout()
	default:
		printAuthHelp()
		return fmt.Errorf("unknown auth subcommand: %s", args[0])
	}
}

func printAuthHelp() {
	fmt.Println(ui.Bold("postq auth") + " — manage PostQ API credentials")
	fmt.Println()
	fmt.Println(ui.Bold("SUBCOMMANDS"))
	fmt.Println("  login    Save API key (and optionally a custom endpoint)")
	fmt.Println("  whoami   Print configured endpoint + masked key")
	fmt.Println("  logout   Remove saved credentials")
	fmt.Println()
	fmt.Println(ui.Bold("EXAMPLES"))
	fmt.Println("  postq auth login --api-key pq_live_xxxxxxxxxxxxxxxxxxxxxxxx")
	fmt.Println("  postq auth login --api-key pq_live_… --api-endpoint https://api.example.com")
	fmt.Println("  postq auth whoami")
}

func runAuthLogin(args []string) error {
	fs := flag.NewFlagSet("auth login", flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprintln(fs.Output(), "Usage: postq auth login --api-key <key> [--api-endpoint <url>]")
		fs.PrintDefaults()
	}
	apiKey := fs.String("api-key", "", "PostQ API key (pq_live_…)")
	endpoint := fs.String("api-endpoint", "", "PostQ API endpoint (default: "+config.DefaultEndpoint+")")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *apiKey == "" {
		return fmt.Errorf("--api-key is required (generate one at https://postq.dev/settings/api-keys)")
	}
	if !strings.HasPrefix(*apiKey, "pq_live_") && !strings.HasPrefix(*apiKey, "pq_test_") {
		fmt.Fprintln(os.Stderr, ui.Yellow("warning:")+" key does not look like a PostQ key (expected pq_live_… or pq_test_…)")
	}

	c, _ := config.Load()
	c.APIKey = *apiKey
	if *endpoint != "" {
		c.APIEndpoint = *endpoint
	}
	if c.APIEndpoint == "" {
		c.APIEndpoint = config.DefaultEndpoint
	}
	if err := config.Save(c); err != nil {
		return err
	}
	path, _ := config.Path()
	fmt.Printf("%s Saved credentials to %s\n", ui.Green("✓"), path)
	fmt.Printf("  endpoint: %s\n", c.APIEndpoint)
	fmt.Printf("  key:      %s\n", config.MaskKey(c.APIKey))
	return nil
}

func runAuthWhoami() error {
	c, err := config.Load()
	if err != nil {
		return err
	}
	fmt.Printf("API endpoint: %s\n", c.APIEndpoint)
	fmt.Printf("API key:      %s\n", config.MaskKey(c.APIKey))
	if c.APIKey == "" {
		fmt.Println()
		fmt.Println(ui.Dim("Run `postq auth login --api-key …` to authenticate."))
	}
	return nil
}

func runAuthLogout() error {
	if err := config.Delete(); err != nil {
		return err
	}
	fmt.Printf("%s Credentials removed.\n", ui.Green("✓"))
	return nil
}

// ── config ───────────────────────────────────────────────────────────────────

func runConfig(args []string) error {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" {
		fmt.Println(ui.Bold("postq config") + " — inspect CLI configuration")
		fmt.Println()
		fmt.Println(ui.Bold("SUBCOMMANDS"))
		fmt.Println("  path    Print path to config.json")
		return nil
	}
	switch args[0] {
	case "path":
		p, err := config.Path()
		if err != nil {
			return err
		}
		fmt.Println(p)
		return nil
	default:
		return fmt.Errorf("unknown config subcommand: %s", args[0])
	}
}

// ── scan ─────────────────────────────────────────────────────────────────────

func runScan(args []string, build BuildInfo) error {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" {
		printScanHelp()
		return nil
	}
	switch args[0] {
	case "url":
		return runScanURL(args[1:], build)
	case "list":
		return runScanList(args[1:], build)
	case "cloud":
		return runScanCloud(args[1:], build)
	case "code":
		return runScanCode(args[1:], build)
	case "github", "k8s", "kubernetes", "bulk", "iac", "deps":
		return fmt.Errorf("scan %s: not implemented yet (coming soon)", args[0])
	default:
		printScanHelp()
		return fmt.Errorf("unknown scan target: %s", args[0])
	}
}

func printScanHelp() {
	fmt.Println(ui.Bold("postq scan") + " — run quantum-risk scans")
	fmt.Println()
	fmt.Println(ui.Bold("SUBCOMMANDS"))
	fmt.Println("  " + ui.Cyan("url") + "        TLS handshake + cert quantum-risk scan")
	fmt.Println("  " + ui.Cyan("cloud aws") + "  Inventory AWS KMS keys (server-side via PostQ API)")
	fmt.Println("  " + ui.Cyan("cloud azure") + "  Inventory Azure Key Vault keys (server-side via PostQ API)")
	fmt.Println("  " + ui.Cyan("code") + "       " + ui.Yellow("(beta)") + " Static crypto-misuse scan on a local repo")
	fmt.Println("  " + ui.Cyan("list") + "       Show recent scans uploaded to your org")
	fmt.Println("  " + ui.Dim("iac        Terraform / Bicep / Helm crypto-config scan (soon)"))
	fmt.Println("  " + ui.Dim("deps       Lockfile + manifest crypto-library audit (soon)"))
	fmt.Println("  " + ui.Dim("github     Repo-wide static analysis (soon)"))
	fmt.Println("  " + ui.Dim("k8s        In-cluster TLS secrets / ingress / mTLS scan (use postq-agent helm chart)"))
	fmt.Println()
	fmt.Println(ui.Bold("EXAMPLES"))
	fmt.Println("  postq scan url example.com")
	fmt.Println("  postq scan url a.com b.com c.com --concurrency 5")
	fmt.Println("  postq scan url example.com --no-upload --json")
	fmt.Println("  postq scan cloud aws --account 123456789012 --role-arn arn:aws:iam::123456789012:role/PostQScanner")
	fmt.Println("  postq scan list --limit 10")
}

func runScanURL(args []string, build BuildInfo) error {
	fs := flag.NewFlagSet("scan url", flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprintln(fs.Output(), `Usage: postq scan url <host>... [flags]

Performs a TLS handshake against each host (default port 443) and reports
quantum-vulnerable cipher suites, public key algorithms, and certificate
signatures.

By default the scan runs SERVER-SIDE on api.postq.dev (requires an API
key) so every CLI gets the same scanner, HNDL scoring, and PQ probe as
the dashboard. Pass --local to run the scan in-process instead (works
offline, falls back to the legacy CLI scanner with no PQ probe / HNDL).

Results are uploaded to PostQ unless --no-upload is set (--no-upload
also implies --local).

Exits with code 2 if any scan finds Critical or High risk (useful for CI).`)
		fs.PrintDefaults()
	}
	apiKey := fs.String("api-key", "", "Override saved API key")
	endpoint := fs.String("api-endpoint", "", "Override saved API endpoint")
	noUpload := fs.Bool("no-upload", false, "Don't POST results to PostQ (implies --local)")
	local := fs.Bool("local", false, "Run the TLS scan locally instead of server-side")
	asJSON := fs.Bool("json", false, "Machine-readable JSON output")
	insecure := fs.Bool("insecure", false, "Skip TLS certificate verification (local mode only)")
	timeout := fs.Duration("timeout", 10*time.Second, "Per-host TLS timeout")
	concurrency := fs.Int("concurrency", 4, "Number of hosts to scan in parallel")
	targetList := fs.String("target-list", "", "Read additional hosts from a file (one per line, # for comments)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	targets := fs.Args()
	if *targetList != "" {
		extra, err := readTargetList(*targetList)
		if err != nil {
			return fmt.Errorf("--target-list: %w", err)
		}
		targets = append(targets, extra...)
	}
	if len(targets) == 0 {
		fs.Usage()
		return fmt.Errorf("at least one host is required (positional or via --target-list)")
	}

	cfg, err := config.Resolve(*endpoint, *apiKey)
	if err != nil {
		return err
	}

	host, _ := os.Hostname()
	agent := report.Agent{
		Name:     "postq-cli",
		Version:  build.Version,
		Hostname: host,
		OS:       runtime.GOOS,
	}

	// --no-upload forces local-only (nothing to talk to the API for).
	if *noUpload {
		*local = true
	}

	// Server-side mode requires an API key.
	if !*local && cfg.APIKey == "" {
		fmt.Fprintln(os.Stderr, ui.Yellow("warning:")+" no API key configured — falling back to --local (run `postq auth login --api-key …` to use the server-side scanner)")
		*local = true
		*noUpload = true
	}

	var client *apiclient.Client
	if cfg.APIKey != "" {
		client = apiclient.New(cfg.APIEndpoint, cfg.APIKey, build.userAgent())
	}

	out := make([]urlScanOutcome, len(targets))
	sem := make(chan struct{}, max(1, *concurrency))
	var wg sync.WaitGroup

	for i, t := range targets {
		i, t := i, t
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()

			if *local {
				out[i] = runLocalURLScan(t, agent, client, *noUpload, *insecure, *timeout)
				return
			}
			out[i] = runRemoteURLScan(t, client, agent, *insecure, *timeout)
		}()
	}
	wg.Wait()

	if *asJSON {
		payload := make([]map[string]any, 0, len(out))
		for _, oc := range out {
			item := map[string]any{"target": oc.Target}
			if oc.Err != nil {
				item["error"] = oc.Err.Error()
			} else {
				item["riskScore"] = oc.RiskScore
				item["riskLevel"] = oc.RiskLevel
				item["findings"] = oc.Findings
				item["metadata"] = oc.Metadata
				item["portalUrl"] = oc.PortalURL
				item["durationMs"] = oc.DurationMS
				item["mode"] = oc.Mode
			}
			payload = append(payload, item)
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(payload); err != nil {
			return err
		}
	} else {
		for _, oc := range out {
			if oc.Err != nil {
				fmt.Printf("\n%s %s: %s\n", ui.Red("✗"), ui.Bold(oc.Target), oc.Err)
				continue
			}
			printURLOutcome(oc)
		}
	}

	worst := report.RiskSafe
	for _, oc := range out {
		if oc.Err != nil {
			continue
		}
		if rank(oc.RiskLevel) > rank(worst) {
			worst = oc.RiskLevel
		}
	}
	if worst == report.RiskCritical || worst == report.RiskHigh {
		exitOrReturn(2)
	}
	return nil
}

// urlScanOutcome is the unified result row used by `scan url` regardless of
// whether the scan ran locally (scanurl.Scan) or server-side (POST /v1/scans/url).
type urlScanOutcome struct {
	Target     string
	Mode       string // "local" | "live"
	RiskScore  int
	RiskLevel  report.RiskLevel
	Findings   []report.Finding
	Metadata   map[string]string
	DurationMS int64
	PortalURL  string
	Err        error
}

// runLocalURLScan keeps the legacy in-process scanner for offline / no-key use.
func runLocalURLScan(target string, agent report.Agent, client *apiclient.Client, noUpload, insecure bool, timeout time.Duration) urlScanOutcome {
	res, err := scanurl.Scan(target, scanurl.Options{
		Timeout:            timeout,
		InsecureSkipVerify: insecure,
	})
	if err != nil {
		return urlScanOutcome{Target: target, Mode: "local", Err: err}
	}
	oc := urlScanOutcome{
		Target:     target,
		Mode:       "local",
		RiskScore:  res.RiskScore,
		RiskLevel:  res.RiskLevel,
		Findings:   res.Findings,
		Metadata:   res.Metadata,
		DurationMS: res.DurationMS,
	}
	if !noUpload && client != nil {
		sub := &report.Submission{
			Type:      "url",
			Target:    target,
			Source:    "cli",
			RiskScore: res.RiskScore,
			RiskLevel: res.RiskLevel,
			Findings:  res.Findings,
			Metadata:  res.Metadata,
			Agent:     agent,
		}
		resp, err := client.Submit(context.Background(), sub)
		if err != nil {
			oc.Err = fmt.Errorf("upload: %w", err)
		} else {
			oc.PortalURL = resp.Data.URL
		}
	}
	return oc
}

// runRemoteURLScan asks the API to perform the scan server-side via POST /v1/scans/url.
func runRemoteURLScan(target string, client *apiclient.Client, agent report.Agent, insecure bool, timeout time.Duration) urlScanOutcome {
	_ = agent // server stamps its own agent metadata
	resp, err := client.ScanURL(context.Background(), &apiclient.URLScanRequest{
		Target:             target,
		InsecureSkipVerify: insecure,
		TimeoutMS:          int(timeout / time.Millisecond),
	})
	if err != nil {
		return urlScanOutcome{Target: target, Mode: "live", Err: err}
	}
	findings := make([]report.Finding, 0, len(resp.Data.Findings))
	for _, f := range resp.Data.Findings {
		findings = append(findings, report.Finding{
			Severity:    report.Severity(f.Severity),
			Title:       f.Title,
			Description: f.Description,
			Location:    f.Location,
			Algorithm:   f.Algorithm,
			Remediation: f.Remediation,
			Vulnerable:  f.Vulnerable,
		})
	}
	return urlScanOutcome{
		Target:     resp.Data.Target,
		Mode:       resp.Data.Mode,
		RiskScore:  resp.Data.RiskScore,
		RiskLevel:  report.RiskLevel(resp.Data.RiskLevel),
		Findings:   findings,
		Metadata:   resp.Data.Metadata,
		DurationMS: resp.Data.ScanDurationMS,
		PortalURL:  resp.Data.URL,
	}
}

func rank(rl report.RiskLevel) int {
	switch rl {
	case report.RiskCritical:
		return 4
	case report.RiskHigh:
		return 3
	case report.RiskMedium:
		return 2
	case report.RiskLow:
		return 1
	}
	return 0
}

func printURLOutcome(oc urlScanOutcome) {
	fmt.Println()
	modeBadge := ""
	if oc.Mode == "local" {
		modeBadge = " " + ui.Dim("[local]")
	} else if oc.Mode != "" && oc.Mode != "live" {
		modeBadge = " " + ui.Dim("["+oc.Mode+"]")
	}
	fmt.Println(ui.Bold("PostQ scan") + " — " + ui.Cyan(oc.Target) + modeBadge)
	fmt.Printf("Risk score:   %d/100  (%s)\n", oc.RiskScore, ui.RiskBadge(oc.RiskLevel))
	fmt.Printf("Findings:     %d\n", len(oc.Findings))
	fmt.Println()

	for _, k := range sortedKeys(oc.Metadata) {
		fmt.Printf("  %s %s\n", ui.Dim(pad(k+":", 22)), oc.Metadata[k])
	}
	if len(oc.Metadata) > 0 {
		fmt.Println()
	}

	for _, f := range oc.Findings {
		fmt.Printf("%s %s\n", ui.SeverityBadge(f.Severity), ui.Bold(f.Title))
		if f.Description != "" {
			fmt.Printf("    %s\n", f.Description)
		}
		if f.Algorithm != "" {
			fmt.Printf("    %s %s\n", ui.Dim("algo:"), f.Algorithm)
		}
		if f.Remediation != "" {
			fmt.Printf("    %s %s\n", ui.Dim("fix: "), f.Remediation)
		}
		fmt.Println()
	}

	if oc.DurationMS > 0 {
		fmt.Printf("%s %dms\n", ui.Dim("Took"), oc.DurationMS)
	}
	if oc.PortalURL != "" {
		fmt.Printf("%s %s\n", ui.Dim("View:"), ui.Blue(oc.PortalURL))
	}
}

func runScanList(args []string, build BuildInfo) error {
	fs := flag.NewFlagSet("scan list", flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprintln(fs.Output(), "Usage: postq scan list [--limit N] [--json]")
		fs.PrintDefaults()
	}
	apiKey := fs.String("api-key", "", "Override saved API key")
	endpoint := fs.String("api-endpoint", "", "Override saved API endpoint")
	limit := fs.Int("limit", 10, "Maximum scans to return")
	asJSON := fs.Bool("json", false, "Machine-readable JSON output")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, err := config.Resolve(*endpoint, *apiKey)
	if err != nil {
		return err
	}
	if cfg.APIKey == "" {
		return fmt.Errorf("not authenticated — run `postq auth login --api-key …`")
	}

	cl := apiclient.New(cfg.APIEndpoint, cfg.APIKey, build.userAgent())
	resp, err := cl.List(context.Background(), *limit)
	if err != nil {
		return err
	}

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(resp.Data)
	}

	if len(resp.Data) == 0 {
		fmt.Println(ui.Dim("No scans yet. Run `postq scan url <host>` to create one."))
		return nil
	}

	fmt.Printf("%s  %s  %s  %s  %s  %s\n",
		ui.Dim(pad("WHEN", 16)),
		ui.Dim(pad("TYPE", 6)),
		ui.Dim(pad("RISK", 8)),
		ui.Dim(pad("SCORE", 5)),
		ui.Dim(pad("FINDINGS", 8)),
		ui.Dim("TARGET"),
	)
	for _, s := range resp.Data {
		when := s.CreatedAt
		if t, err := time.Parse(time.RFC3339, s.CreatedAt); err == nil {
			when = t.Local().Format("2006-01-02 15:04")
		}
		fmt.Printf("%s  %s  %s  %s  %s  %s\n",
			pad(when, 16),
			pad(s.Type, 6),
			pad(s.RiskLevel, 8),
			pad(fmt.Sprintf("%d", s.RiskScore), 5),
			pad(fmt.Sprintf("%d", s.FindingsCount), 8),
			s.Target,
		)
	}
	return nil
}

// ── small helpers ────────────────────────────────────────────────────────────

func pad(s string, n int) string {
	for len(s) < n {
		s += " "
	}
	return s
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	for i := 1; i < len(keys); i++ {
		for j := i; j > 0 && keys[j-1] > keys[j]; j-- {
			keys[j-1], keys[j] = keys[j], keys[j-1]
		}
	}
	return keys
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// ── scan cloud ───────────────────────────────────────────────────────────────

func runScanCloud(args []string, build BuildInfo) error {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" {
		printScanCloudHelp()
		return nil
	}
	switch args[0] {
	case "aws":
		return runScanCloudAWS(args[1:], build)
	case "azure":
		return runScanCloudAzure(args[1:], build)
	case "kubernetes", "k8s":
		return fmt.Errorf("scan cloud %s: not implemented yet (use the in-cluster postq-agent helm chart)", args[0])
	default:
		printScanCloudHelp()
		return fmt.Errorf("unknown cloud provider: %s", args[0])
	}
}

func printScanCloudHelp() {
	fmt.Println(ui.Bold("postq scan cloud") + " — server-side cloud crypto inventory")
	fmt.Println()
	fmt.Println(ui.Bold("PROVIDERS"))
	fmt.Println("  " + ui.Cyan("aws") + "      Inventory KMS keys across regions")
	fmt.Println("  " + ui.Cyan("azure") + "    Inventory Key Vault keys across a subscription")
	fmt.Println("  " + ui.Dim("k8s      In-cluster scan (use the postq-agent Helm chart)"))
	fmt.Println()
	fmt.Println(ui.Dim("These scans run server-side via the PostQ API, so the CLI never"))
	fmt.Println(ui.Dim("touches your AWS credentials directly."))
	fmt.Println()
	fmt.Println(ui.Bold("EXAMPLES"))
	fmt.Println("  postq scan cloud aws --account 123456789012")
	fmt.Println("  postq scan cloud aws --account 123456789012 --regions us-east-1,us-west-2")
	fmt.Println("  postq scan cloud aws --account 123456789012 \\")
	fmt.Println("      --role-arn arn:aws:iam::123456789012:role/PostQScanner --external-id postq")
	fmt.Println("  postq scan cloud azure --subscription 00000000-0000-0000-0000-000000000000 \\")
	fmt.Println("      --tenant <tenant-id> --client-id <sp-client-id> --client-secret <sp-secret>")
}

func runScanCloudAWS(args []string, build BuildInfo) error {
	fs := flag.NewFlagSet("scan cloud aws", flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprintln(fs.Output(), `Usage: postq scan cloud aws --account <id> [flags]

Triggers a server-side AWS KMS scan via the PostQ API. The API uses either
the role you assume into (--role-arn) or whatever credentials the API host
already has, so your local AWS credentials never leave this machine.

Exits with code 2 if the scan finds Critical or High risk (CI gate).`)
		fs.PrintDefaults()
	}
	apiKey := fs.String("api-key", "", "Override saved API key")
	endpoint := fs.String("api-endpoint", "", "Override saved API endpoint")
	account := fs.String("account", "", "AWS account id (or any label for the scan)")
	regions := fs.String("regions", "", "Comma-separated list of regions to scan (default: top 9 regions)")
	roleArn := fs.String("role-arn", "", "IAM role for the API to assume into your account")
	externalID := fs.String("external-id", "", "External ID for the AssumeRole trust policy")
	asJSON := fs.Bool("json", false, "Machine-readable JSON output")
	if err := fs.Parse(args); err != nil {
		return err
	}

	target := strings.TrimSpace(*account)
	if target == "" {
		fs.Usage()
		return fmt.Errorf("--account is required")
	}

	cfg, err := config.Resolve(*endpoint, *apiKey)
	if err != nil {
		return err
	}
	if cfg.APIKey == "" {
		return fmt.Errorf("not authenticated — run `postq auth login --api-key …`")
	}

	req := &apiclient.CloudScanRequest{
		Provider: "aws",
		Target:   target,
	}
	if *roleArn != "" || *externalID != "" || *regions != "" {
		req.AWS = &apiclient.CloudScanAWSOptions{
			RoleArn:    *roleArn,
			ExternalID: *externalID,
			Regions:    splitCSV(*regions),
		}
	}

	cl := apiclient.New(cfg.APIEndpoint, cfg.APIKey, build.userAgent())
	fmt.Fprintf(os.Stderr, "%s scanning aws account %s ...\n", ui.Dim("→"), target)
	resp, err := cl.ScanCloud(context.Background(), req)
	if err != nil {
		return err
	}

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(resp.Data)
	}

	fmt.Println()
	fmt.Println(ui.Bold("PostQ cloud scan") + " — " + ui.Cyan("aws/"+resp.Data.Target))
	fmt.Printf("Mode:         %s\n", resp.Data.Mode)
	fmt.Printf("Risk score:   %d/100  (%s)\n", resp.Data.RiskScore, ui.RiskBadge(report.RiskLevel(resp.Data.RiskLevel)))
	fmt.Printf("Resources:    %d\n", resp.Data.ResourcesCount)
	fmt.Printf("  Vulnerable: %d\n", resp.Data.Summary.QuantumVulnerable)
	fmt.Printf("  PQ-ready:   %d\n", resp.Data.Summary.PqReady)
	fmt.Printf("Findings:     %d\n", resp.Data.FindingsCount)
	fmt.Printf("%s %s\n", ui.Dim("View:"), ui.Blue(resp.Data.URL))

	switch resp.Data.RiskLevel {
	case "Critical", "High":
		exitOrReturn(2)
	}
	return nil
}

func runScanCloudAzure(args []string, build BuildInfo) error {
	fs := flag.NewFlagSet("scan cloud azure", flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprintln(fs.Output(), `Usage: postq scan cloud azure --subscription <id> [flags]

Triggers a server-side Azure Key Vault scan via the PostQ API. Authenticate
either with a service principal (--tenant + --client-id + --client-secret)
or rely on whatever credentials the API host already has (Managed Identity,
azd login, AZURE_* env vars).

Exits with code 2 if the scan finds Critical or High risk (CI gate).`)
		fs.PrintDefaults()
	}
	apiKey := fs.String("api-key", "", "Override saved API key")
	endpoint := fs.String("api-endpoint", "", "Override saved API endpoint")
	subscription := fs.String("subscription", "", "Azure subscription id")
	tenant := fs.String("tenant", "", "Azure AD tenant id (service principal auth)")
	clientID := fs.String("client-id", "", "Service-principal client/app id")
	clientSecret := fs.String("client-secret", "", "Service-principal client secret")
	vaults := fs.String("vaults", "", "Comma-separated list of vault names to scan (default: all)")
	asJSON := fs.Bool("json", false, "Machine-readable JSON output")
	if err := fs.Parse(args); err != nil {
		return err
	}

	target := strings.TrimSpace(*subscription)
	if target == "" {
		fs.Usage()
		return fmt.Errorf("--subscription is required")
	}

	cfg, err := config.Resolve(*endpoint, *apiKey)
	if err != nil {
		return err
	}
	if cfg.APIKey == "" {
		return fmt.Errorf("not authenticated — run `postq auth login --api-key …`")
	}

	req := &apiclient.CloudScanRequest{
		Provider: "azure",
		Target:   target,
		Azure: &apiclient.CloudScanAzureOptions{
			SubscriptionID: target,
			TenantID:       *tenant,
			ClientID:       *clientID,
			ClientSecret:   *clientSecret,
			VaultNames:     splitCSV(*vaults),
		},
	}

	cl := apiclient.New(cfg.APIEndpoint, cfg.APIKey, build.userAgent())
	fmt.Fprintf(os.Stderr, "%s scanning azure subscription %s ...\n", ui.Dim("→"), target)
	resp, err := cl.ScanCloud(context.Background(), req)
	if err != nil {
		return err
	}

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(resp.Data)
	}

	fmt.Println()
	fmt.Println(ui.Bold("PostQ cloud scan") + " — " + ui.Cyan("azure/"+resp.Data.Target))
	fmt.Printf("Mode:         %s\n", resp.Data.Mode)
	fmt.Printf("Risk score:   %d/100  (%s)\n", resp.Data.RiskScore, ui.RiskBadge(report.RiskLevel(resp.Data.RiskLevel)))
	fmt.Printf("Resources:    %d\n", resp.Data.ResourcesCount)
	fmt.Printf("  Vulnerable: %d\n", resp.Data.Summary.QuantumVulnerable)
	fmt.Printf("  PQ-ready:   %d\n", resp.Data.Summary.PqReady)
	fmt.Printf("Findings:     %d\n", resp.Data.FindingsCount)
	fmt.Printf("%s %s\n", ui.Dim("View:"), ui.Blue(resp.Data.URL))

	switch resp.Data.RiskLevel {
	case "Critical", "High":
		exitOrReturn(2)
	}
	return nil
}

func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if v := strings.TrimSpace(p); v != "" {
			out = append(out, v)
		}
	}
	return out
}

// ── scan code ────────────────────────────────────────────────────────────────

func runScanCode(args []string, build BuildInfo) error {
	fs := flag.NewFlagSet("scan code", flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprintln(fs.Output(), `Usage: postq scan code <path> [flags]

Walks the given directory and runs PostQ's crypto-misuse rule pack
(weak RNG, MD5/SHA-1 in signing paths, JWT alg:none, AES-ECB,
hardcoded private keys, classical-only signing, ...) over source files.

This is a beta detector pack — high-signal, not exhaustive.`)
		fs.PrintDefaults()
	}
	asJSON := fs.Bool("json", false, "Machine-readable JSON output")
	maxBytes := fs.Int64("max-file-size", 1<<20, "Skip files larger than this many bytes")
	severity := fs.String("min-severity", "low", "Minimum severity to print (info|low|medium|high|critical)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	rest := fs.Args()
	if len(rest) == 0 {
		fs.Usage()
		return fmt.Errorf("path is required (try `postq scan code .`)")
	}
	root := rest[0]

	res, err := scancode.Run(root, scancode.Options{MaxFileBytes: *maxBytes})
	if err != nil {
		return err
	}

	minSev := sevRank(*severity)
	filtered := make([]scancode.Finding, 0, len(res.Findings))
	for _, f := range res.Findings {
		if sevRank(string(f.Severity)) >= minSev {
			filtered = append(filtered, f)
		}
	}

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(map[string]any{
			"root":         res.Root,
			"filesScanned": res.FilesScanned,
			"riskScore":    res.RiskScore,
			"riskLevel":    res.RiskLevel,
			"findings":     filtered,
			"agent":        report.Agent{Name: "postq-cli", Version: build.Version, OS: runtime.GOOS},
		})
	}

	fmt.Println()
	fmt.Println(ui.Bold("PostQ code scan") + " — " + ui.Cyan(res.Root))
	fmt.Printf("Files scanned: %d\n", res.FilesScanned)
	fmt.Printf("Risk score:    %d/100  (%s)\n", res.RiskScore, ui.RiskBadge(res.RiskLevel))
	fmt.Printf("Findings:      %d", len(filtered))
	if len(filtered) != len(res.Findings) {
		fmt.Printf("  %s", ui.Dim(fmt.Sprintf("(%d hidden by --min-severity)", len(res.Findings)-len(filtered))))
	}
	fmt.Println()
	fmt.Println()

	if len(filtered) == 0 {
		fmt.Println(ui.Green("  ✓ ") + "no detections in scope")
		fmt.Println()
		return nil
	}

	for _, f := range filtered {
		fmt.Printf("%s %s %s\n",
			ui.SeverityBadge(f.Severity),
			ui.Bold(f.Title),
			ui.Dim("· "+f.RuleID),
		)
		fmt.Printf("    %s\n", f.Description)
		fmt.Printf("    %s %s\n", ui.Dim("at:  "), ui.Cyan(f.File)+ui.Dim(":")+fmt.Sprint(f.Line))
		if f.Snippet != "" {
			fmt.Printf("    %s %s\n", ui.Dim("code:"), trimSnippet(f.Snippet))
		}
		if f.DiscoveredBy != "" {
			fmt.Printf("    %s %s\n", ui.Dim("via: "), ui.Purple(f.DiscoveredBy))
		}
		fmt.Printf("    %s %s\n\n", ui.Dim("fix: "), f.Remediation)
	}

	if res.RiskLevel == report.RiskCritical || res.RiskLevel == report.RiskHigh {
		exitOrReturn(2)
	}
	return nil
}

func trimSnippet(s string) string {
	if len(s) > 120 {
		return s[:117] + "..."
	}
	return s
}

func sevRank(s string) int {
	switch strings.ToLower(s) {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	case "info":
		return 0
	}
	return 1
}

// readTargetList reads a file of hosts (one per line). Blank lines and
// lines starting with '#' are ignored.
func readTargetList(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var out []string
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return out, nil
}
