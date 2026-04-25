// Package commands wires CLI subcommands together.
package commands

import (
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
	fmt.Println(ui.Bold("PostQ CLI") + " — quantum-risk scanning for TLS, certs, and cloud crypto")
	fmt.Println()
	fmt.Println(ui.Bold("USAGE"))
	fmt.Println("  postq <command> [subcommand] [flags] [args]")
	fmt.Println()
	fmt.Println(ui.Bold("COMMANDS"))
	fmt.Println("  " + ui.Cyan("scan url") + " <host>...     TLS handshake + cert quantum-risk scan")
	fmt.Println("  " + ui.Cyan("scan list") + "              Recent scans uploaded to your org")
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
	fmt.Println("  postq auth login --api-key pq_live_…")
	fmt.Println("  postq scan url example.com")
	fmt.Println("  postq scan url example.com api.example.com --json")
	fmt.Println("  postq scan url example.com --no-upload")
	fmt.Println("  postq scan list --limit 20")
	fmt.Println()
	fmt.Println(ui.Dim("Generate an API key at https://app.postq.dev/settings/api-keys"))
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
		return fmt.Errorf("--api-key is required (generate one at https://app.postq.dev/settings/api-keys)")
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
	case "github", "azure", "k8s", "kubernetes", "bulk", "iac", "deps":
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
	fmt.Println("  " + ui.Cyan("code") + "       " + ui.Yellow("(beta)") + " Static crypto-misuse scan on a local repo")
	fmt.Println("  " + ui.Cyan("list") + "       Show recent scans uploaded to your org")
	fmt.Println("  " + ui.Dim("iac        Terraform / Bicep / Helm crypto-config scan (soon)"))
	fmt.Println("  " + ui.Dim("deps       Lockfile + manifest crypto-library audit (soon)"))
	fmt.Println("  " + ui.Dim("github     Repo-wide static analysis (soon)"))
	fmt.Println("  " + ui.Dim("cloud azure   Key Vault / App Service / Storage scan (soon)"))
	fmt.Println("  " + ui.Dim("k8s        In-cluster TLS secrets / ingress / mTLS scan (soon)"))
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
signatures. Results are uploaded to PostQ unless --no-upload is set.

Exits with code 2 if any scan finds Critical or High risk (useful for CI).`)
		fs.PrintDefaults()
	}
	apiKey := fs.String("api-key", "", "Override saved API key")
	endpoint := fs.String("api-endpoint", "", "Override saved API endpoint")
	noUpload := fs.Bool("no-upload", false, "Don't POST results to PostQ")
	asJSON := fs.Bool("json", false, "Machine-readable JSON output")
	insecure := fs.Bool("insecure", false, "Skip TLS certificate verification")
	timeout := fs.Duration("timeout", 10*time.Second, "Per-host TLS timeout")
	concurrency := fs.Int("concurrency", 4, "Number of hosts to scan in parallel")
	if err := fs.Parse(args); err != nil {
		return err
	}
	targets := fs.Args()
	if len(targets) == 0 {
		fs.Usage()
		return fmt.Errorf("at least one host is required")
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

	var client *apiclient.Client
	if !*noUpload && cfg.APIKey != "" {
		client = apiclient.New(cfg.APIEndpoint, cfg.APIKey, build.userAgent())
	}
	if !*noUpload && cfg.APIKey == "" {
		fmt.Fprintln(os.Stderr, ui.Yellow("warning:")+" no API key configured — skipping upload (run `postq auth login --api-key …`)")
	}

	type scanOutcome struct {
		Target    string
		Sub       *report.Submission
		Result    *scanurl.Result
		PortalURL string
		Err       error
	}

	out := make([]scanOutcome, len(targets))
	sem := make(chan struct{}, max(1, *concurrency))
	var wg sync.WaitGroup

	for i, t := range targets {
		i, t := i, t
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()

			res, err := scanurl.Scan(t, scanurl.Options{
				Timeout:            *timeout,
				InsecureSkipVerify: *insecure,
			})
			if err != nil {
				out[i] = scanOutcome{Target: t, Err: err}
				return
			}
			sub := &report.Submission{
				Type:      "url",
				Target:    t,
				Source:    "cli",
				RiskScore: res.RiskScore,
				RiskLevel: res.RiskLevel,
				Findings:  res.Findings,
				Metadata:  res.Metadata,
				Agent:     agent,
			}
			oc := scanOutcome{Target: t, Sub: sub, Result: res}
			if client != nil {
				resp, err := client.Submit(context.Background(), sub)
				if err != nil {
					oc.Err = fmt.Errorf("upload: %w", err)
				} else {
					oc.PortalURL = resp.Data.URL
				}
			}
			out[i] = oc
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
				item["riskScore"] = oc.Sub.RiskScore
				item["riskLevel"] = oc.Sub.RiskLevel
				item["findings"] = oc.Sub.Findings
				item["metadata"] = oc.Sub.Metadata
				item["portalUrl"] = oc.PortalURL
				item["durationMs"] = oc.Result.DurationMS
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
			printHumanReport(oc.Sub, oc.Result, oc.PortalURL)
		}
	}

	worst := report.RiskSafe
	for _, oc := range out {
		if oc.Sub == nil {
			continue
		}
		if rank(oc.Sub.RiskLevel) > rank(worst) {
			worst = oc.Sub.RiskLevel
		}
	}
	if worst == report.RiskCritical || worst == report.RiskHigh {
		exitOrReturn(2)
	}
	return nil
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

func printHumanReport(sub *report.Submission, res *scanurl.Result, portalURL string) {
	fmt.Println()
	fmt.Println(ui.Bold("PostQ scan") + " — " + ui.Cyan(res.Host+":"+res.Port))
	fmt.Printf("Risk score:   %d/100  (%s)\n", sub.RiskScore, ui.RiskBadge(sub.RiskLevel))
	fmt.Printf("Findings:     %d\n", len(sub.Findings))
	fmt.Println()

	for _, k := range sortedKeys(res.Metadata) {
		fmt.Printf("  %s %s\n", ui.Dim(pad(k+":", 22)), res.Metadata[k])
	}
	fmt.Println()

	for _, f := range sub.Findings {
		fmt.Printf("%s %s\n", ui.SeverityBadge(f.Severity), ui.Bold(f.Title))
		fmt.Printf("    %s\n", f.Description)
		if f.Algorithm != "" {
			fmt.Printf("    %s %s\n", ui.Dim("algo:"), f.Algorithm)
		}
		fmt.Printf("    %s %s\n\n", ui.Dim("fix: "), f.Remediation)
	}

	fmt.Printf("%s %dms\n", ui.Dim("Took"), res.DurationMS)
	if portalURL != "" {
		fmt.Printf("%s %s\n", ui.Dim("View:"), ui.Blue(portalURL))
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
	case "azure", "kubernetes", "k8s":
		return fmt.Errorf("scan cloud %s: not implemented yet (coming soon)", args[0])
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
	fmt.Println("  " + ui.Dim("azure    Key Vault scan (soon)"))
	fmt.Println("  " + ui.Dim("k8s      In-cluster scan (soon)"))
	fmt.Println()
	fmt.Println(ui.Dim("These scans run server-side via the PostQ API, so the CLI never"))
	fmt.Println(ui.Dim("touches your AWS credentials directly."))
	fmt.Println()
	fmt.Println(ui.Bold("EXAMPLES"))
	fmt.Println("  postq scan cloud aws --account 123456789012")
	fmt.Println("  postq scan cloud aws --account 123456789012 --regions us-east-1,us-west-2")
	fmt.Println("  postq scan cloud aws --account 123456789012 \\")
	fmt.Println("      --role-arn arn:aws:iam::123456789012:role/PostQScanner --external-id postq")
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
