// Package tui implements the interactive PostQ shell launched when the user
// runs `postq` with no arguments.
package tui

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/postqdev/postq-cli/internal/apiclient"
	"github.com/postqdev/postq-cli/internal/banner"
	"github.com/postqdev/postq-cli/internal/config"
	"github.com/postqdev/postq-cli/internal/ui"
)

// Build is the build info plumbed in from main.
type Build struct {
	Version string
	Commit  string
	Date    string
}

// Dispatch is the bridge back into the regular subcommand router so the TUI
// can re-use everything (`scan url`, `scan cloud aws`, etc.) without
// duplicating implementation.
type Dispatch func(args []string) error

// Run starts the interactive shell. Returns nil on clean exit.
func Run(in io.Reader, out io.Writer, build Build, dispatch Dispatch) error {
	if in == nil {
		in = os.Stdin
	}
	if out == nil {
		out = os.Stdout
	}

	clearScreen(out)
	banner.Print(out, build.Version, true)

	cfg, _ := config.Load()
	scanner := bufio.NewScanner(in)
	scanner.Buffer(make([]byte, 0, 1024), 1024*1024)

	if cfg.APIKey == "" {
		if !runOnboarding(out, scanner) {
			fmt.Fprintln(out, ui.Dim("  (skipped — local scans still work; uploads will be off)"))
			fmt.Fprintln(out)
		} else {
			cfg, _ = config.Load()
		}
	} else {
		printStatusLine(out, cfg, build)
	}

	if cfg.APIKey != "" {
		showRecentPeek(out, cfg, build)
	}

	for {
		fmt.Fprint(out, prompt())
		if !scanner.Scan() {
			fmt.Fprintln(out)
			return nil
		}
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "#") {
			continue
		}

		switch line {
		case "exit", "quit", ":q", "q":
			fmt.Fprintln(out, ui.Dim("  goodbye."))
			return nil
		case "clear", "cls":
			clearScreen(out)
			banner.Print(out, build.Version, false)
			continue
		case "help", "?":
			printHelp(out)
			continue
		case "status", "whoami":
			cfg, _ = config.Load()
			printStatusLine(out, cfg, build)
			continue
		case "logout":
			if err := config.Delete(); err != nil {
				fmt.Fprintln(out, ui.Red("  ✗ ")+err.Error())
			} else {
				fmt.Fprintln(out, ui.Green("  ✓ ")+"credentials removed")
			}
			continue
		case "login":
			runLoginPrompt(out, scanner)
			continue
		case "open dashboard", "dashboard":
			openBrowser("https://app.postq.dev")
			fmt.Fprintln(out, ui.Dim("  → opening https://app.postq.dev"))
			continue
		}

		args := tokenize(line)
		if len(args) == 0 {
			continue
		}
		if args[0] == "shell" || args[0] == "interactive" {
			fmt.Fprintln(out, ui.Dim("  (already in interactive shell)"))
			continue
		}

		stop := startSpinner(out, "running "+args[0])
		err := dispatch(args)
		stop()
		if err != nil {
			fmt.Fprintln(out, ui.Red("  ✗ ")+err.Error())
		}
	}
}

func prompt() string {
	return "\n" + ui.Dim("  postq") + ui.Cyan("  › ")
}

func printStatusLine(out io.Writer, cfg *config.Config, build Build) {
	endpoint := cfg.APIEndpoint
	if endpoint == "" {
		endpoint = config.DefaultEndpoint
	}
	keyLine := ui.Dim("not authenticated") + " · " + ui.Yellow("uploads disabled")
	if cfg.APIKey != "" {
		keyLine = ui.Green("● ") + ui.Bold("authenticated") + ui.Dim(" as "+config.MaskKey(cfg.APIKey))
	}
	fmt.Fprintln(out, "  "+keyLine)
	fmt.Fprintln(out, "  "+ui.Dim("endpoint  ")+endpoint)
	fmt.Fprintln(out, "  "+ui.Dim("cli       v")+build.Version+ui.Dim("  ·  ")+runtime.GOOS+"/"+runtime.GOARCH)
	fmt.Fprintln(out)
}

func printHelp(out io.Writer) {
	fmt.Fprintln(out)
	fmt.Fprintln(out, "  "+ui.Bold("PostQ shell")+ui.Dim(" — type a command, hit enter."))
	fmt.Fprintln(out)
	section(out, "scan", []row{
		{"scan url <host> [host ...]", "TLS handshake + cert quantum-risk scan"},
		{"scan cloud aws --account ID", "server-side AWS KMS inventory"},
		{"scan code <path>", ui.Cyan("(beta)") + " static crypto-misuse scan on a local repo"},
		{"scan list [--limit N]", "recent scans uploaded to your org"},
	})
	section(out, "auth", []row{
		{"login", "paste / enter an API key (pq_live_…)"},
		{"logout", "remove saved credentials"},
		{"whoami / status", "show endpoint + masked key"},
	})
	section(out, "shell", []row{
		{"help / ?", "show this help"},
		{"clear", "redraw the banner"},
		{"dashboard", "open https://app.postq.dev in your browser"},
		{"exit / quit", "leave the shell"},
	})
	fmt.Fprintln(out, "  "+ui.Dim("any flag from the non-interactive CLI works here too,"))
	fmt.Fprintln(out, "  "+ui.Dim("e.g. ")+ui.Cyan("scan url example.com --json --no-upload"))
}

type row struct{ cmd, desc string }

func section(out io.Writer, title string, rows []row) {
	fmt.Fprintln(out, "  "+ui.Purple(strings.ToUpper(title)))
	for _, r := range rows {
		pad := 32 - visibleLen(r.cmd)
		if pad < 1 {
			pad = 1
		}
		fmt.Fprintln(out, "    "+ui.Cyan(r.cmd)+strings.Repeat(" ", pad)+ui.Dim(r.desc))
	}
	fmt.Fprintln(out)
}

func visibleLen(s string) int {
	n, inEsc := 0, false
	for _, r := range s {
		if inEsc {
			if r == 'm' {
				inEsc = false
			}
			continue
		}
		if r == 0x1b {
			inEsc = true
			continue
		}
		n++
	}
	return n
}

func runOnboarding(out io.Writer, scanner *bufio.Scanner) bool {
	fmt.Fprintln(out, ui.Purple("  ┌──────────────────────────────────────────────────────────────┐"))
	fmt.Fprintln(out, ui.Purple("  │ ")+ui.Bold("Welcome to PostQ")+strings.Repeat(" ", 46)+ui.Purple("│"))
	fmt.Fprintln(out, ui.Purple("  │")+strings.Repeat(" ", 62)+ui.Purple("│"))
	fmt.Fprintln(out, ui.Purple("  │ ")+ui.Dim("Connect this CLI to your org so scans land in your")+"           "+ui.Purple("│"))
	fmt.Fprintln(out, ui.Purple("  │ ")+ui.Dim("dashboard. You can skip — local scans still print here.")+"      "+ui.Purple("│"))
	fmt.Fprintln(out, ui.Purple("  │")+strings.Repeat(" ", 62)+ui.Purple("│"))
	fmt.Fprintln(out, ui.Purple("  │ ")+ui.Dim("1. open ")+ui.Cyan("https://app.postq.dev/settings/api-keys")+"            "+ui.Purple("│"))
	fmt.Fprintln(out, ui.Purple("  │ ")+ui.Dim("2. create a key starting with ")+ui.Cyan("pq_live_…")+"                    "+ui.Purple("│"))
	fmt.Fprintln(out, ui.Purple("  │ ")+ui.Dim("3. paste it below")+strings.Repeat(" ", 45)+ui.Purple("│"))
	fmt.Fprintln(out, ui.Purple("  └──────────────────────────────────────────────────────────────┘"))
	fmt.Fprintln(out)
	fmt.Fprint(out, "  open the page in your browser now? "+ui.Dim("[Y/n] "))
	if scanner.Scan() {
		ans := strings.TrimSpace(strings.ToLower(scanner.Text()))
		if ans == "" || ans == "y" || ans == "yes" {
			openBrowser("https://app.postq.dev/settings/api-keys")
			fmt.Fprintln(out, ui.Dim("  → opened in browser"))
		}
	}
	return runLoginPrompt(out, scanner)
}

func runLoginPrompt(out io.Writer, scanner *bufio.Scanner) bool {
	fmt.Fprintln(out)
	fmt.Fprint(out, "  "+ui.Bold("api key")+ui.Dim(" (paste, or blank to skip): "))
	if !scanner.Scan() {
		return false
	}
	key := strings.TrimSpace(scanner.Text())
	if key == "" {
		return false
	}
	if !strings.HasPrefix(key, "pq_live_") && !strings.HasPrefix(key, "pq_test_") {
		fmt.Fprintln(out, ui.Yellow("  ! ")+"that doesn't look like a PostQ key — saving anyway")
	}
	cfg, _ := config.Load()
	cfg.APIKey = key
	if cfg.APIEndpoint == "" {
		cfg.APIEndpoint = config.DefaultEndpoint
	}
	if err := config.Save(cfg); err != nil {
		fmt.Fprintln(out, ui.Red("  ✗ ")+"could not save: "+err.Error())
		return false
	}
	path, _ := config.Path()
	fmt.Fprintln(out, ui.Green("  ✓ ")+"saved to "+ui.Dim(path))
	fmt.Fprintln(out, "    endpoint "+cfg.APIEndpoint)
	fmt.Fprintln(out, "    key      "+config.MaskKey(cfg.APIKey))
	fmt.Fprintln(out)
	return true
}

func showRecentPeek(out io.Writer, cfg *config.Config, build Build) {
	cl := apiclient.New(cfg.APIEndpoint, cfg.APIKey, "postq-cli/"+build.Version)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	resp, err := cl.List(ctx, 3)
	if err != nil || len(resp.Data) == 0 {
		return
	}
	fmt.Fprintln(out, "  "+ui.Dim("recent scans"))
	for _, s := range resp.Data {
		when := s.CreatedAt
		if t, err := time.Parse(time.RFC3339, s.CreatedAt); err == nil {
			when = t.Local().Format("01-02 15:04")
		}
		fmt.Fprintf(out, "    %s  %s  %s\n",
			ui.Dim(when),
			ui.RiskBadgeStr(s.RiskLevel),
			s.Target,
		)
	}
	fmt.Fprintln(out)
}

func startSpinner(out io.Writer, label string) func() {
	if !ui.Enabled() {
		return func() {}
	}
	frames := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		i := 0
		for {
			select {
			case <-stop:
				fmt.Fprint(out, "\r\x1b[2K")
				return
			default:
				fmt.Fprintf(out, "\r  %s %s ", ui.Cyan(frames[i%len(frames)]), ui.Dim(label))
				i++
				time.Sleep(80 * time.Millisecond)
			}
		}
	}()
	return func() {
		close(stop)
		<-done
	}
}

func clearScreen(out io.Writer) {
	if !ui.Enabled() {
		return
	}
	fmt.Fprint(out, "\x1b[2J\x1b[H")
}

func openBrowser(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	_ = cmd.Start()
}

func tokenize(s string) []string {
	var out []string
	var cur strings.Builder
	inQuote := false
	for _, r := range s {
		switch {
		case r == '"':
			inQuote = !inQuote
		case r == ' ' && !inQuote:
			if cur.Len() > 0 {
				out = append(out, cur.String())
				cur.Reset()
			}
		default:
			cur.WriteRune(r)
		}
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}
