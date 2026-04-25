// Package tui implements the interactive PostQ shell launched when the user
// runs `postq` with no arguments.
//
// Layout:
//
//	┌─ alt screen buffer ─────────────────────────────┐
//	│                                                  │
//	│   ██████╗  ██████╗   …  PostQ block-letter logo │
//	│                                                  │
//	│   cryptographic posture for whatever Q-Day …    │
//	│   what's your [Mythos]?    ← rotates in place   │
//	│                                                  │
//	│   ──────────────────────────────────────────    │
//	│   ● authenticated as pq_live_…                  │
//	│   ──────────────────────────────────────────    │
//	│                                                  │
//	│   ▸ scan code .             ← prev command      │
//	│     21 findings, 4 critical                     │
//	│     …                                           │
//	│                                                  │
//	│   postq ›                   ← prompt            │
//	└──────────────────────────────────────────────────┘
//
// The screen is fully repainted between commands, so the banner is always
// visible at the top — the previous command's output is replaced when the
// next one runs (Microsoft-Copilot-CLI style "boxed" feel).
package tui

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strings"
	"sync"
	"syscall"
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

// Dispatch is the bridge back into the regular subcommand router.
type Dispatch func(args []string) error

// shell holds mutable shell state across the REPL loop.
type shell struct {
	out       io.Writer
	in        io.Reader
	build     Build
	dispatch  Dispatch
	cfg       *config.Config
	lastCmd   string
	lastOut   string
	statusMsg string

	mu      sync.Mutex // serializes writes to out (rotator + main thread)
	qIdx    int
	qRow    int
	stopRot chan struct{}
	rotDone chan struct{}
}

// Run starts the interactive shell. Returns nil on clean exit.
func Run(in io.Reader, out io.Writer, build Build, dispatch Dispatch) error {
	if in == nil {
		in = os.Stdin
	}
	if out == nil {
		out = os.Stdout
	}

	sh := &shell{
		out:      out,
		in:       in,
		build:    build,
		dispatch: dispatch,
	}
	sh.cfg, _ = config.Load()

	// Onboarding (first-launch with no key): runs INLINE before alt-screen
	// so the user sees & can paste freely without it disappearing.
	if sh.cfg.APIKey == "" {
		runOnboarding(out, bufio.NewScanner(in))
		sh.cfg, _ = config.Load()
	}

	// Background-fetch the recent-scans peek before painting the first frame.
	if sh.cfg.APIKey != "" {
		sh.fetchRecentPeek()
	}

	// Enter alternate screen — preserves the user's scrollback.
	enterAltScreen(out)
	hideCursor(out)
	defer func() {
		showCursor(out)
		leaveAltScreen(out)
	}()

	// Restore terminal cleanly on Ctrl+C / SIGTERM.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sig)
	go func() {
		<-sig
		sh.stopRotator()
		showCursor(out)
		leaveAltScreen(out)
		os.Exit(0)
	}()

	scanner := bufio.NewScanner(in)
	scanner.Buffer(make([]byte, 0, 1024), 1024*1024)

	for {
		sh.repaint()
		sh.startRotator()
		showCursor(out)

		line, ok := readLine(scanner)
		sh.stopRotator()
		hideCursor(out)
		if !ok {
			return nil
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Built-ins.
		switch line {
		case "exit", "quit", ":q":
			return nil
		case "clear", "cls":
			sh.lastCmd, sh.lastOut, sh.statusMsg = "", "", ""
			continue
		case "help", "?":
			sh.lastCmd = line
			sh.lastOut = renderHelp()
			continue
		case "status", "whoami":
			sh.cfg, _ = config.Load()
			sh.lastCmd = line
			sh.lastOut = renderStatus(sh.cfg, build)
			continue
		case "logout":
			if err := config.Delete(); err != nil {
				sh.statusMsg = ui.Red("✗ ") + err.Error()
			} else {
				sh.cfg = &config.Config{APIEndpoint: config.DefaultEndpoint}
				sh.statusMsg = ui.Green("✓ ") + "credentials removed"
			}
			sh.lastCmd, sh.lastOut = "", ""
			continue
		case "login":
			// drop out of alt screen for a clean paste UX
			leaveAltScreen(out)
			showCursor(out)
			runLoginPrompt(out, scanner)
			sh.cfg, _ = config.Load()
			enterAltScreen(out)
			hideCursor(out)
			continue
		case "open dashboard", "dashboard":
			openBrowser("https://app.postq.dev")
			sh.statusMsg = ui.Dim("→ opened https://app.postq.dev in browser")
			continue
		}

		// Anything else: dispatch to the existing subcommand router with
		// stdout captured so we can paint the result inside our body region.
		args := tokenize(line)
		if len(args) == 0 {
			continue
		}
		if args[0] == "shell" || args[0] == "interactive" {
			sh.statusMsg = ui.Dim("(already in interactive shell)")
			continue
		}

		sh.lastCmd = line
		out, err := captureDispatch(sh.dispatch, args)
		sh.lastOut = out
		if err != nil {
			sh.lastOut += "\n" + ui.Red("✗ ") + err.Error()
		}
	}
}

// ── painting ─────────────────────────────────────────────────────────────────

func (s *shell) repaint() {
	s.mu.Lock()
	defer s.mu.Unlock()

	moveTo(s.out, 1, 1)
	clearBelow(s.out)

	statusLines := buildStatusLines(s.cfg)
	layout := banner.Print(s.out, s.build.Version, statusLines)
	s.qRow = layout.QRow

	row := layout.BodyRow

	// transcript / last-command output region
	if s.lastCmd != "" {
		fmt.Fprintln(s.out, "  "+ui.Cyan("▸ ")+ui.Bold(s.lastCmd))
		row++
		fmt.Fprintln(s.out)
		row++
		// Indent each output line by 2 spaces for visual containment.
		for _, ln := range strings.Split(strings.TrimRight(s.lastOut, "\n"), "\n") {
			fmt.Fprintln(s.out, "  "+ln)
			row++
		}
		fmt.Fprintln(s.out)
		row++
	}

	if s.statusMsg != "" {
		fmt.Fprintln(s.out, "  "+s.statusMsg)
		fmt.Fprintln(s.out)
	}

	// Prompt line — placed inline beneath whatever transcript exists, so
	// the user types right where they expect.
	fmt.Fprint(s.out, "  "+ui.Cyan("postq")+ui.Dim(" › "))
}

// ── rotator goroutine ────────────────────────────────────────────────────────

func (s *shell) startRotator() {
	if !ui.Enabled() {
		return
	}
	s.stopRot = make(chan struct{})
	s.rotDone = make(chan struct{})
	go func() {
		defer close(s.rotDone)
		ticker := time.NewTicker(1100 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-s.stopRot:
				return
			case <-ticker.C:
				s.mu.Lock()
				s.qIdx++
				saveCursor(s.out)
				moveTo(s.out, s.qRow, 1)
				clearLine(s.out)
				banner.RenderQLine(s.out, s.qIdx)
				restoreCursor(s.out)
				flush(s.out)
				s.mu.Unlock()
			}
		}
	}()
}

func (s *shell) stopRotator() {
	if s.stopRot == nil {
		return
	}
	close(s.stopRot)
	<-s.rotDone
	s.stopRot = nil
	s.rotDone = nil
}

// ── status line content ──────────────────────────────────────────────────────

var recentScansCache string

func (s *shell) fetchRecentPeek() {
	cl := apiclient.New(s.cfg.APIEndpoint, s.cfg.APIKey, "postq-cli/"+s.build.Version)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	resp, err := cl.List(ctx, 3)
	if err != nil || len(resp.Data) == 0 {
		return
	}
	var b strings.Builder
	b.WriteString("  " + ui.Dim("recent scans") + "\n")
	for _, sc := range resp.Data {
		when := sc.CreatedAt
		if t, err := time.Parse(time.RFC3339, sc.CreatedAt); err == nil {
			when = t.Local().Format("01-02 15:04")
		}
		fmt.Fprintf(&b, "    %s  %s  %s\n", ui.Dim(when), ui.RiskBadgeStr(sc.RiskLevel), sc.Target)
	}
	recentScansCache = b.String()
}

func buildStatusLines(cfg *config.Config) []string {
	endpoint := cfg.APIEndpoint
	if endpoint == "" {
		endpoint = config.DefaultEndpoint
	}
	keyLine := ui.Dim("not authenticated") + " · " + ui.Yellow("uploads disabled")
	if cfg.APIKey != "" {
		keyLine = ui.Green("● ") + ui.Bold("authenticated") + ui.Dim(" as "+config.MaskKey(cfg.APIKey))
	}
	out := []string{
		"  " + keyLine,
		"  " + ui.Dim("endpoint  ") + endpoint,
	}
	if recentScansCache != "" {
		// trim trailing newline so banner.Print's spacing stays consistent
		out = append(out, strings.TrimRight(recentScansCache, "\n"))
	}
	return out
}

func renderStatus(cfg *config.Config, build Build) string {
	endpoint := cfg.APIEndpoint
	if endpoint == "" {
		endpoint = config.DefaultEndpoint
	}
	var b strings.Builder
	if cfg.APIKey != "" {
		fmt.Fprintf(&b, "%s%s%s\n", ui.Green("● "), ui.Bold("authenticated"), ui.Dim(" as "+config.MaskKey(cfg.APIKey)))
	} else {
		fmt.Fprintln(&b, ui.Dim("not authenticated"))
	}
	fmt.Fprintf(&b, "%s%s\n", ui.Dim("endpoint  "), endpoint)
	fmt.Fprintf(&b, "%s%s · %s/%s\n", ui.Dim("cli       v"), build.Version, runtime.GOOS, runtime.GOARCH)
	return b.String()
}

func renderHelp() string {
	rows := []struct {
		section string
		entries [][2]string
	}{
		{"SCAN", [][2]string{
			{"scan url <host> [host ...]", "TLS handshake + cert quantum-risk scan"},
			{"scan cloud aws --account ID", "server-side AWS KMS inventory"},
			{"scan code <path>", ui.Cyan("(beta)") + " static crypto-misuse scan"},
			{"scan list [--limit N]", "recent scans uploaded to your org"},
		}},
		{"AUTH", [][2]string{
			{"login", "paste / enter an API key (pq_live_…)"},
			{"logout", "remove saved credentials"},
			{"status", "show endpoint + masked key"},
		}},
		{"SHELL", [][2]string{
			{"help / ?", "show this help"},
			{"clear", "clear the transcript area"},
			{"dashboard", "open https://app.postq.dev in your browser"},
			{"exit / quit", "leave the shell"},
		}},
	}
	var b strings.Builder
	for _, sec := range rows {
		fmt.Fprintln(&b, ui.Purple(sec.section))
		for _, r := range sec.entries {
			pad := 32 - visibleLen(r[0])
			if pad < 1 {
				pad = 1
			}
			fmt.Fprintln(&b, "  "+ui.Cyan(r[0])+strings.Repeat(" ", pad)+ui.Dim(r[1]))
		}
		fmt.Fprintln(&b)
	}
	fmt.Fprintln(&b, ui.Dim("any flag from the non-interactive CLI works here too,"))
	fmt.Fprintln(&b, ui.Dim("e.g. ")+ui.Cyan("scan url example.com --json --no-upload"))
	return b.String()
}

// ── onboarding (runs inline, NOT inside alt screen) ──────────────────────────

func runOnboarding(out io.Writer, scanner *bufio.Scanner) bool {
	fmt.Fprintln(out)
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
	fmt.Fprintln(out)
	return true
}

// ── stdout capture ───────────────────────────────────────────────────────────

// captureDispatch redirects os.Stdout into a pipe while dispatch runs, so
// scan command output can be painted into our body region instead of
// scrolling past the banner.
func captureDispatch(dispatch Dispatch, args []string) (string, error) {
	orig := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		return "", dispatch(args)
	}
	os.Stdout = w

	var buf bytes.Buffer
	done := make(chan struct{})
	go func() {
		_, _ = io.Copy(&buf, r)
		close(done)
	}()

	derr := dispatch(args)
	_ = w.Close()
	os.Stdout = orig
	<-done
	return buf.String(), derr
}

// ── ANSI helpers ─────────────────────────────────────────────────────────────

func enterAltScreen(w io.Writer) { fmt.Fprint(w, "\x1b[?1049h") }
func leaveAltScreen(w io.Writer) { fmt.Fprint(w, "\x1b[?1049l") }
func hideCursor(w io.Writer)     { fmt.Fprint(w, "\x1b[?25l") }
func showCursor(w io.Writer)     { fmt.Fprint(w, "\x1b[?25h") }
func clearBelow(w io.Writer)     { fmt.Fprint(w, "\x1b[J") }
func clearLine(w io.Writer)      { fmt.Fprint(w, "\x1b[2K") }
func saveCursor(w io.Writer)     { fmt.Fprint(w, "\x1b[s") }
func restoreCursor(w io.Writer)  { fmt.Fprint(w, "\x1b[u") }

func moveTo(w io.Writer, row, col int) {
	if row < 1 {
		row = 1
	}
	if col < 1 {
		col = 1
	}
	fmt.Fprintf(w, "\x1b[%d;%dH", row, col)
}

func flush(w io.Writer) {
	if f, ok := w.(*os.File); ok {
		_ = f.Sync()
	}
}

// ── input ────────────────────────────────────────────────────────────────────

func readLine(scanner *bufio.Scanner) (string, bool) {
	if !scanner.Scan() {
		return "", false
	}
	return scanner.Text(), true
}

// ── helpers ──────────────────────────────────────────────────────────────────

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
