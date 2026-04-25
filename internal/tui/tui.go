// Package tui implements the interactive PostQ shell launched when the user
// runs `postq` with no arguments.
//
// Layout (Copilot-CLI inspired):
//
//	╭─────────────────────────────────────────────────────────────╮
//	│                                                             │
//	│              ██████╗   …  PostQ block-letter logo           │
//	│                                                             │
//	│              cryptographic posture …                        │
//	│              what's your [Quantum]?       ← rotates          │
//	│                                                             │
//	│   ● authenticated as pq_live_…                              │
//	│   endpoint  https://api.postq.dev                           │
//	│                                                             │
//	│   ▸ scan code .                                             │
//	│     21 findings, 4 critical                                 │
//	│                                                             │
//	│   ~/postq-cli  [⎇ feat/interactive-shell]                  │
//	│   ╭───────────────────────────────────────────────────────╮ │
//	│   │ ›  type a command, or ? for help                      │ │
//	│   ╰───────────────────────────────────────────────────────╯ │
//	│   Ctrl+C exit · Ctrl+L clear · ? help                       │
//	╰─────────────────────────────────────────────────────────────╯
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
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/postqdev/postq-cli/internal/apiclient"
	"github.com/postqdev/postq-cli/internal/banner"
	"github.com/postqdev/postq-cli/internal/config"
	"github.com/postqdev/postq-cli/internal/term"
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

// shell holds mutable state across the REPL loop.
type shell struct {
	out      io.Writer
	in       io.Reader
	build    Build
	dispatch Dispatch
	cfg      *config.Config

	// transcript shown above the prompt
	lastCmd   string
	lastOut   string
	statusMsg string

	// rotator state
	mu      sync.Mutex
	qIdx    int
	qRow    int // absolute terminal row of the rotating-Q line
	qCol    int // absolute terminal col where "what's your " starts
	stopRot chan struct{}
	rotDone chan struct{}
}

// Run starts the interactive shell.
func Run(in io.Reader, out io.Writer, build Build, dispatch Dispatch) error {
	if in == nil {
		in = os.Stdin
	}
	if out == nil {
		out = os.Stdout
	}

	sh := &shell{out: out, in: in, build: build, dispatch: dispatch}
	sh.cfg, _ = config.Load()

	// Onboarding runs INLINE (before alt-screen) for clean paste UX.
	if sh.cfg.APIKey == "" {
		runOnboarding(out, bufio.NewScanner(in))
		sh.cfg, _ = config.Load()
	}

	// Best-effort recent-scans peek before painting.
	if sh.cfg.APIKey != "" {
		sh.fetchRecentPeek()
	}

	enterAltScreen(out)
	defer leaveAltScreen(out)
	defer showCursor(out)

	// Clean exit on signals.
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

	// Repaint on terminal resize.
	resize := term.OnResize()

	scanner := bufio.NewScanner(in)
	scanner.Buffer(make([]byte, 0, 1024), 1024*1024)

	for {
		sh.repaint()
		sh.startRotator()

		// Drain any resize events that fired during repaint.
		select {
		case <-resize:
		default:
		}

		// Read one line. If a resize comes in, we just repaint after Enter
		// — readline-with-resize-while-blocked needs raw mode which we
		// avoid for the stdlib-only constraint.
		line, ok := readLine(scanner)
		sh.stopRotator()
		if !ok {
			return nil
		}
		line = strings.TrimSpace(line)

		// Empty line or pure whitespace: just repaint (e.g. dismiss).
		if line == "" {
			continue
		}

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
			leaveAltScreen(out)
			showCursor(out)
			runLoginPrompt(out, scanner)
			sh.cfg, _ = config.Load()
			enterAltScreen(out)
			continue
		case "open dashboard", "dashboard":
			openBrowser("https://app.postq.dev")
			sh.statusMsg = ui.Dim("→ opened https://app.postq.dev in browser")
			continue
		}

		args := tokenize(line)
		if len(args) == 0 {
			continue
		}
		if args[0] == "shell" || args[0] == "interactive" {
			sh.statusMsg = ui.Dim("(already in interactive shell)")
			continue
		}

		sh.lastCmd = line
		captured, err := captureDispatch(sh.dispatch, args)
		sh.lastOut = captured
		if err != nil {
			sh.lastOut += "\n" + ui.Red("✗ ") + err.Error()
		}
	}
}

// ── painting ─────────────────────────────────────────────────────────────────

const (
	minBoxWidth  = 60
	minBoxHeight = 24
	innerPad     = 2 // horizontal padding inside outer box
)

func (s *shell) repaint() {
	s.mu.Lock()
	defer s.mu.Unlock()

	rows, cols := term.Size()
	if rows < minBoxHeight {
		rows = minBoxHeight
	}
	if cols < minBoxWidth {
		cols = minBoxWidth
	}

	// Outer box spans the whole terminal.
	boxW := cols
	boxH := rows

	// Clear & home.
	hideCursor(s.out)
	moveTo(s.out, 1, 1)
	clearScreen(s.out)

	useBig := boxW >= banner.LogoBigWidth+innerPad*2+4

	// Track absolute row as we draw. Row 1 is the top border.
	row := 1

	// Top border
	drawBorderTop(s.out, boxW)
	row++

	// Blank inside line
	drawBlankLine(s.out, boxW)
	row++

	// Logo (centered)
	if useBig {
		for i, l := range banner.LogoBig {
			leftPad := (boxW - banner.LogoBigWidth) / 2
			color := ""
			reset := ""
			if ui.Enabled() {
				color = banner.LogoColors[i%len(banner.LogoColors)]
				reset = "\x1b[0m"
			}
			content := strings.Repeat(" ", leftPad) + color + banner.LogoBig[i] + reset
			_ = l
			drawContentLine(s.out, boxW, content, banner.LogoBigWidth+leftPad)
			row++
		}
	} else {
		// Narrow terminal: single-line wordmark
		wm := banner.LogoSmall
		leftPad := (boxW - len(wm)) / 2
		drawContentLine(s.out, boxW, strings.Repeat(" ", leftPad)+ui.Bold(wm), leftPad+len(wm))
		row++
	}

	drawBlankLine(s.out, boxW)
	row++

	// Tagline
	tagline := "cryptographic posture for whatever Q-Day comes next"
	taglinePad := (boxW - len(tagline)) / 2
	if taglinePad < 0 {
		taglinePad = 0
	}
	drawContentLine(s.out, boxW, strings.Repeat(" ", taglinePad)+ui.Dim(tagline), taglinePad+len(tagline))
	row++

	// Rotating Q line — record absolute row for in-place updates.
	qLineText, qVisLen := buildQLine(s.qIdx)
	qLeftPad := (boxW - qVisLen) / 2
	if qLeftPad < 0 {
		qLeftPad = 0
	}
	s.qRow = row
	s.qCol = 1 + 1 + qLeftPad // 1 (border) + 1 (space inside) ... but border is at col 1, inner content starts at col 2
	// Actually: drawContentLine writes "│" + content padded + "│". Content
	// itself starts at col 2. So absolute col of the left-pad start is 2.
	s.qCol = 2
	drawContentLine(s.out, boxW, strings.Repeat(" ", qLeftPad)+qLineText, qLeftPad+qVisLen)
	row++

	drawBlankLine(s.out, boxW)
	row++

	// Status block (left-aligned with innerPad).
	for _, l := range buildStatusLines(s.cfg) {
		drawContentLine(s.out, boxW, strings.Repeat(" ", innerPad)+l, innerPad+visibleLen(l))
		row++
	}
	drawBlankLine(s.out, boxW)
	row++

	// Compute how many rows are reserved for the bottom (location + prompt + footer).
	// 1 location, 3 inner box (top/middle/bottom), 1 footer = 5 rows.
	const bottomReserve = 5

	// Body region for transcript fills everything between current row and
	// the bottom-reserve region.
	bodyMaxRow := boxH - 1 - bottomReserve // -1 for outer bottom border
	if s.lastCmd != "" {
		avail := bodyMaxRow - row
		if avail > 0 {
			bodyLines := buildTranscript(s.lastCmd, s.lastOut, boxW-innerPad*2-2)
			// Keep the most recent N lines.
			if len(bodyLines) > avail {
				dropped := len(bodyLines) - avail + 1
				bodyLines = append(
					[]string{ui.Dim(fmt.Sprintf("… %d earlier line(s) hidden", dropped))},
					bodyLines[dropped:]...,
				)
			}
			for _, l := range bodyLines {
				drawContentLine(s.out, boxW, strings.Repeat(" ", innerPad)+l, innerPad+visibleLen(l))
				row++
				if row >= bodyMaxRow {
					break
				}
			}
		}
	}
	if s.statusMsg != "" && row < bodyMaxRow {
		drawContentLine(s.out, boxW, strings.Repeat(" ", innerPad)+s.statusMsg, innerPad+visibleLen(s.statusMsg))
		row++
	}

	// Pad blank lines until we hit the bottom-reserve region.
	for row < boxH-1-bottomReserve {
		drawBlankLine(s.out, boxW)
		row++
	}

	// Location line: ~/cwd  [⎇ branch]
	locLine := buildLocationLine()
	drawContentLine(s.out, boxW, strings.Repeat(" ", innerPad)+locLine, innerPad+visibleLen(locLine))
	row++

	// Inner prompt box (3 rows)
	innerW := boxW - innerPad*2 - 2 // leaves 2 chars total padding from outer border
	if innerW < 10 {
		innerW = 10
	}
	drawInnerBoxTop(s.out, boxW, innerW)
	row++
	// Inner box middle line — the input line
	promptInner := " " + ui.Cyan("›") + "  "
	placeholder := ui.Dim("type a command, or ? for help")
	drawInnerBoxMiddle(s.out, boxW, innerW, promptInner+placeholder, visibleLen(promptInner)+visibleLen(placeholder))
	promptRow := row
	promptCol := innerCursorCol(boxW, innerW, visibleLen(promptInner))
	row++
	drawInnerBoxBottom(s.out, boxW, innerW)
	row++

	// Footer
	footer := ui.Bold("Ctrl+C") + ui.Dim(" exit  · ") +
		ui.Bold("Ctrl+L") + ui.Dim(" clear  · ") +
		ui.Bold("?") + ui.Dim(" help")
	drawContentLine(s.out, boxW, strings.Repeat(" ", innerPad)+footer, innerPad+visibleLen(footer))
	row++

	// Pad until bottom border row (boxH).
	for row < boxH {
		drawBlankLine(s.out, boxW)
		row++
	}

	// Bottom border (no trailing newline so we don't push the box up).
	drawBorderBottom(s.out, boxW)

	// Position cursor inside the prompt box, ready for input.
	moveTo(s.out, promptRow, promptCol)
	// Erase the placeholder (so when the user types, it doesn't visually
	// land on top of the dim text).
	clearLineFromCursor(s.out)
	showCursor(s.out)
	flush(s.out)
}

func innerCursorCol(boxW, innerW, prefixVisLen int) int {
	// Outer "│" at col 1, then innerPad spaces, then inner "│" border, then content starts.
	leftOfContent := 1 + innerPad + 1 + prefixVisLen
	_ = innerW
	_ = boxW
	return leftOfContent + 1
}

// ── Q rotator goroutine ──────────────────────────────────────────────────────

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
				// Move to the rotating-Q row, col 2 (just inside outer border).
				moveTo(s.out, s.qRow, 2)
				// Erase from cursor to end of line, but stop before right border.
				// Easiest: rewrite the whole content area.
				_, cols := term.Size()
				boxW := cols
				if boxW < minBoxWidth {
					boxW = minBoxWidth
				}
				qText, qVis := buildQLine(s.qIdx)
				qLeftPad := (boxW - qVis) / 2
				if qLeftPad < 0 {
					qLeftPad = 0
				}
				inner := boxW - 2
				content := strings.Repeat(" ", qLeftPad) + qText
				// Pad to fill inner width so any prior longer word is overwritten.
				padRight := inner - qLeftPad - qVis
				if padRight < 0 {
					padRight = 0
				}
				fmt.Fprint(s.out, content+strings.Repeat(" ", padRight))
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

// ── content helpers ──────────────────────────────────────────────────────────

func buildQLine(idx int) (string, int) {
	idx = ((idx % len(banner.QWords)) + len(banner.QWords)) % len(banner.QWords)
	q := banner.QWords[idx]
	prefix := "what's your "
	suffix := "?"
	visLen := len(prefix) + 1 + len(q) + 1 + len(suffix) // "[" + q + "]"
	text := prefix + ui.Bold("[") + ui.Cyan(q) + ui.Bold("]") + suffix
	return text, visLen
}

var recentScansCache string

func (s *shell) fetchRecentPeek() {
	cl := apiclient.New(s.cfg.APIEndpoint, s.cfg.APIKey, "postq-cli/"+s.build.Version)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	resp, err := cl.List(ctx, 3)
	if err != nil || len(resp.Data) == 0 {
		return
	}
	var lines []string
	lines = append(lines, ui.Dim("recent scans"))
	for _, sc := range resp.Data {
		when := sc.CreatedAt
		if t, err := time.Parse(time.RFC3339, sc.CreatedAt); err == nil {
			when = t.Local().Format("01-02 15:04")
		}
		lines = append(lines, fmt.Sprintf("  %s  %s  %s",
			ui.Dim(when), ui.RiskBadgeStr(sc.RiskLevel), sc.Target))
	}
	recentScansCache = strings.Join(lines, "\n")
}

func buildStatusLines(cfg *config.Config) []string {
	endpoint := cfg.APIEndpoint
	if endpoint == "" {
		endpoint = config.DefaultEndpoint
	}
	keyLine := ui.Dim("○") + " " + ui.Dim("not authenticated") + " · " + ui.Yellow("uploads disabled")
	if cfg.APIKey != "" {
		keyLine = ui.Green("●") + " " + ui.Bold("Authenticated") + ui.Dim(" as "+config.MaskKey(cfg.APIKey))
	}
	out := []string{
		keyLine,
		ui.Blue("●") + " " + ui.Dim("API endpoint  ") + endpoint,
	}
	if recentScansCache != "" {
		for _, l := range strings.Split(recentScansCache, "\n") {
			out = append(out, l)
		}
	}
	return out
}

func buildLocationLine() string {
	cwd, _ := os.Getwd()
	home, _ := os.UserHomeDir()
	if home != "" && strings.HasPrefix(cwd, home) {
		cwd = "~" + strings.TrimPrefix(cwd, home)
	}
	branch := gitBranch(cwd)
	out := ui.Bold(cwd)
	if branch != "" {
		out += "  " + ui.Dim("[") + ui.Cyan("⎇ "+branch) + ui.Dim("]")
	}
	return out
}

// gitBranch reads .git/HEAD walking upward from dir. Best-effort, no shell out.
func gitBranch(dir string) string {
	for i := 0; i < 12; i++ {
		head := filepath.Join(dir, ".git", "HEAD")
		if data, err := os.ReadFile(head); err == nil {
			s := strings.TrimSpace(string(data))
			if strings.HasPrefix(s, "ref: refs/heads/") {
				return strings.TrimPrefix(s, "ref: refs/heads/")
			}
			if len(s) >= 7 {
				return s[:7]
			}
			return ""
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return ""
}

func buildTranscript(cmd, output string, maxWidth int) []string {
	if maxWidth < 20 {
		maxWidth = 20
	}
	header := ui.Cyan("▸ ") + ui.Bold(cmd)
	lines := []string{header, ""}
	for _, ln := range strings.Split(strings.TrimRight(output, "\n"), "\n") {
		// Soft-wrap on visible width (rough — splits by visible runes).
		for _, w := range softWrap(ln, maxWidth) {
			lines = append(lines, w)
		}
	}
	return lines
}

func softWrap(s string, maxVis int) []string {
	if visibleLen(s) <= maxVis {
		return []string{s}
	}
	// Crude fallback: split at maxVis runes ignoring ANSI is tricky. For
	// now, just truncate with an ellipsis — most scan output already fits.
	out := []string{}
	cur := ""
	curVis := 0
	inEsc := false
	for _, r := range s {
		cur += string(r)
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
		curVis++
		if curVis >= maxVis {
			out = append(out, cur)
			cur = ""
			curVis = 0
		}
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}

// ── help / status (transcript renderers) ─────────────────────────────────────

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
	fmt.Fprintf(&b, "%s%s · %s/%s", ui.Dim("cli       v"), build.Version, runtime.GOOS, runtime.GOARCH)
	return b.String()
}

func renderHelp() string {
	rows := []struct {
		section string
		entries [][2]string
	}{
		{"SCAN", [][2]string{
			{"scan url <host>", "TLS handshake + cert quantum-risk scan"},
			{"scan cloud aws --account ID", "server-side AWS KMS inventory"},
			{"scan code <path>", ui.Cyan("(beta)") + " static crypto-misuse scan"},
			{"scan list [--limit N]", "recent scans uploaded to your org"},
		}},
		{"AUTH", [][2]string{
			{"login", "paste / enter an API key"},
			{"logout", "remove saved credentials"},
			{"status", "show endpoint + masked key"},
		}},
		{"SHELL", [][2]string{
			{"clear", "clear the transcript area"},
			{"dashboard", "open https://app.postq.dev"},
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
	fmt.Fprint(&b, ui.Dim("e.g. ")+ui.Cyan("scan url example.com --json --no-upload"))
	return b.String()
}

// ── onboarding (inline, before alt screen) ───────────────────────────────────

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
	fmt.Fprintln(out, ui.Green("  ✓ ")+"saved")
	fmt.Fprintln(out)
	return true
}

// ── stdout capture ───────────────────────────────────────────────────────────

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

// ── box drawing ──────────────────────────────────────────────────────────────

const (
	tlc = "╭"
	trc = "╮"
	blc = "╰"
	brc = "╯"
	hb  = "─"
	vb  = "│"
)

func drawBorderTop(w io.Writer, width int) {
	fmt.Fprint(w, ui.Purple(tlc+strings.Repeat(hb, width-2)+trc))
	fmt.Fprintln(w)
}

func drawBorderBottom(w io.Writer, width int) {
	// No trailing newline so we don't scroll.
	fmt.Fprint(w, ui.Purple(blc+strings.Repeat(hb, width-2)+brc))
}

func drawBlankLine(w io.Writer, width int) {
	fmt.Fprint(w, ui.Purple(vb)+strings.Repeat(" ", width-2)+ui.Purple(vb))
	fmt.Fprintln(w)
}

// drawContentLine writes a single row inside the outer box: "│" + content
// + padding + "│". contentVisLen is the content's visible (non-ANSI) width.
// If the content is wider than the available inner width, it is
// truncated with an ellipsis.
func drawContentLine(w io.Writer, boxW int, content string, contentVisLen int) {
	inner := boxW - 2
	if contentVisLen > inner {
		content = truncateVisible(content, inner-1) + "…"
		contentVisLen = inner
	}
	pad := inner - contentVisLen
	if pad < 0 {
		pad = 0
	}
	fmt.Fprint(w, ui.Purple(vb)+content+strings.Repeat(" ", pad)+ui.Purple(vb))
	fmt.Fprintln(w)
}

// truncateVisible returns the prefix of s whose visible width is <= max,
// preserving any ANSI escape sequences within that prefix.
func truncateVisible(s string, max int) string {
	if max <= 0 {
		return ""
	}
	var b strings.Builder
	vis, inEsc := 0, false
	for _, r := range s {
		if inEsc {
			b.WriteRune(r)
			if r == 'm' {
				inEsc = false
			}
			continue
		}
		if r == 0x1b {
			inEsc = true
			b.WriteRune(r)
			continue
		}
		if vis >= max {
			break
		}
		b.WriteRune(r)
		vis++
	}
	return b.String()
}

func drawInnerBoxTop(w io.Writer, boxW, innerW int) {
	left := strings.Repeat(" ", innerPad)
	right := strings.Repeat(" ", boxW-2-innerPad-innerW)
	if right == "" || boxW-2-innerPad-innerW < 0 {
		right = ""
	}
	box := ui.Dim(tlc + strings.Repeat(hb, innerW-2) + trc)
	fmt.Fprint(w, ui.Purple(vb)+left+box+right+ui.Purple(vb))
	fmt.Fprintln(w)
}

func drawInnerBoxBottom(w io.Writer, boxW, innerW int) {
	left := strings.Repeat(" ", innerPad)
	right := strings.Repeat(" ", boxW-2-innerPad-innerW)
	if boxW-2-innerPad-innerW < 0 {
		right = ""
	}
	box := ui.Dim(blc + strings.Repeat(hb, innerW-2) + brc)
	fmt.Fprint(w, ui.Purple(vb)+left+box+right+ui.Purple(vb))
	fmt.Fprintln(w)
}

func drawInnerBoxMiddle(w io.Writer, boxW, innerW int, content string, contentVisLen int) {
	left := strings.Repeat(" ", innerPad)
	right := strings.Repeat(" ", boxW-2-innerPad-innerW)
	if boxW-2-innerPad-innerW < 0 {
		right = ""
	}
	innerPadRight := innerW - 2 - contentVisLen
	if innerPadRight < 0 {
		innerPadRight = 0
	}
	inner := ui.Dim(vb) + content + strings.Repeat(" ", innerPadRight) + ui.Dim(vb)
	fmt.Fprint(w, ui.Purple(vb)+left+inner+right+ui.Purple(vb))
	fmt.Fprintln(w)
}

// ── ANSI / cursor helpers ────────────────────────────────────────────────────

func enterAltScreen(w io.Writer)      { fmt.Fprint(w, "\x1b[?1049h") }
func leaveAltScreen(w io.Writer)      { fmt.Fprint(w, "\x1b[?1049l") }
func hideCursor(w io.Writer)          { fmt.Fprint(w, "\x1b[?25l") }
func showCursor(w io.Writer)          { fmt.Fprint(w, "\x1b[?25h") }
func clearScreen(w io.Writer)         { fmt.Fprint(w, "\x1b[2J") }
func clearLineFromCursor(w io.Writer) { /* no-op: we re-draw next frame */ }
func saveCursor(w io.Writer)          { fmt.Fprint(w, "\x1b[s") }
func restoreCursor(w io.Writer)       { fmt.Fprint(w, "\x1b[u") }

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

// ── input + helpers ──────────────────────────────────────────────────────────

func readLine(scanner *bufio.Scanner) (string, bool) {
	if !scanner.Scan() {
		return "", false
	}
	return scanner.Text(), true
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
