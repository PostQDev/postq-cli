// Package banner renders the animated PostQ logo + intro card shown at
// the top of the interactive shell.
package banner

import (
	"fmt"
	"io"
	"os"

	"github.com/postqdev/postq-cli/internal/ui"
)

// QWords is the rotating list of "Q-as-variable" words.
var QWords = []string{
	"Quantum",
	"AI",
	"Q-Day",
	"Mythos",
	"Quotient",
	"Query",
}

// MaxQWordLen is the longest QWord — used to pre-size the rotator slot
// so the layout doesn't shift as words change.
var MaxQWordLen = func() int {
	n := 0
	for _, q := range QWords {
		if len(q) > n {
			n = len(q)
		}
	}
	return n
}()

var logoLines = []string{
	"██████╗  ██████╗ ███████╗████████╗   ▄▄▄▄▄  ",
	"██╔══██╗██╔═══██╗██╔════╝╚══██╔══╝  █     █ ",
	"██████╔╝██║   ██║███████╗   ██║     █  ◆  █ ",
	"██╔═══╝ ██║   ██║╚════██║   ██║     █     █ ",
	"██║     ╚██████╔╝███████║   ██║      ▀▀█▄▀  ",
	"╚═╝      ╚═════╝ ╚══════╝   ╚═╝         ▀▀  ",
}

// Layout positions returned by Print so callers know which absolute row
// the rotating-Q line is on (for in-place updates) and where the body
// region starts.
type Layout struct {
	QRow    int
	BodyRow int
}

var logoColors = []string{
	"\x1b[38;5;141m",
	"\x1b[38;5;135m",
	"\x1b[38;5;99m",
	"\x1b[38;5;105m",
	"\x1b[38;5;111m",
	"\x1b[38;5;117m",
}

const reset = "\x1b[0m"

// Print renders the banner at the current cursor position. Caller should
// have homed the cursor first (\x1b[H). statusLines are inserted between
// the rule lines beneath the logo (e.g. auth status, recent scans).
func Print(w io.Writer, version string, statusLines []string) Layout {
	if w == nil {
		w = os.Stdout
	}

	row := 1
	fmt.Fprintln(w)
	row++

	for i, line := range logoLines {
		if ui.Enabled() {
			fmt.Fprintln(w, "  "+logoColors[i%len(logoColors)]+line+reset)
		} else {
			fmt.Fprintln(w, "  "+line)
		}
		row++
	}
	fmt.Fprintln(w)
	row++

	fmt.Fprintln(w, ui.Dim("  cryptographic posture for whatever Q-Day comes next"))
	row++

	qRow := row
	RenderQLine(w, 0)
	fmt.Fprintln(w)
	row++

	fmt.Fprintln(w)
	row++

	fmt.Fprintln(w, ui.Dim("  ──────────────────────────────────────────────────────────────"))
	row++

	for _, l := range statusLines {
		fmt.Fprintln(w, l)
		row++
	}
	fmt.Fprintln(w, ui.Dim("  v"+version+"  ·  type ")+ui.Cyan("help")+ui.Dim(" for commands  ·  ")+ui.Cyan("exit")+ui.Dim(" to quit"))
	row++

	fmt.Fprintln(w, ui.Dim("  ──────────────────────────────────────────────────────────────"))
	row++
	fmt.Fprintln(w)
	row++

	return Layout{QRow: qRow, BodyRow: row}
}

// RenderQLine writes just the rotating-Q line at the current cursor
// position, padded so the trailing "?" stays in the same column across
// words of different length.
func RenderQLine(w io.Writer, idx int) {
	idx = ((idx % len(QWords)) + len(QWords)) % len(QWords)
	q := QWords[idx]
	pad := MaxQWordLen - len(q)
	if pad < 0 {
		pad = 0
	}
	fmt.Fprint(w, "  what's your ", ui.Bold("["), ui.Cyan(q), ui.Bold("]"), "?")
	for i := 0; i < pad; i++ {
		fmt.Fprint(w, " ")
	}
}
