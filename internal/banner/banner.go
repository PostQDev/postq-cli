// Package banner renders the animated PostQ logo + intro card shown at
// startup of the interactive shell.
package banner

import (
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/postqdev/postq-cli/internal/ui"
)

// Q-as-variable: the bracketed word rotates on startup.
var qWords = []string{
	"Quantum",
	"AI",
	"Q-Day",
	"Mythos",
	"Quotient",
	"Query",
}

// PostQ block-letter logo. Each line is one row of glyphs.
// Reads "Post[ Q ]" with the Q drawn as part of the block letters.
var logoLines = []string{
	"██████╗  ██████╗ ███████╗████████╗   ▄▄▄▄▄  ",
	"██╔══██╗██╔═══██╗██╔════╝╚══██╔══╝  █     █ ",
	"██████╔╝██║   ██║███████╗   ██║     █  ◆  █ ",
	"██╔═══╝ ██║   ██║╚════██║   ██║     █     █ ",
	"██║     ╚██████╔╝███████║   ██║      ▀▀█▄▀  ",
	"╚═╝      ╚═════╝ ╚══════╝   ╚═╝         ▀▀  ",
}

// Print renders the full banner with optional animation. Pass animate=false
// for non-TTY/CI use.
func Print(w io.Writer, version string, animate bool) {
	if w == nil {
		w = os.Stdout
	}
	colors := []string{
		"\x1b[38;5;141m", // soft purple
		"\x1b[38;5;135m",
		"\x1b[38;5;99m",
		"\x1b[38;5;105m",
		"\x1b[38;5;111m",
		"\x1b[38;5;117m", // soft cyan
	}
	reset := "\x1b[0m"

	fmt.Fprintln(w)
	for i, line := range logoLines {
		if ui.Enabled() {
			fmt.Fprintln(w, "  "+colors[i%len(colors)]+line+reset)
		} else {
			fmt.Fprintln(w, "  "+line)
		}
	}
	fmt.Fprintln(w)

	tagline := "  cryptographic posture for whatever Q-Day comes next"
	fmt.Fprintln(w, ui.Dim(tagline))

	// Rotating word line: "  what's your [_____]?"
	if animate && ui.Enabled() && isTTY(w) {
		animateRotator(w)
	} else {
		fmt.Fprintln(w, "  what's your "+ui.Bold("[")+ui.Cyan(qWords[0])+ui.Bold("]")+"?")
	}

	fmt.Fprintln(w)
	fmt.Fprintln(w, ui.Dim("  v"+version+"  ·  type ")+ui.Cyan("help")+ui.Dim(" for commands  ·  ")+ui.Cyan("exit")+ui.Dim(" to quit"))
	fmt.Fprintln(w)
}

// animateRotator briefly cycles the bracketed word on a single redrawn line.
func animateRotator(w io.Writer) {
	prefix := "  what's your "
	suffix := "?"
	// width of the longest word so we can pad cleanly during redraws
	pad := 0
	for _, q := range qWords {
		if len(q) > pad {
			pad = len(q)
		}
	}
	for i, q := range qWords {
		// build line
		bracketed := ui.Bold("[") + ui.Cyan(q) + ui.Bold("]")
		filler := strings.Repeat(" ", pad-len(q))
		line := "\r" + prefix + bracketed + suffix + filler
		fmt.Fprint(w, line)
		// Faster as we go, then slow on the final word.
		switch {
		case i == len(qWords)-1:
			// final - hold
		case i == 0:
			time.Sleep(140 * time.Millisecond)
		default:
			time.Sleep(110 * time.Millisecond)
		}
	}
	fmt.Fprintln(w)
}

func isTTY(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}
