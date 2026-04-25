// Package banner holds the static PostQ ASCII logo and the rotating
// Q-words used by the interactive shell.
package banner

// QWords is the rotating list of "Q-as-variable" words.
var QWords = []string{
	"Quantum",
	"AI",
	"Q-Day",
	"Mythos",
	"Quotient",
	"Query",
}

// MaxQWordLen is the longest QWord — used to pre-size the rotator slot.
var MaxQWordLen = func() int {
	n := 0
	for _, q := range QWords {
		if len(q) > n {
			n = len(q)
		}
	}
	return n
}()

// LogoBig is the wide, multi-row block-letter logo.
var LogoBig = []string{
	"██████╗  ██████╗ ███████╗████████╗   ▄▄▄▄▄  ",
	"██╔══██╗██╔═══██╗██╔════╝╚══██╔══╝  █     █ ",
	"██████╔╝██║   ██║███████╗   ██║     █  ◆  █ ",
	"██╔═══╝ ██║   ██║╚════██║   ██║     █     █ ",
	"██║     ╚██████╔╝███████║   ██║      ▀▀█▄▀  ",
	"╚═╝      ╚═════╝ ╚══════╝   ╚═╝         ▀▀  ",
}

// LogoBigWidth is the printable width of LogoBig (all rows are equal).
const LogoBigWidth = 44

// LogoSmall is a single-line wordmark for narrow terminals.
const LogoSmall = "Post[Q]"

// LogoColors are the per-row gradient colors for LogoBig.
var LogoColors = []string{
	"\x1b[38;5;141m",
	"\x1b[38;5;135m",
	"\x1b[38;5;99m",
	"\x1b[38;5;105m",
	"\x1b[38;5;111m",
	"\x1b[38;5;117m",
}
