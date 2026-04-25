// Package ui provides TTY-aware ANSI color helpers for terminal output.
package ui

import (
	"os"
	"strings"

	"github.com/postqdev/postq-cli/internal/report"
)

// EnableColor is set at startup based on TTY detection and the NO_COLOR env var.
// Toggle from the commands package via SetColor.
var enabled = autodetect()

func autodetect() bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	if os.Getenv("POSTQ_NO_COLOR") != "" {
		return false
	}
	fi, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}

// SetColor explicitly toggles ANSI color output.
func SetColor(on bool) { enabled = on }

// Enabled reports whether color output is on.
func Enabled() bool { return enabled }

const (
	reset  = "\x1b[0m"
	bold   = "\x1b[1m"
	dim    = "\x1b[2m"
	red    = "\x1b[31m"
	green  = "\x1b[32m"
	yellow = "\x1b[33m"
	blue   = "\x1b[34m"
	purple = "\x1b[35m"
	cyan   = "\x1b[36m"
	gray   = "\x1b[90m"
)

func wrap(code, s string) string {
	if !enabled {
		return s
	}
	return code + s + reset
}

// Bold/Dim/colour helpers.
func Bold(s string) string   { return wrap(bold, s) }
func Dim(s string) string    { return wrap(dim, s) }
func Red(s string) string    { return wrap(red, s) }
func Green(s string) string  { return wrap(green, s) }
func Yellow(s string) string { return wrap(yellow, s) }
func Blue(s string) string   { return wrap(blue, s) }
func Purple(s string) string { return wrap(purple, s) }
func Cyan(s string) string   { return wrap(cyan, s) }
func Gray(s string) string   { return wrap(gray, s) }

// SeverityBadge returns a coloured padded label like "[CRITICAL]".
func SeverityBadge(sev report.Severity) string {
	label := strings.ToUpper(string(sev))
	padded := label
	for len(padded) < 8 {
		padded += " "
	}
	switch sev {
	case report.SeverityCritical:
		return wrap(red+bold, "["+padded+"]")
	case report.SeverityHigh:
		return wrap(red, "["+padded+"]")
	case report.SeverityMedium:
		return wrap(yellow, "["+padded+"]")
	case report.SeverityLow:
		return wrap(blue, "["+padded+"]")
	case report.SeverityInfo:
		return wrap(gray, "["+padded+"]")
	default:
		return "[" + padded + "]"
	}
}

// RiskBadge returns a coloured one-word risk level.
func RiskBadge(rl report.RiskLevel) string {
	s := string(rl)
	switch rl {
	case report.RiskCritical:
		return wrap(red+bold, s)
	case report.RiskHigh:
		return wrap(red, s)
	case report.RiskMedium:
		return wrap(yellow, s)
	case report.RiskLow:
		return wrap(blue, s)
	case report.RiskSafe:
		return wrap(green, s)
	default:
		return s
	}
}

// RiskBadgeStr is the same as RiskBadge but accepts a plain string (used by
// the TUI which receives risk levels as strings from the API).
func RiskBadgeStr(s string) string {
	return RiskBadge(report.RiskLevel(s))
}
