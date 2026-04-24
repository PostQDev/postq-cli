// Package main is the entrypoint for the PostQ CLI.
package main

import (
	"fmt"
	"os"

	"github.com/postqdev/postq-cli/internal/commands"
)

// These are overridden at build time by GoReleaser via -ldflags:
//
//	-X main.version={{.Version}} -X main.commit={{.Commit}} -X main.date={{.Date}}
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	if err := commands.Run(os.Args[1:], commands.BuildInfo{
		Version: version,
		Commit:  commit,
		Date:    date,
	}); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
