package commands

import (
	"flag"
	"io"
	"testing"
	"time"
)

func TestParsePermuted(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	asJSON := fs.Bool("json", false, "")
	timeout := fs.Duration("timeout", 10*time.Second, "")

	positionals, err := parsePermuted(
		fs,
		[]string{"one.example", "--json", "two.example", "--timeout", "5s"},
	)
	if err != nil {
		t.Fatalf("parsePermuted() error = %v", err)
	}
	if len(positionals) != 2 || positionals[0] != "one.example" || positionals[1] != "two.example" {
		t.Fatalf("positionals = %#v", positionals)
	}
	if !*asJSON || *timeout != 5*time.Second {
		t.Fatalf("flags: json=%v timeout=%s", *asJSON, *timeout)
	}
}
