// Online `postq ledger {entries,append,checkpoints,seal,proof,bundle}`
// subcommands — each is a thin wrapper over the corresponding REST endpoint.
//
// Offline `postq ledger verify <bundle.json>` lives in ledger.go.
package commands

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/postqdev/postq-cli/internal/hybridsign"
	"github.com/postqdev/postq-cli/internal/ui"
)

// commonAPIFlags wires --api-key / --api-endpoint into a flag set.
type commonAPIFlags struct {
	apiKey   *string
	endpoint *string
}

func registerCommonAPIFlags(fs *flag.FlagSet) commonAPIFlags {
	return commonAPIFlags{
		apiKey:   fs.String("api-key", "", "Override saved API key"),
		endpoint: fs.String("api-endpoint", "", "Override saved API endpoint"),
	}
}

func (f commonAPIFlags) client() (*hybridsign.Client, error) {
	return newHybridClient(*f.endpoint, *f.apiKey, BuildInfo{Version: "dev"})
}

// resolveDataFlag accepts either a JSON literal, a single key=value pair, or
// `@/path/to/file.json`.
func resolveDataFlag(s string) (map[string]any, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	if strings.HasPrefix(s, "@") {
		raw, err := os.ReadFile(strings.TrimPrefix(s, "@"))
		if err != nil {
			return nil, fmt.Errorf("read --data file: %w", err)
		}
		s = string(raw)
	}
	if strings.HasPrefix(strings.TrimSpace(s), "{") {
		var out map[string]any
		if err := json.Unmarshal([]byte(s), &out); err != nil {
			return nil, fmt.Errorf("parse --data JSON: %w", err)
		}
		return out, nil
	}
	// k=v fallback (single pair).
	if i := strings.Index(s, "="); i > 0 {
		return map[string]any{s[:i]: s[i+1:]}, nil
	}
	return nil, fmt.Errorf("--data must be JSON, @file, or key=value")
}

// ── entries ──────────────────────────────────────────────────────────────────

func runLedgerEntries(args []string) error {
	fs := flag.NewFlagSet("ledger entries", flag.ContinueOnError)
	since := fs.Int64("since", 0, "Lower bound on seq (inclusive)")
	limit := fs.Int("limit", 50, "Maximum entries to return")
	eventType := fs.String("type", "", "Filter to a single event type (e.g. sign)")
	asJSON := fs.Bool("json", false, "Machine-readable JSON output")
	api := registerCommonAPIFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	cl, err := api.client()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	entries, err := cl.ListLedgerEntries(ctx, *since, *limit, *eventType)
	if err != nil {
		return err
	}
	if *asJSON {
		return jsonStdout(entries)
	}
	if len(entries) == 0 {
		fmt.Println(ui.Dim("No ledger entries."))
		return nil
	}
	fmt.Printf("%s  %s  %s  %s\n",
		ui.Dim(pad("SEQ", 6)),
		ui.Dim(pad("EVENT", 24)),
		ui.Dim(pad("CREATED", 22)),
		ui.Dim("SUBJECT"),
	)
	for _, e := range entries {
		subj := ""
		if e.SubjectID != nil {
			subj = *e.SubjectID
		}
		fmt.Printf("%s  %s  %s  %s\n",
			pad(fmt.Sprintf("%d", e.Seq), 6),
			pad(e.EventType, 24),
			pad(e.CreatedAt, 22),
			subj,
		)
	}
	return nil
}

// ── append ───────────────────────────────────────────────────────────────────

func runLedgerAppend(args []string) error {
	fs := flag.NewFlagSet("ledger append", flag.ContinueOnError)
	name := fs.String("name", "", "Event type / name (required)")
	message := fs.String("message", "", "Optional human-readable message")
	subjectID := fs.String("subject", "", "Optional subject ID")
	data := fs.String("data", "", "Optional JSON object, @file, or key=value")
	asJSON := fs.Bool("json", false, "Print full result as JSON")
	api := registerCommonAPIFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *name == "" {
		return fmt.Errorf("--name is required")
	}
	parsedData, err := resolveDataFlag(*data)
	if err != nil {
		return err
	}
	body := map[string]any{"name": *name}
	if *message != "" {
		body["message"] = *message
	}
	if *subjectID != "" {
		body["subjectId"] = *subjectID
	}
	if parsedData != nil {
		body["data"] = parsedData
	}

	cl, err := api.client()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	entry, err := cl.AppendLedgerEntry(ctx, body)
	if err != nil {
		return err
	}
	if *asJSON {
		return jsonStdout(entry)
	}
	fmt.Printf("%s appended ledger entry seq=%d type=%s id=%s\n",
		ui.Green("✓"), entry.Seq, entry.EventType, entry.ID)
	return nil
}

// ── checkpoints ──────────────────────────────────────────────────────────────

func runLedgerCheckpoints(args []string) error {
	fs := flag.NewFlagSet("ledger checkpoints", flag.ContinueOnError)
	limit := fs.Int("limit", 20, "Maximum checkpoints to return")
	asJSON := fs.Bool("json", false, "Machine-readable JSON output")
	latest := fs.Bool("latest", false, "Just fetch the latest checkpoint")
	api := registerCommonAPIFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	cl, err := api.client()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	if *latest {
		cp, err := cl.LatestCheckpoint(ctx)
		if err != nil {
			return err
		}
		if cp == nil {
			fmt.Println(ui.Dim("No checkpoints yet — run `postq ledger seal`."))
			return nil
		}
		if *asJSON {
			return jsonStdout(cp)
		}
		printCheckpoint(*cp)
		return nil
	}

	cps, err := cl.ListCheckpoints(ctx, *limit)
	if err != nil {
		return err
	}
	if *asJSON {
		return jsonStdout(cps)
	}
	if len(cps) == 0 {
		fmt.Println(ui.Dim("No checkpoints yet — run `postq ledger seal`."))
		return nil
	}
	fmt.Printf("%s  %s  %s  %s\n",
		ui.Dim(pad("SEQ", 6)),
		ui.Dim(pad("ENTRIES", 8)),
		ui.Dim(pad("SIGNED", 22)),
		ui.Dim("MERKLE ROOT"),
	)
	for _, c := range cps {
		fmt.Printf("%s  %s  %s  %s\n",
			pad(fmt.Sprintf("%d", c.Seq), 6),
			pad(fmt.Sprintf("%d", c.EntriesCount), 8),
			pad(c.SignedAt, 22),
			truncMid(c.MerkleRoot, 32),
		)
	}
	return nil
}

func printCheckpoint(c hybridsign.LedgerCheckpoint) {
	fmt.Printf("seq:           %d\n", c.Seq)
	fmt.Printf("entries:       %d\n", c.EntriesCount)
	fmt.Printf("signed:        %s\n", c.SignedAt)
	fmt.Printf("signing key:   %s\n", c.SigningKeyID)
	fmt.Printf("merkle root:   %s\n", c.MerkleRoot)
	if c.Algorithm != "" {
		fmt.Printf("algorithm:     %s\n", c.Algorithm)
	}
}

// ── seal ─────────────────────────────────────────────────────────────────────

func runLedgerSeal(args []string) error {
	fs := flag.NewFlagSet("ledger seal", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "Print full result as JSON")
	api := registerCommonAPIFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	cl, err := api.client()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	res, err := cl.SealLedger(ctx)
	if err != nil {
		return err
	}
	if *asJSON {
		return jsonStdout(res)
	}
	if !res.Sealed {
		fmt.Printf("%s ledger already up-to-date (no new entries to seal)\n", ui.Yellow("•"))
		return nil
	}
	fmt.Printf("%s sealed %d entr%s\n",
		ui.Green("✓"), res.EntriesCovered, ies(int(res.EntriesCovered)))
	if res.Checkpoint != nil {
		printCheckpoint(*res.Checkpoint)
	}
	return nil
}

func ies(n int) string {
	if n == 1 {
		return "y"
	}
	return "ies"
}

// ── proof ────────────────────────────────────────────────────────────────────

func runLedgerProof(args []string) error {
	fs := flag.NewFlagSet("ledger proof", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "Print full result as JSON")
	api := registerCommonAPIFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	rest := fs.Args()
	if len(rest) != 1 {
		return fmt.Errorf("usage: postq ledger proof <entryId>")
	}
	cl, err := api.client()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	p, err := cl.LedgerProof(ctx, rest[0])
	if err != nil {
		return err
	}
	if *asJSON {
		return jsonStdout(p)
	}
	fmt.Printf("entry id:       %s\n", p.EntryID)
	fmt.Printf("seq:            %d\n", p.Seq)
	fmt.Printf("leaf hash:      %s\n", p.LeafHash)
	fmt.Printf("merkle path:    %d sibling hash%s\n", len(p.MerklePath), pluralEs(len(p.MerklePath)))
	for i, h := range p.MerklePath {
		fmt.Printf("  [%d] %s\n", i, h)
	}
	fmt.Printf("checkpoint seq: %d\n", p.Checkpoint.Seq)
	fmt.Printf("merkle root:    %s\n", p.Checkpoint.MerkleRoot)
	return nil
}

func pluralEs(n int) string {
	if n == 1 {
		return ""
	}
	return "es"
}

// ── bundle ───────────────────────────────────────────────────────────────────

func runLedgerBundle(args []string) error {
	fs := flag.NewFlagSet("ledger bundle", flag.ContinueOnError)
	out := fs.String("out", "", "Write bundle to this file (default: stdout)")
	api := registerCommonAPIFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	cl, err := api.client()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	raw, err := cl.LedgerBundle(ctx)
	if err != nil {
		return err
	}
	if *out == "" || *out == "-" {
		_, err = os.Stdout.Write(append(raw, '\n'))
		return err
	}
	if err := os.WriteFile(*out, raw, 0o644); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "%s wrote %d bytes to %s\n", ui.Green("✓"), len(raw), *out)
	fmt.Fprintf(os.Stderr, "%s verify offline: postq ledger verify %s\n", ui.Dim("›"), *out)
	return nil
}

// truncMid abbreviates a long string with an ellipsis in the middle.
func truncMid(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	keep := (maxLen - 1) / 2
	return s[:keep] + "…" + s[len(s)-keep:]
}
