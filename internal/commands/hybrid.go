// Hybrid signing subcommands: `postq sign`, `postq verify`, and
// `postq keys {create,list,get,revoke}`.
//
// All four are thin wrappers over the PostQ REST API — the CLI never
// holds private key material. This keeps us within the stdlib-only
// constraint (no Go ML-DSA implementation needed in the binary).
//
// Exit codes:
//   0  success
//   1  unexpected error
//   2  verify failed (signature did not validate) — use as a CI gate
package commands

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/postqdev/postq-cli/internal/config"
	"github.com/postqdev/postq-cli/internal/hybridsign"
	"github.com/postqdev/postq-cli/internal/ui"
)

// stdinSentinel is the conventional value meaning "read from stdin".
const stdinSentinel = "-"

// ── dispatch ─────────────────────────────────────────────────────────────────

func runSign(args []string, build BuildInfo) error {
	fs := flag.NewFlagSet("sign", flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprintln(fs.Output(), "Usage: postq sign --key <id> --in <file|-> [--out <file>] [--json]")
		fs.PrintDefaults()
	}
	keyID := fs.String("key", "", "Hybrid key ID (required)")
	in := fs.String("in", "", "Path to payload file, or '-' for stdin (required)")
	out := fs.String("out", "", "Write composite signature to this file (default: stdout)")
	asJSON := fs.Bool("json", false, "Print full result as JSON instead of just the signature")
	apiKey := fs.String("api-key", "", "Override saved API key")
	endpoint := fs.String("api-endpoint", "", "Override saved API endpoint")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *keyID == "" || *in == "" {
		fs.Usage()
		return fmt.Errorf("--key and --in are required")
	}

	payload, err := readInput(*in)
	if err != nil {
		return err
	}

	cl, err := newHybridClient(*endpoint, *apiKey, build)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	res, err := cl.Sign(ctx, *keyID, payload)
	if err != nil {
		return err
	}

	if *asJSON {
		return jsonStdout(res)
	}

	// Write just the signature to --out / stdout, plus a one-line summary on stderr.
	sig := []byte(res.Signature + "\n")
	if *out == "" || *out == stdinSentinel {
		_, err = os.Stdout.Write(sig)
	} else {
		err = os.WriteFile(*out, sig, 0o644)
	}
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr,
		"%s signed %d byte%s with %s (%s)\n",
		ui.Green("✓"),
		res.PayloadSize, plural(res.PayloadSize),
		res.Algorithm, shortID(res.KeyID),
	)
	return nil
}

func runVerify(args []string, build BuildInfo) error {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprintln(fs.Output(), "Usage: postq verify --key <id> --in <file|-> --sig <file|-> [--json]")
		fs.PrintDefaults()
	}
	keyID := fs.String("key", "", "Hybrid key ID (or use --public-key)")
	pubKey := fs.String("public-key", "", "Composite public key JSON (string) or @file path")
	in := fs.String("in", "", "Path to original payload, or '-' for stdin (required)")
	sigPath := fs.String("sig", "", "Path to signature file, or '-' for stdin (required)")
	asJSON := fs.Bool("json", false, "Print full result as JSON")
	apiKey := fs.String("api-key", "", "Override saved API key")
	endpoint := fs.String("api-endpoint", "", "Override saved API endpoint")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *in == "" || *sigPath == "" {
		fs.Usage()
		return fmt.Errorf("--in and --sig are required")
	}
	if *keyID == "" && *pubKey == "" {
		fs.Usage()
		return fmt.Errorf("either --key or --public-key is required")
	}
	if *in == stdinSentinel && *sigPath == stdinSentinel {
		return fmt.Errorf("only one of --in / --sig can be '-'")
	}

	payload, err := readInput(*in)
	if err != nil {
		return err
	}
	sigBytes, err := readInput(*sigPath)
	if err != nil {
		return err
	}
	signature := strings.TrimSpace(string(sigBytes))

	pubKeyValue, err := resolveAtFile(*pubKey)
	if err != nil {
		return err
	}

	cl, err := newHybridClient(*endpoint, *apiKey, build)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	res, err := cl.Verify(ctx, *keyID, pubKeyValue, payload, signature)
	if err != nil {
		return err
	}

	if *asJSON {
		if encErr := jsonStdout(res); encErr != nil {
			return encErr
		}
	} else {
		printVerifyResult(res)
	}

	if !res.OK {
		exitOrReturn(2)
		return fmt.Errorf("signature did not verify")
	}
	return nil
}

func runKeys(args []string, build BuildInfo) error {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" {
		printKeysHelp()
		return nil
	}
	switch args[0] {
	case "create":
		return runKeysCreate(args[1:], build)
	case "list", "ls":
		return runKeysList(args[1:], build)
	case "get", "show":
		return runKeysGet(args[1:], build)
	case "revoke", "delete", "rm":
		return runKeysRevoke(args[1:], build)
	default:
		printKeysHelp()
		return fmt.Errorf("unknown keys subcommand: %s", args[0])
	}
}

func runKeysCreate(args []string, build BuildInfo) error {
	fs := flag.NewFlagSet("keys create", flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprintln(fs.Output(), "Usage: postq keys create --name <label> [--algorithm mldsa65+ed25519] [--json]")
		fs.PrintDefaults()
	}
	name := fs.String("name", "", "Human-readable key label (required)")
	algorithm := fs.String("algorithm", "mldsa65+ed25519", "Composite algorithm")
	asJSON := fs.Bool("json", false, "Print full result as JSON")
	apiKey := fs.String("api-key", "", "Override saved API key")
	endpoint := fs.String("api-endpoint", "", "Override saved API endpoint")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *name == "" {
		fs.Usage()
		return fmt.Errorf("--name is required")
	}

	cl, err := newHybridClient(*endpoint, *apiKey, build)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	key, err := cl.CreateKey(ctx, *name, *algorithm)
	if err != nil {
		return err
	}

	if *asJSON {
		return jsonStdout(key)
	}
	fmt.Printf("%s created hybrid signing key\n", ui.Green("✓"))
	fmt.Printf("  id:        %s\n", key.ID)
	fmt.Printf("  name:      %s\n", key.Name)
	fmt.Printf("  algorithm: %s\n", key.Algorithm)
	fmt.Printf("  created:   %s\n", key.CreatedAt)
	fmt.Println()
	fmt.Println(ui.Dim("Public key (distribute to verifiers — keep secure):"))
	fmt.Println(key.PublicKey)
	return nil
}

func runKeysList(args []string, build BuildInfo) error {
	fs := flag.NewFlagSet("keys list", flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprintln(fs.Output(), "Usage: postq keys list [--limit N] [--all] [--json]")
		fs.PrintDefaults()
	}
	limit := fs.Int("limit", 20, "Maximum keys to return")
	all := fs.Bool("all", false, "Include revoked keys")
	asJSON := fs.Bool("json", false, "Machine-readable JSON output")
	apiKey := fs.String("api-key", "", "Override saved API key")
	endpoint := fs.String("api-endpoint", "", "Override saved API endpoint")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cl, err := newHybridClient(*endpoint, *apiKey, build)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	keys, err := cl.ListKeys(ctx, *limit, *all)
	if err != nil {
		return err
	}

	if *asJSON {
		return jsonStdout(keys)
	}
	if len(keys) == 0 {
		fmt.Println(ui.Dim("No hybrid keys yet. Run `postq keys create --name …`."))
		return nil
	}

	fmt.Printf("%s  %s  %s  %s\n",
		ui.Dim(pad("ID", 38)),
		ui.Dim(pad("ALGORITHM", 18)),
		ui.Dim(pad("CREATED", 22)),
		ui.Dim("NAME"),
	)
	for _, k := range keys {
		status := ""
		if k.RevokedAt != nil {
			status = " " + ui.Yellow("(revoked)")
		}
		fmt.Printf("%s  %s  %s  %s%s\n",
			pad(k.ID, 38),
			pad(k.Algorithm, 18),
			pad(k.CreatedAt, 22),
			k.Name,
			status,
		)
	}
	return nil
}

func runKeysGet(args []string, build BuildInfo) error {
	fs := flag.NewFlagSet("keys get", flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprintln(fs.Output(), "Usage: postq keys get <id> [--json]")
		fs.PrintDefaults()
	}
	asJSON := fs.Bool("json", false, "Machine-readable JSON output")
	apiKey := fs.String("api-key", "", "Override saved API key")
	endpoint := fs.String("api-endpoint", "", "Override saved API endpoint")
	if err := fs.Parse(args); err != nil {
		return err
	}
	rest := fs.Args()
	if len(rest) != 1 {
		fs.Usage()
		return fmt.Errorf("exactly one key id is required")
	}

	cl, err := newHybridClient(*endpoint, *apiKey, build)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	key, err := cl.GetKey(ctx, rest[0])
	if err != nil {
		return err
	}
	if *asJSON {
		return jsonStdout(key)
	}
	fmt.Printf("id:        %s\n", key.ID)
	fmt.Printf("name:      %s\n", key.Name)
	fmt.Printf("algorithm: %s\n", key.Algorithm)
	fmt.Printf("created:   %s\n", key.CreatedAt)
	if key.RevokedAt != nil {
		fmt.Printf("revoked:   %s\n", *key.RevokedAt)
	}
	if key.LastUsedAt != nil {
		fmt.Printf("last used: %s\n", *key.LastUsedAt)
	}
	fmt.Println()
	fmt.Println(ui.Dim("Public key:"))
	fmt.Println(key.PublicKey)
	return nil
}

func runKeysRevoke(args []string, build BuildInfo) error {
	fs := flag.NewFlagSet("keys revoke", flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprintln(fs.Output(), "Usage: postq keys revoke <id>")
		fs.PrintDefaults()
	}
	apiKey := fs.String("api-key", "", "Override saved API key")
	endpoint := fs.String("api-endpoint", "", "Override saved API endpoint")
	if err := fs.Parse(args); err != nil {
		return err
	}
	rest := fs.Args()
	if len(rest) != 1 {
		fs.Usage()
		return fmt.Errorf("exactly one key id is required")
	}

	cl, err := newHybridClient(*endpoint, *apiKey, build)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	if err := cl.RevokeKey(ctx, rest[0]); err != nil {
		return err
	}
	fmt.Printf("%s revoked %s\n", ui.Green("✓"), rest[0])
	return nil
}

// ── help ─────────────────────────────────────────────────────────────────────

func printKeysHelp() {
	fmt.Println(ui.Bold("postq keys") + " — manage PostQ-managed hybrid signing keys")
	fmt.Println()
	fmt.Println(ui.Bold("SUBCOMMANDS"))
	fmt.Println("  create   Mint a new composite (ML-DSA + Ed25519) signing key")
	fmt.Println("  list     List your org's hybrid keys")
	fmt.Println("  get      Show one key with its composite public key")
	fmt.Println("  revoke   Revoke a key (existing signatures still verify)")
	fmt.Println()
	fmt.Println(ui.Bold("EXAMPLES"))
	fmt.Println("  postq keys create --name release-signing")
	fmt.Println("  postq keys list")
	fmt.Println("  postq keys get <id>")
	fmt.Println("  postq keys revoke <id>")
}

// ── helpers ──────────────────────────────────────────────────────────────────

func newHybridClient(endpoint, apiKey string, build BuildInfo) (*hybridsign.Client, error) {
	cfg, err := config.Resolve(endpoint, apiKey)
	if err != nil {
		return nil, err
	}
	if cfg.APIKey == "" {
		return nil, fmt.Errorf("not authenticated — run `postq auth login --api-key …`")
	}
	return hybridsign.New(cfg.APIEndpoint, cfg.APIKey, build.userAgent()), nil
}

func readInput(path string) ([]byte, error) {
	if path == stdinSentinel {
		return io.ReadAll(os.Stdin)
	}
	return os.ReadFile(path)
}

// resolveAtFile lets --public-key accept either an inline JSON string or
// `@/path/to/key.json` to read from disk.
func resolveAtFile(s string) (string, error) {
	if s == "" || !strings.HasPrefix(s, "@") {
		return s, nil
	}
	b, err := os.ReadFile(strings.TrimPrefix(s, "@"))
	if err != nil {
		return "", fmt.Errorf("read public key file: %w", err)
	}
	return strings.TrimSpace(string(b)), nil
}

func jsonStdout(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

func shortID(id string) string {
	if len(id) <= 8 {
		return id
	}
	return id[:8]
}

func printVerifyResult(r *hybridsign.VerifyResult) {
	if r.OK {
		fmt.Printf("%s signature verified (%s)\n", ui.Green("✓"), r.Algorithm)
	} else {
		fmt.Printf("%s signature did NOT verify\n", ui.Red("✗"))
	}
	classical := boolGlyph(r.ClassicalOK)
	pq := boolGlyph(r.PqOK)
	fmt.Printf("  classical (Ed25519): %s\n", classical)
	fmt.Printf("  post-quantum (ML-DSA): %s\n", pq)
}

func boolGlyph(b bool) string {
	if b {
		return ui.Green("ok")
	}
	return ui.Red("FAIL")
}
