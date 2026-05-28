// Attestation subcommands: `postq attest verify`.
//
// `postq attest verify` re-checks an attestation document returned by
// /v1/sign against a locally-pinned policy, without trusting the API's
// verdict. The verifier is pure-Go (crypto/ed25519 + crypto/sha256).
//
// Exit codes:
//
//	0  attestation passes
//	1  unexpected error (bad flags, unreadable file, etc.)
//	2  attestation rejected (use as a CI gate)
package commands

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/postqdev/postq-cli/internal/attest"
	"github.com/postqdev/postq-cli/internal/ui"
)

func runAttest(args []string, build BuildInfo) error {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" {
		printAttestHelp()
		return nil
	}
	switch args[0] {
	case "verify":
		return runAttestVerify(args[1:], build)
	default:
		printAttestHelp()
		return fmt.Errorf("unknown attest subcommand: %s", args[0])
	}
}

func printAttestHelp() {
	fmt.Println(ui.Bold("postq attest") + " — verify enclave attestation documents")
	fmt.Println()
	fmt.Println(ui.Bold("SUBCOMMANDS"))
	fmt.Println("  " + ui.Cyan("verify") + "   Re-check an attestation doc against a pinned policy")
	fmt.Println()
	fmt.Println(ui.Bold("EXAMPLES"))
	fmt.Println("  # Re-verify a sign response (writes pass/fail to stderr, exit 0 / 2):")
	fmt.Println("  postq sign --key <id> --in artifact --json > sig.json")
	fmt.Println("  postq attest verify \\")
	fmt.Println("    --sign-result sig.json \\")
	fmt.Println("    --payload artifact \\")
	fmt.Println("    --policy ./trusted-policy.json")
	fmt.Println()
	fmt.Println("  # Verify a standalone doc with explicit vendor + policy:")
	fmt.Println("  postq attest verify --doc-b64 \"$DOC\" --vendor mock --policy ./policy.json")
}

func runAttestVerify(args []string, _ BuildInfo) error {
	fs := flag.NewFlagSet("attest verify", flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprintln(fs.Output(), "Usage: postq attest verify --policy <file> "+
			"[--sign-result <file>|--doc-b64 <b64> --vendor <name>] [--payload <file>] [--json]")
		fs.PrintDefaults()
	}
	policyPath := fs.String("policy", "", "Path to attestation policy JSON (required)")
	signResultPath := fs.String("sign-result", "", "Path to a /v1/sign JSON response (sets doc, vendor, expected hashes)")
	docB64 := fs.String("doc-b64", "", "Raw attestation doc, base64 (mutually exclusive with --sign-result)")
	vendor := fs.String("vendor", "", "Attestation vendor (required with --doc-b64)")
	payloadPath := fs.String("payload", "", "Original signed payload (binds claims.payloadSha256)")
	allowStale := fs.Bool("allow-stale", false, "Skip freshness check (audit/replay mode)")
	asJSON := fs.Bool("json", false, "Print result as JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *policyPath == "" {
		fs.Usage()
		return fmt.Errorf("--policy is required")
	}
	if *signResultPath == "" && *docB64 == "" {
		fs.Usage()
		return fmt.Errorf("provide --sign-result or --doc-b64")
	}
	if *signResultPath != "" && *docB64 != "" {
		return fmt.Errorf("--sign-result and --doc-b64 are mutually exclusive")
	}

	// 1) Load policy.
	polBytes, err := os.ReadFile(*policyPath)
	if err != nil {
		return fmt.Errorf("read policy: %w", err)
	}
	var policy attest.Policy
	if err := json.Unmarshal(polBytes, &policy); err != nil {
		return fmt.Errorf("parse policy: %w", err)
	}
	if policy.Vendor == "" {
		return fmt.Errorf("policy.vendor missing")
	}
	if policy.MaxDocAgeSeconds <= 0 {
		policy.MaxDocAgeSeconds = 300
	}

	in := attest.Input{
		Policy:           policy,
		EnforceFreshness: !*allowStale,
	}

	// 2) Source the doc + bindings.
	if *signResultPath != "" {
		sr, err := loadSignResult(*signResultPath)
		if err != nil {
			return err
		}
		if sr.Attestation == nil {
			return fmt.Errorf("sign-result has no attestation block (key not bound to a policy?)")
		}
		in.DocB64 = sr.Attestation.DocB64
		in.Vendor = attest.Vendor(sr.Attestation.Vendor)
		// Bind sigSha256 to the composite signature returned by the API
		// (we hash the PQ half from the envelope; see API verifier).
		if sigSha, perr := pqSigSha256FromEnvelope(sr.Signature); perr == nil {
			in.ExpectedSigSha256 = sigSha
		}
	} else {
		in.DocB64 = *docB64
		if *vendor == "" {
			return fmt.Errorf("--vendor is required with --doc-b64")
		}
		in.Vendor = attest.Vendor(*vendor)
	}

	// 3) Bind payload hash if a payload was provided.
	if *payloadPath != "" {
		pb, err := readInput(*payloadPath)
		if err != nil {
			return err
		}
		in.ExpectedPayloadSha256 = attest.HexSha256(pb)
	}

	// 4) Verify.
	res, err := attest.Verify(in)
	if err != nil {
		return err
	}

	if *asJSON {
		if err := jsonStdout(res); err != nil {
			return err
		}
	} else {
		printAttestResult(res)
	}

	if !res.OK {
		exitOrReturn(2)
		return fmt.Errorf("attestation rejected: %s", res.Reason)
	}
	return nil
}

// loadSignResult reads the JSON output of `postq sign --json`.
func loadSignResult(path string) (*hybridSignJSON, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read sign-result: %w", err)
	}
	var sr hybridSignJSON
	if err := json.Unmarshal(raw, &sr); err != nil {
		return nil, fmt.Errorf("parse sign-result: %w", err)
	}
	return &sr, nil
}

// hybridSignJSON mirrors the fields of hybridsign.SignResult we care about
// here. We deliberately re-declare a local shape so this file has no
// dependency on the apiclient package (keeps the verifier self-contained).
type hybridSignJSON struct {
	Signature   string `json:"signature"`
	Attestation *struct {
		Vendor    string `json:"vendor"`
		ImageHash string `json:"imageHash"`
		Counter   int    `json:"counter"`
		DocB64    string `json:"docB64"`
		Verdict   string `json:"verdict"`
		Reason    string `json:"reason,omitempty"`
	} `json:"attestation,omitempty"`
}

// pqSigSha256FromEnvelope decodes the composite signature envelope
// {"v":1,"alg":"…","classical":"<b64>","pq":"<b64>"} and returns the hex
// sha256 of the PQ half — which is what the API binds into claims.sigSha256.
func pqSigSha256FromEnvelope(b64 string) (string, error) {
	raw, err := base64decode(b64)
	if err != nil {
		return "", err
	}
	var env struct {
		PQ string `json:"pq"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		return "", err
	}
	pq, err := base64decode(env.PQ)
	if err != nil {
		return "", err
	}
	return attest.HexSha256(pq), nil
}

func printAttestResult(r attest.Result) {
	if r.OK {
		fmt.Fprintf(os.Stderr, "%s attestation %s\n", ui.Green("✓"), ui.Bold("PASS"))
	} else {
		fmt.Fprintf(os.Stderr, "%s attestation %s\n", ui.Red("✗"), ui.Bold("FAIL"))
	}
	fmt.Fprintf(os.Stderr, "  vendor:    %s\n", r.Vendor)
	if r.ImageHash != "" {
		fmt.Fprintf(os.Stderr, "  imageHash: %s\n", r.ImageHash)
	}
	if r.Counter != 0 {
		fmt.Fprintf(os.Stderr, "  counter:   %d\n", r.Counter)
	}
	if r.Reason != "" {
		fmt.Fprintf(os.Stderr, "  reason:    %s\n", r.Reason)
	}
}

// base64decode accepts both standard and URL-safe base64, with or without
// padding. The composite signature envelope uses standard base64, but we
// stay liberal so this also handles any future raw-URL encoded payloads.
func base64decode(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	if b, err := base64.RawStdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	if b, err := base64.URLEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.RawURLEncoding.DecodeString(s)
}
