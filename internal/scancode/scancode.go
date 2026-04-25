// Package scancode runs cheap, deterministic crypto-misuse detectors over a
// local source tree. Each detector is a small regex paired with a severity
// and remediation hint.
//
// This is an MVP — the rule pack is intentionally small and high-signal.
// The wire format mirrors internal/report so findings can be uploaded to
// the PostQ API alongside URL / cloud scan results.
package scancode

import (
	"bufio"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/postqdev/postq-cli/internal/report"
)

// Finding is one detector hit, expressed in a way the rest of the CLI
// (report.Submission, the API, the dashboard) already understands.
type Finding struct {
	report.Finding

	RuleID       string `json:"ruleId"`
	File         string `json:"file"`
	Line         int    `json:"line"`
	Snippet      string `json:"snippet,omitempty"`
	DiscoveredBy string `json:"discoveredBy,omitempty"`
}

// Result is what the CLI prints + uploads.
type Result struct {
	Root         string           `json:"root"`
	FilesScanned int              `json:"filesScanned"`
	Findings     []Finding        `json:"findings"`
	RiskScore    int              `json:"riskScore"`
	RiskLevel    report.RiskLevel `json:"riskLevel"`
}

// Options tunes a code scan.
type Options struct {
	MaxFileBytes int64 // skip files larger than this (default 1 MiB)
}

// rule is one regex-based detector.
type rule struct {
	id           string
	title        string
	desc         string
	severity     report.Severity
	remediation  string
	algorithm    string
	discoveredBy string

	pattern    *regexp.Regexp
	substring  string
	extensions []string // restrict to these extensions; empty = all
}

// rulePack: the v1 detector set. Lean and high-signal on purpose.
var rulePack = []rule{
	{
		id:           "POSTQ-CODE-001",
		title:        "Math.random() used in security-sensitive context",
		desc:         "Math.random() is not a CSPRNG. If this value is used as a token, key, IV, or nonce it is trivially predictable.",
		severity:     report.SeverityHigh,
		remediation:  "Use crypto.randomBytes(n).toString('base64url') or crypto.getRandomValues() in browsers.",
		algorithm:    "Math.random()",
		discoveredBy: "anthropic-research",
		pattern:      regexp.MustCompile(`Math\.random\s*\(`),
		extensions:   []string{".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs"},
	},
	{
		id:           "POSTQ-CODE-002",
		title:        "MD5 used for hashing",
		desc:         "MD5 is collision-broken. Using it for signatures, integrity checks, or password hashing is unsafe.",
		severity:     report.SeverityHigh,
		remediation:  "Use SHA-256 (or BLAKE2/3 for non-signing). For passwords use bcrypt / argon2.",
		algorithm:    "MD5",
		discoveredBy: "core",
		pattern:      regexp.MustCompile(`(?i)(createHash\(\s*['"]md5|hashlib\.md5|md5\.New|MD5\.Create|MessageDigest\.getInstance\(\s*"MD5)`),
	},
	{
		id:           "POSTQ-CODE-003",
		title:        "SHA-1 used for signing or HMAC",
		desc:         "SHA-1 is collision-broken (SHAttered, 2017). Do not use for signatures, HMAC keys, or cert chains.",
		severity:     report.SeverityMedium,
		remediation:  "Use SHA-256 or stronger. For HMAC: HMAC-SHA-256.",
		algorithm:    "SHA-1",
		discoveredBy: "core",
		pattern:      regexp.MustCompile(`(?i)(createHash\(\s*['"]sha-?1|hashlib\.sha1|sha1\.New|SHA1\.Create|"SHA-?1")`),
	},
	{
		id:           "POSTQ-CODE-004",
		title:        "JWT verification accepts 'none' algorithm",
		desc:         "Allowing alg:none lets an attacker forge tokens by stripping the signature.",
		severity:     report.SeverityCritical,
		remediation:  "Always pass an explicit algorithms allow-list to verify(): { algorithms: ['RS256'] } or similar.",
		algorithm:    "JWT alg:none",
		discoveredBy: "anthropic-research",
		pattern:      regexp.MustCompile(`(?i)algorithms\s*:\s*\[[^\]]*['"]none['"]`),
	},
	{
		id:           "POSTQ-CODE-005",
		title:        "TLS certificate verification disabled",
		desc:         "Disabling cert verification breaks the trust chain — any attacker on-path can MITM the connection.",
		severity:     report.SeverityCritical,
		remediation:  "Remove this flag. If you need a self-signed cert in dev, pin it explicitly instead.",
		algorithm:    "TLS",
		discoveredBy: "core",
		pattern:      regexp.MustCompile(`(rejectUnauthorized\s*:\s*false|InsecureSkipVerify\s*:\s*true|verify\s*=\s*False|CURLOPT_SSL_VERIFYPEER\s*,\s*0)`),
	},
	{
		id:           "POSTQ-CODE-006",
		title:        "AES used in ECB mode",
		desc:         "ECB leaks structure — identical plaintext blocks produce identical ciphertext blocks.",
		severity:     report.SeverityHigh,
		remediation:  "Use AES-GCM (preferred — authenticated). If you need CBC, pair it with HMAC and a random IV.",
		algorithm:    "AES-ECB",
		discoveredBy: "core",
		pattern:      regexp.MustCompile(`(?i)("AES/ECB|aes-\d+-ecb|MODE_ECB|AesEcb)`),
	},
	{
		id:           "POSTQ-CODE-007",
		title:        "Hardcoded RSA private key",
		desc:         "Private keys committed to source can be extracted by anyone with repo access — past, present, or via leaked clones.",
		severity:     report.SeverityCritical,
		remediation:  "Move to a KMS / secret manager. Rotate the key — assume it is already compromised.",
		algorithm:    "key material",
		discoveredBy: "core",
		substring:    "BEGIN RSA PRIVATE KEY",
	},
	{
		id:           "POSTQ-CODE-008",
		title:        "Hardcoded EC private key",
		desc:         "EC private keys committed to source can be extracted by anyone with repo access.",
		severity:     report.SeverityCritical,
		remediation:  "Move to a KMS / secret manager. Rotate the key — assume it is already compromised.",
		algorithm:    "key material",
		discoveredBy: "core",
		substring:    "BEGIN EC PRIVATE KEY",
	},
	{
		id:           "POSTQ-CODE-009",
		title:        "PKCS#1 v1.5 RSA padding",
		desc:         "PKCS#1 v1.5 padding is vulnerable to Bleichenbacher / Manger oracle attacks when used for encryption.",
		severity:     report.SeverityMedium,
		remediation:  "Use OAEP for encryption (RSA-OAEP-256). v1.5 is acceptable for signatures only.",
		algorithm:    "RSA-PKCS1v15",
		discoveredBy: "core",
		pattern:      regexp.MustCompile(`(?i)(RSA_PKCS1_PADDING|RSA-PKCS1V1_5|PKCS1v15)`),
	},
	{
		id:           "POSTQ-CODE-010",
		title:        "Classical-only signing (no PQ hybrid)",
		desc:         "This signing call uses a classical-only algorithm. Once a CRQC arrives, these signatures are forgeable.",
		severity:     report.SeverityLow,
		remediation:  "Migrate to a hybrid scheme (e.g. dilithium3+ed25519). See https://postq.dev/product/hybrid-signing",
		algorithm:    "classical signing",
		discoveredBy: "postq-research",
		pattern:      regexp.MustCompile(`(?i)(ed25519\.Sign|ecdsa\.SignASN1)`),
	},
}

var skipDirs = map[string]bool{
	"node_modules":  true,
	".git":          true,
	".next":         true,
	".turbo":        true,
	"dist":          true,
	"build":         true,
	"target":        true,
	"vendor":        true,
	".venv":         true,
	"venv":          true,
	"__pycache__":   true,
	".pytest_cache": true,
	"out":           true,
	"coverage":      true,
}

// Run walks root and returns all findings.
func Run(root string, opt Options) (*Result, error) {
	if opt.MaxFileBytes == 0 {
		opt.MaxFileBytes = 1 << 20
	}
	info, err := os.Stat(root)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, errors.New("path is not a directory")
	}

	res := &Result{Root: root}

	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return nil
		}
		if d.IsDir() {
			if skipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		ext := strings.ToLower(filepath.Ext(d.Name()))
		if !isSourceExt(ext) {
			return nil
		}
		fi, err := d.Info()
		if err != nil || fi.Size() > opt.MaxFileBytes {
			return nil
		}
		res.FilesScanned++
		findings := scanFile(path, ext)
		res.Findings = append(res.Findings, findings...)
		return nil
	})
	if err != nil {
		return nil, err
	}

	res.RiskScore, res.RiskLevel = scoreFindings(res.Findings)
	return res, nil
}

func scanFile(path, ext string) []Finding {
	f, err := os.Open(path) //nolint:gosec
	if err != nil {
		return nil
	}
	defer f.Close()

	var out []Finding
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := sc.Text()
		if len(line) > 4000 {
			continue
		}
		for _, r := range rulePack {
			if len(r.extensions) > 0 && !contains(r.extensions, ext) {
				continue
			}
			match := false
			if r.pattern != nil {
				match = r.pattern.MatchString(line)
			} else if r.substring != "" {
				match = strings.Contains(line, r.substring)
			}
			if !match {
				continue
			}
			out = append(out, Finding{
				Finding: report.Finding{
					Severity:    r.severity,
					Title:       r.title,
					Description: r.desc,
					Algorithm:   r.algorithm,
					Remediation: r.remediation,
					Vulnerable:  true,
					Location:    fmt.Sprintf("%s:%d", path, lineNo),
				},
				RuleID:       r.id,
				File:         path,
				Line:         lineNo,
				Snippet:      strings.TrimSpace(line),
				DiscoveredBy: r.discoveredBy,
			})
		}
	}
	return out
}

func scoreFindings(findings []Finding) (int, report.RiskLevel) {
	if len(findings) == 0 {
		return 0, report.RiskSafe
	}
	score := 0
	worst := report.RiskSafe
	for _, f := range findings {
		switch f.Severity {
		case report.SeverityCritical:
			score += 30
			worst = report.RiskCritical
		case report.SeverityHigh:
			score += 18
			if worst != report.RiskCritical {
				worst = report.RiskHigh
			}
		case report.SeverityMedium:
			score += 8
			if worst != report.RiskCritical && worst != report.RiskHigh {
				worst = report.RiskMedium
			}
		case report.SeverityLow:
			score += 3
			if worst == report.RiskSafe {
				worst = report.RiskLow
			}
		}
	}
	if score > 100 {
		score = 100
	}
	return score, worst
}

func isSourceExt(ext string) bool {
	switch ext {
	case ".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs",
		".py", ".pyi",
		".go",
		".java", ".kt", ".scala",
		".rb",
		".rs",
		".cs",
		".php",
		".c", ".cc", ".cpp", ".h", ".hpp",
		".swift",
		".pem", ".key":
		return true
	}
	return false
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}
