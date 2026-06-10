package scancode

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/postqdev/postq-cli/internal/report"
)

// writeTree creates a temp dir with the given files and returns its path.
func writeTree(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range files {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func ruleIDs(r *Result) map[string]int {
	m := map[string]int{}
	for _, f := range r.Findings {
		m[f.RuleID]++
	}
	return m
}

func TestDetectsMD5(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"a.py": "import hashlib\nh = hashlib.md5(b'x').hexdigest()\n",
	})
	res, err := Run(dir, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if ruleIDs(res)["POSTQ-CODE-002"] == 0 {
		t.Fatalf("expected MD5 finding, got %+v", res.Findings)
	}
}

func TestDetectsRSAKeygen(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"a.go": "package x\nimport \"crypto/rsa\"\nimport \"crypto/rand\"\nfunc f(){ _,_ = rsa.GenerateKey(rand.Reader, 2048) }\n",
		"b.py": "from cryptography.hazmat.primitives.asymmetric import rsa\nk = rsa.generate_private_key(public_exponent=65537, key_size=2048)\n",
	})
	res, err := Run(dir, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if got := ruleIDs(res)["POSTQ-CODE-011"]; got < 2 {
		t.Fatalf("expected RSA keygen flagged in both files, got %d: %+v", got, res.Findings)
	}
}

func TestDetectsECKeygen(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"a.go": "package x\nimport \"crypto/ecdsa\"\nimport \"crypto/elliptic\"\nimport \"crypto/rand\"\nfunc f(){ _,_ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader) }\n",
	})
	res, err := Run(dir, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if ruleIDs(res)["POSTQ-CODE-012"] == 0 {
		t.Fatalf("expected EC keygen finding, got %+v", res.Findings)
	}
}

func TestCleanTreeScoresZero(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"a.txt": "no crypto here, just text\n",
		"b.go":  "package x\nfunc Add(a, b int) int { return a + b }\n",
	})
	res, err := Run(dir, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if res.RiskScore != 0 || res.RiskLevel != report.RiskSafe {
		t.Fatalf("clean tree should score 0/safe, got %d/%s", res.RiskScore, res.RiskLevel)
	}
}

func TestSkipsVendorDirs(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"node_modules/dep/x.js": "const h = require('crypto').createHash('md5');\n",
		"src/app.js":            "console.log('clean');\n",
	})
	res, err := Run(dir, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if ruleIDs(res)["POSTQ-CODE-002"] != 0 {
		t.Fatal("should not scan inside node_modules")
	}
}
