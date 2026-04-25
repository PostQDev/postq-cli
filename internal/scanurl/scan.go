// Package scanurl performs a real TLS handshake against a host and reports
// quantum-vulnerable cipher suites, key exchange algorithms, and certificate
// signature algorithms.
package scanurl

import (
	"crypto/dsa" //nolint:staticcheck // we *want* to detect DSA usage in remote certs
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/postqdev/postq-cli/internal/report"
)

// Options tweaks scan behaviour.
type Options struct {
	Timeout            time.Duration
	InsecureSkipVerify bool
}

// Result is the aggregated TLS scan output.
type Result struct {
	Host        string
	Port        string
	Findings    []report.Finding
	Metadata    map[string]string
	RiskScore   int
	RiskLevel   report.RiskLevel
	DurationMS  int64
	HandshakeOK bool
}

// Scan opens a TLS connection to target (host[:port], with or without scheme),
// inspects the negotiated parameters and the certificate chain, and returns
// a report.
func Scan(target string, opts Options) (*Result, error) {
	if opts.Timeout == 0 {
		opts.Timeout = 10 * time.Second
	}

	host, port, err := normalizeTarget(target)
	if err != nil {
		return nil, err
	}

	start := time.Now()

	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: opts.Timeout},
		"tcp",
		net.JoinHostPort(host, port),
		&tls.Config{
			ServerName:         host,
			MinVersion:         tls.VersionTLS10,        // probe for legacy support
			InsecureSkipVerify: opts.InsecureSkipVerify, //nolint:gosec // user-controlled debugging flag
		},
	)
	if err != nil {
		return nil, fmt.Errorf("tls handshake failed: %w", err)
	}
	defer conn.Close()

	state := conn.ConnectionState()
	res := &Result{
		Host:        host,
		Port:        port,
		Metadata:    map[string]string{},
		HandshakeOK: true,
		DurationMS:  time.Since(start).Milliseconds(),
	}

	res.Metadata["TLS Version"] = tlsVersionName(state.Version)
	res.Metadata["Cipher Suite"] = tls.CipherSuiteName(state.CipherSuite)
	res.Metadata["Server Name"] = state.ServerName
	res.Metadata["Negotiated ALPN"] = state.NegotiatedProtocol

	// ── TLS version findings ────────────────────────────────────────────────
	switch {
	case state.Version <= tls.VersionTLS11:
		res.Findings = append(res.Findings, report.Finding{
			Severity:    report.SeverityHigh,
			Title:       "Legacy TLS version negotiated",
			Description: fmt.Sprintf("Server negotiated %s. Pre-TLS 1.2 versions only support broken ciphers (RC4, 3DES, CBC) and lack forward secrecy.", tlsVersionName(state.Version)),
			Location:    fmt.Sprintf("%s:%s — TLS handshake", host, port),
			Algorithm:   tlsVersionName(state.Version),
			Remediation: "Disable TLS 1.0/1.1 on the server. Configure to accept TLS 1.2+ (prefer TLS 1.3 only).",
			Vulnerable:  true,
		})
	case state.Version == tls.VersionTLS12:
		res.Findings = append(res.Findings, report.Finding{
			Severity:    report.SeverityLow,
			Title:       "TLS 1.2 negotiated (no PQ key exchange)",
			Description: "Server negotiated TLS 1.2. TLS 1.3 with X25519MLKEM768 is the path to post-quantum key exchange.",
			Location:    fmt.Sprintf("%s:%s — TLS handshake", host, port),
			Algorithm:   "TLS 1.2",
			Remediation: "Upgrade to TLS 1.3 and enable hybrid post-quantum key exchange (X25519MLKEM768).",
			Vulnerable:  false,
		})
	}

	// ── Certificate chain findings ──────────────────────────────────────────
	for i, cert := range state.PeerCertificates {
		role := "Leaf certificate"
		if i > 0 {
			role = fmt.Sprintf("Intermediate certificate #%d", i)
		}
		analyzeCert(cert, role, host, res)
	}
	if len(state.PeerCertificates) > 0 {
		leaf := state.PeerCertificates[0]
		res.Metadata["Cert Subject"] = leaf.Subject.CommonName
		if len(leaf.Issuer.Organization) > 0 {
			res.Metadata["Cert Issuer"] = leaf.Issuer.Organization[0]
		} else {
			res.Metadata["Cert Issuer"] = leaf.Issuer.CommonName
		}
		res.Metadata["Cert Expiry"] = leaf.NotAfter.UTC().Format("2006-01-02")
		days := int(time.Until(leaf.NotAfter).Hours() / 24)
		if days < 0 {
			res.Findings = append(res.Findings, report.Finding{
				Severity:    report.SeverityCritical,
				Title:       "Leaf certificate has expired",
				Description: fmt.Sprintf("Certificate expired %d days ago.", -days),
				Location:    leaf.Subject.CommonName,
				Remediation: "Renew the certificate immediately, ideally with a hybrid PQ-classical cert.",
				Vulnerable:  true,
			})
		} else if days < 14 {
			res.Findings = append(res.Findings, report.Finding{
				Severity:    report.SeverityMedium,
				Title:       "Leaf certificate expires soon",
				Description: fmt.Sprintf("Certificate expires in %d days.", days),
				Location:    leaf.Subject.CommonName,
				Remediation: "Schedule renewal. Consider switching to a NIST PQC algorithm (ML-DSA / SLH-DSA) at renewal.",
				Vulnerable:  false,
			})
		}
	}

	// Score = sum of severity weights, capped at 100
	res.RiskScore = computeScore(res.Findings)
	res.RiskLevel = report.ScoreToLevel(res.RiskScore)
	res.Metadata["Post-Quantum Ready"] = "No"
	return res, nil
}

func analyzeCert(cert *x509.Certificate, role, host string, res *Result) {
	// Public-key algorithm
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		bits := pub.Size() * 8
		sev := report.SeverityCritical
		if bits >= 4096 {
			sev = report.SeverityHigh // still quantum-broken, but classically strong
		}
		res.Findings = append(res.Findings, report.Finding{
			Severity:    sev,
			Title:       fmt.Sprintf("RSA-%d public key", bits),
			Description: "RSA is broken in polynomial time by Shor's algorithm on a sufficiently large quantum computer.",
			Location:    fmt.Sprintf("%s — %s", host, role),
			Algorithm:   fmt.Sprintf("RSA-%d", bits),
			Remediation: "Replace with ML-DSA (CRYSTALS-Dilithium) for signatures, or use ML-KEM-768 hybrid cert for key exchange.",
			Vulnerable:  true,
		})
	case *ecdsa.PublicKey:
		curve := curveName(pub.Curve)
		res.Findings = append(res.Findings, report.Finding{
			Severity:    report.SeverityCritical,
			Title:       fmt.Sprintf("ECDSA public key (%s)", curve),
			Description: "Elliptic-curve discrete log is broken in polynomial time by Shor's algorithm.",
			Location:    fmt.Sprintf("%s — %s", host, role),
			Algorithm:   "ECDSA-" + curve,
			Remediation: "Migrate to ML-DSA (CRYSTALS-Dilithium) for signatures.",
			Vulnerable:  true,
		})
	case *dsa.PublicKey:
		_ = pub
		res.Findings = append(res.Findings, report.Finding{
			Severity:    report.SeverityCritical,
			Title:       "DSA public key",
			Description: "DSA is quantum-vulnerable (Shor) and classically deprecated.",
			Location:    fmt.Sprintf("%s — %s", host, role),
			Algorithm:   "DSA",
			Remediation: "Replace with ML-DSA. DSA is deprecated by NIST.",
			Vulnerable:  true,
		})
	}

	// Signature algorithm of the cert itself
	sigSev := report.SeverityHigh
	switch cert.SignatureAlgorithm {
	case x509.MD5WithRSA:
		sigSev = report.SeverityCritical
	case x509.SHA1WithRSA, x509.ECDSAWithSHA1:
		sigSev = report.SeverityCritical
	}
	if isQuantumWeakSig(cert.SignatureAlgorithm) {
		res.Findings = append(res.Findings, report.Finding{
			Severity:    sigSev,
			Title:       fmt.Sprintf("Quantum-vulnerable signature algorithm (%s)", cert.SignatureAlgorithm),
			Description: "The certificate signature itself is quantum-vulnerable. Even with PQ key exchange, a quantum attacker could forge certificates.",
			Location:    fmt.Sprintf("%s — %s", host, role),
			Algorithm:   cert.SignatureAlgorithm.String(),
			Remediation: "Issue replacement certificate signed with ML-DSA (or hybrid ML-DSA + Ed25519).",
			Vulnerable:  true,
		})
	}
}

func isQuantumWeakSig(s x509.SignatureAlgorithm) bool {
	switch s {
	case x509.SHA256WithRSA, x509.SHA384WithRSA, x509.SHA512WithRSA,
		x509.ECDSAWithSHA256, x509.ECDSAWithSHA384, x509.ECDSAWithSHA512,
		x509.SHA256WithRSAPSS, x509.SHA384WithRSAPSS, x509.SHA512WithRSAPSS,
		x509.SHA1WithRSA, x509.ECDSAWithSHA1, x509.MD5WithRSA, x509.DSAWithSHA1, x509.DSAWithSHA256:
		return true
	}
	return false
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	}
	return fmt.Sprintf("0x%04x", v)
}

func curveName(c elliptic.Curve) string {
	if c == nil {
		return "unknown"
	}
	return c.Params().Name
}

func normalizeTarget(target string) (host, port string, err error) {
	t := strings.TrimSpace(target)
	if t == "" {
		return "", "", errors.New("empty target")
	}
	if !strings.Contains(t, "://") {
		t = "https://" + t
	}
	u, err := url.Parse(t)
	if err != nil {
		return "", "", fmt.Errorf("parse url: %w", err)
	}
	if u.Hostname() == "" {
		return "", "", errors.New("missing host")
	}
	host = u.Hostname()
	port = u.Port()
	if port == "" {
		port = "443"
	}
	return host, port, nil
}

func computeScore(findings []report.Finding) int {
	weights := map[report.Severity]int{
		report.SeverityCritical: 35,
		report.SeverityHigh:     20,
		report.SeverityMedium:   10,
		report.SeverityLow:      4,
		report.SeverityInfo:     0,
	}
	score := 0
	for _, f := range findings {
		score += weights[f.Severity]
	}
	if score > 100 {
		score = 100
	}
	return score
}
