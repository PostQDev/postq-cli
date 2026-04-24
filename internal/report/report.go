// Package report defines the wire format for scan submissions to /v1/scans.
//
// Mirrors the Zod schema in postq-site/apps/api/src/routes/v1-scans.ts.
package report

// Severity matches the API's enum.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// RiskLevel is the bucketed risk classification.
type RiskLevel string

const (
	RiskCritical RiskLevel = "Critical"
	RiskHigh     RiskLevel = "High"
	RiskMedium   RiskLevel = "Medium"
	RiskLow      RiskLevel = "Low"
	RiskSafe     RiskLevel = "Safe"
)

// Finding is a single quantum-vulnerability hit.
type Finding struct {
	Severity    Severity `json:"severity"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Location    string   `json:"location"`
	Algorithm   string   `json:"algorithm,omitempty"`
	Remediation string   `json:"remediation"`
	Vulnerable  bool     `json:"vulnerable"`
}

// Agent is identifying info about the scanner that produced this report.
type Agent struct {
	Name     string `json:"name,omitempty"`
	Version  string `json:"version,omitempty"`
	Hostname string `json:"hostname,omitempty"`
	OS       string `json:"os,omitempty"`
}

// Submission is the POST /v1/scans request body.
type Submission struct {
	Type      string            `json:"type"` // url|github|aws|azure|kubernetes|bulk
	Target    string            `json:"target"`
	Source    string            `json:"source"` // cli|helm|lambda|bicep|web
	RiskScore int               `json:"riskScore"`
	RiskLevel RiskLevel         `json:"riskLevel"`
	Findings  []Finding         `json:"findings"`
	Metadata  map[string]string `json:"metadata"`
	Agent     Agent             `json:"agent"`
}

// ScoreToLevel mirrors the bucket logic in scan-engine.ts.
func ScoreToLevel(score int) RiskLevel {
	switch {
	case score >= 80:
		return RiskCritical
	case score >= 60:
		return RiskHigh
	case score >= 40:
		return RiskMedium
	case score >= 20:
		return RiskLow
	default:
		return RiskSafe
	}
}
