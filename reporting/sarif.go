// Package reporting converts shelob-ng findings to SARIF 2.1.0 format
// compatible with Svacer import. Output mirrors the structure of Svacer
// SARIF exports: tool.driver.rules, run.artifacts, run.results with
// fingerprints and per-result properties.
package reporting

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	sarifVersion = "2.1.0"
	sarifSchema  = "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json"
	toolName     = "Shelob"
	toolVersion  = "0.1.0"
	toolInfoURI  = "https://github.com/morgonf/shelob-ng"
)

// Entry is a normalized finding for SARIF output, covering both
// checkers.Finding (checker!=Sequence:*) and sequence.Finding.
type Entry struct {
	Checker     string // checker name; "Sequence:<name>" for sequence findings
	Severity    string
	Title       string
	Detail      string
	Method      string
	URL         string
	StatusCode  int
	PathPattern string // OpenAPI path template; empty for sequence findings
	POC         string // curl PoC; empty when absent
}

// ReadFindingsDir scans dir and returns all findings as Entries.
// Files prefixed "seq_" are unmarshalled as sequence findings; others as
// checker findings. Unreadable or malformed files are silently skipped.
func ReadFindingsDir(dir string) ([]Entry, error) {
	des, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var out []Entry
	for _, de := range des {
		if de.IsDir() || !strings.HasSuffix(de.Name(), ".json") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, de.Name()))
		if err != nil {
			continue
		}
		if strings.HasPrefix(de.Name(), "seq_") {
			var f struct {
				SequenceName string `json:"sequence"`
				Severity     string `json:"severity"`
				Title        string `json:"title"`
				Detail       string `json:"detail"`
				Method       string `json:"method"`
				URL          string `json:"url"`
			}
			if json.Unmarshal(b, &f) != nil {
				continue
			}
			out = append(out, Entry{
				Checker:  "Sequence:" + f.SequenceName,
				Severity: f.Severity,
				Title:    f.Title,
				Detail:   f.Detail,
				Method:   f.Method,
				URL:      f.URL,
			})
		} else {
			var f struct {
				Checker     string `json:"checker"`
				Severity    string `json:"severity"`
				Title       string `json:"title"`
				Detail      string `json:"detail"`
				Method      string `json:"method"`
				URL         string `json:"url"`
				StatusCode  int    `json:"status_code"`
				PathPattern string `json:"path_pattern"`
				POC         string `json:"poc"`
			}
			if json.Unmarshal(b, &f) != nil {
				continue
			}
			out = append(out, Entry{
				Checker:     f.Checker,
				Severity:    f.Severity,
				Title:       f.Title,
				Detail:      f.Detail,
				Method:      f.Method,
				URL:         f.URL,
				StatusCode:  f.StatusCode,
				PathPattern: f.PathPattern,
				POC:         f.POC,
			})
		}
	}
	return out, nil
}

// WriteSARIF converts findings to a Svacer-compatible SARIF 2.1.0 report and
// writes it to path. projectName is used as the top-level project_name property.
func WriteSARIF(path string, findings []Entry, projectName string) error {
	report := buildReport(findings, projectName)
	b, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("sarif: marshal: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("sarif: mkdir: %w", err)
	}
	return os.WriteFile(path, b, 0o644)
}

// --- SARIF type definitions (Svacer-compatible subset) ---

type sarifReport struct {
	Version    string       `json:"version"`
	Schema     string       `json:"$schema"`
	Runs       []sarifRun   `json:"runs"`
	Properties sarifTopProp `json:"properties"`
}

type sarifRun struct {
	Tool      sarifTool       `json:"tool"`
	Artifacts []sarifArtifact `json:"artifacts,omitempty"`
	Results   []sarifResult   `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	InformationURI string      `json:"informationUri"`
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	Rules          []sarifRule `json:"rules,omitempty"`
}

type sarifRule struct {
	ID               string         `json:"id"`
	Name             string         `json:"name"`
	ShortDescription sarifText      `json:"shortDescription"`
	Properties       sarifRuleProps `json:"properties"`
}

type sarifRuleProps struct {
	Severity        string `json:"severity"`
	SvacerCheckerID string `json:"svacer_checker_id"`
	Tool            string `json:"tool"`
	WarnClass       string `json:"warnClass"`
}

type sarifArtifact struct {
	Location sarifArtifactLoc      `json:"location"`
	Length   int                   `json:"length"`
	Contents sarifArtifactContents `json:"contents"`
}

type sarifArtifactLoc struct {
	URI string `json:"uri"`
}

type sarifArtifactContents struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID              string             `json:"ruleId"`
	RuleIndex           int                `json:"ruleIndex"`
	Kind                string             `json:"kind"`
	Level               string             `json:"level"`
	Message             sarifText          `json:"message"`
	Locations           []sarifLocation    `json:"locations"`
	Fingerprints        sarifFingerprints  `json:"fingerprints"`
	PartialFingerprints sarifPartialFP     `json:"partialFingerprints"`
	Properties          sarifResultProps   `json:"properties"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysLoc        `json:"physicalLocation"`
	LogicalLocations []sarifLogicalLoc   `json:"logicalLocations,omitempty"`
}

type sarifPhysLoc struct {
	ArtifactLocation sarifArtifactLocRef `json:"artifactLocation"`
	Region           sarifRegion         `json:"region"`
}

type sarifArtifactLocRef struct {
	URI   string `json:"uri"`
	Index int    `json:"index"`
}

type sarifRegion struct {
	StartLine      int    `json:"startLine"`
	SourceLanguage string `json:"sourceLanguage"`
}

type sarifLogicalLoc struct {
	FullyQualifiedName string `json:"fullyQualifiedName"`
	Kind               string `json:"kind"`
}

type sarifFingerprints struct {
	Invariant string `json:"invariant"`
}

type sarifPartialFP struct {
	Details string `json:"details"`
}

type sarifResultProps struct {
	Action          string `json:"action"`
	CheckerSeverity string `json:"checker_severity"`
	Details         string `json:"details"`
	Invariant       string `json:"invariant"`
	POC             string `json:"poc,omitempty"`
	Status          string `json:"status"`
	StatusCode      int    `json:"status_code,omitempty"`
	Tags            any    `json:"tags"`
	Tool            string `json:"tool"`
	WarnClass       string `json:"warnClass"`
}

type sarifTopProp struct {
	ArtifactsCount int    `json:"artifacts_count"`
	ProjectName    string `json:"project_name"`
	SnapshotName   string `json:"snapshot_name"`
	WarningsCount  int    `json:"warnings_count"`
}

// --- builders ---

func buildReport(findings []Entry, projectName string) sarifReport {
	// Unique rules in insertion order.
	ruleIdx := map[string]int{}
	var rules []sarifRule
	for _, f := range findings {
		if _, ok := ruleIdx[f.Checker]; !ok {
			ruleIdx[f.Checker] = len(rules)
			rules = append(rules, sarifRule{
				ID:               f.Checker,
				Name:             f.Checker,
				ShortDescription: sarifText{Text: f.Checker},
				Properties: sarifRuleProps{
					Severity:        f.Severity,
					SvacerCheckerID: f.Checker,
					Tool:            toolName,
					WarnClass:       f.Checker,
				},
			})
		}
	}

	// Unique endpoint paths for the artifacts array.
	artifactIdx := map[string]int{}
	var artifacts []sarifArtifact
	for _, f := range findings {
		p := endpointPath(f)
		if _, ok := artifactIdx[p]; !ok {
			artifactIdx[p] = len(artifacts)
			artifacts = append(artifacts, sarifArtifact{
				Location: sarifArtifactLoc{URI: p},
				Length:   0,
				Contents: sarifArtifactContents{Text: ""},
			})
		}
	}

	var results []sarifResult
	for _, f := range findings {
		key := dedupeKey(f)
		inv := invariantFingerprint(key)
		partial := detailsFingerprint(key)
		p := endpointPath(f)

		msg := f.Title
		if f.Detail != "" {
			msg = f.Title + ": " + f.Detail
		}

		results = append(results, sarifResult{
			RuleID:    f.Checker,
			RuleIndex: ruleIdx[f.Checker],
			Kind:      "fail",
			Level:     severityLevel(f.Severity),
			Message:   sarifText{Text: msg},
			Locations: []sarifLocation{{
				PhysicalLocation: sarifPhysLoc{
					ArtifactLocation: sarifArtifactLocRef{
						URI:   p,
						Index: artifactIdx[p],
					},
					Region: sarifRegion{
						StartLine:      1,
						SourceLanguage: "HTTP",
					},
				},
				LogicalLocations: []sarifLogicalLoc{{
					FullyQualifiedName: f.Method + " " + p,
					Kind:               "function",
				}},
			}},
			Fingerprints:        sarifFingerprints{Invariant: inv},
			PartialFingerprints: sarifPartialFP{Details: partial},
			Properties: sarifResultProps{
				Action:          "Undecided",
				CheckerSeverity: f.Severity,
				Details:         partial,
				Invariant:       inv,
				POC:             f.POC,
				Status:          "Undecided",
				StatusCode:      f.StatusCode,
				Tags:            nil,
				Tool:            toolName,
				WarnClass:       f.Checker,
			},
		})
	}

	return sarifReport{
		Version: sarifVersion,
		Schema:  sarifSchema,
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				InformationURI: toolInfoURI,
				Name:           toolName,
				Version:        toolVersion,
				Rules:          rules,
			}},
			Artifacts: artifacts,
			Results:   results,
		}},
		Properties: sarifTopProp{
			ArtifactsCount: len(artifacts),
			ProjectName:    projectName,
			SnapshotName:   time.Now().UTC().Format(time.RFC3339),
			WarningsCount:  len(findings),
		},
	}
}

// endpointPath returns the OpenAPI path template when available,
// otherwise the URL path component.
func endpointPath(f Entry) string {
	if f.PathPattern != "" {
		return f.PathPattern
	}
	u, err := url.Parse(f.URL)
	if err != nil || u.Path == "" {
		return f.URL
	}
	return u.Path
}

// dedupeKey mirrors checkers.Finding.DedupeKey so fingerprints are stable.
func dedupeKey(f Entry) string {
	scope := f.PathPattern
	if scope == "" {
		scope = f.URL
	}
	return f.Checker + "\x00" + f.Method + "\x00" + scope
}

// invariantFingerprint is a base64-encoded SHA-256 prefix (16 bytes → 24 chars).
func invariantFingerprint(key string) string {
	h := sha256.Sum256([]byte(key))
	return base64.StdEncoding.EncodeToString(h[:16])
}

// detailsFingerprint is a 40-char lowercase hex of SHA-256 (first 20 bytes),
// matching Svacer's partialFingerprints.details format.
func detailsFingerprint(key string) string {
	h := sha256.Sum256([]byte(key))
	return fmt.Sprintf("%x", h[:20])
}

// severityLevel maps shelob severity to SARIF level.
func severityLevel(s string) string {
	switch strings.ToLower(s) {
	case "high":
		return "error"
	case "medium":
		return "warning"
	default:
		return "note"
	}
}
