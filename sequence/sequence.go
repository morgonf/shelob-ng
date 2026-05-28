// Package sequence implements stateful multi-step API testing.
//
// A Sequence is an ordered list of HTTP Steps that share state: a value
// extracted from one step's response (e.g. a newly created resource ID) is
// automatically bound into a path parameter of subsequent steps.
//
// The canonical pattern is CRUD + UseAfterFree:
//  1. POST /resource          → extract id from response body
//  2. GET  /resource/{id}     → expect 2xx (resource exists)
//  3. DELETE /resource/{id}   → expect 2xx (deletion succeeds)
//  4. GET  /resource/{id}     → expect 4xx (resource gone — 2xx is a finding)
//
// Sequences are built automatically from the OpenAPI spec by builder.go and
// run periodically inside the main fuzzing loop (run/run.go, every 20 iters).
package sequence

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"shelob-ng/corpus"
	"shelob-ng/request"
)

// Step is one HTTP call inside a Sequence.
type Step struct {
	// Entry is the template request. Cloned before each execution so the
	// original template is never mutated.
	Entry *corpus.CorpusEntry

	// ExtractKey is the top-level JSON field name whose value should be
	// extracted from this step's response body and stored for later steps.
	// Empty string = no extraction.
	ExtractKey string

	// BindParam is the path-parameter name in subsequent steps that receives
	// the extracted value. Only meaningful when ExtractKey != "".
	BindParam string

	// WantStatus is the expected HTTP status class: 2 means any 2xx, 4 means
	// any 4xx. 0 means no expectation (step is informational only).
	WantStatus int

	// FindingTitle is the human-readable finding title emitted when the
	// response status does NOT match WantStatus. Empty = no finding on mismatch.
	FindingTitle string

	// FindingSeverity is the severity level for the mismatch finding.
	FindingSeverity string
}

// Sequence is a named ordered list of Steps.
type Sequence struct {
	Name  string
	Steps []Step
}

// Finding records one security issue detected during sequence execution.
type Finding struct {
	SequenceName string `json:"sequence"`
	StepIndex    int    `json:"step_index"`
	Severity     string `json:"severity"`
	Title        string `json:"title"`
	Detail       string `json:"detail"`
	Method       string `json:"method"`
	URL          string `json:"url"`
	StatusCode   int    `json:"status_code"`
}

// ReplayStep captures what actually happened at one step for post-mortem analysis.
type ReplayStep struct {
	Method     string            `json:"method"`
	URL        string            `json:"url"`
	StatusCode int               `json:"status_code"`
	Extracted  map[string]string `json:"extracted,omitempty"`
}

// Replay is the full execution record of one Sequence run, persisted when
// a finding is detected so the sequence can be reproduced manually.
type Replay struct {
	SequenceName string       `json:"sequence"`
	ExecutedAt   time.Time    `json:"executed_at"`
	Steps        []ReplayStep `json:"steps"`
	Findings     []Finding    `json:"findings"`
}

// Runner executes Sequences against the target API.
type Runner struct {
	Client      *http.Client
	TargetURL   string
	AuthCookies []*http.Cookie
	APIKey      string
	Token       string
}

// Run executes seq step-by-step, propagating extracted values between steps.
// It returns all findings detected and a Replay record for persistence.
func (r *Runner) Run(ctx context.Context, seq Sequence) ([]Finding, Replay) {
	replay := Replay{
		SequenceName: seq.Name,
		ExecutedAt:   time.Now(),
		Steps:        make([]ReplayStep, 0, len(seq.Steps)),
	}

	// bound holds values extracted in earlier steps, keyed by BindParam name.
	bound := make(map[string]interface{})

	var findings []Finding

	for i, step := range seq.Steps {
		entry := step.Entry.Clone()

		// Inject previously extracted values into path params.
		for param, val := range bound {
			entry.PathParams[param] = val
		}

		resp, body, url, err := r.sendStep(ctx, entry)
		if err != nil {
			// Network failure — stop the sequence (target may be down).
			break
		}

		rs := ReplayStep{
			Method:     entry.Method,
			URL:        url,
			StatusCode: resp.StatusCode,
		}

		// Extract a value from the response body for downstream steps.
		if step.ExtractKey != "" {
			val := extractJSONField(body, step.ExtractKey)
			if val != nil {
				bound[step.BindParam] = val
				rs.Extracted = map[string]string{step.BindParam: fmt.Sprintf("%v", val)}
			}
		}

		replay.Steps = append(replay.Steps, rs)

		// Check whether the status matches the expectation.
		if step.FindingTitle != "" && step.WantStatus != 0 {
			got := resp.StatusCode / 100
			if got != step.WantStatus {
				detail := fmt.Sprintf(
					"%s expected %dxx, got %d",
					step.FindingTitle, step.WantStatus, resp.StatusCode,
				)
				f := Finding{
					SequenceName: seq.Name,
					StepIndex:    i,
					Severity:     step.FindingSeverity,
					Title:        step.FindingTitle,
					Detail:       detail,
					Method:       entry.Method,
					URL:          url,
					StatusCode:   resp.StatusCode,
				}
				findings = append(findings, f)
			}
		}
	}

	replay.Findings = findings
	return findings, replay
}

// sendStep builds and sends one HTTP request, returning the response, body,
// the full request URL string, and any transport-level error.
func (r *Runner) sendStep(ctx context.Context, entry *corpus.CorpusEntry) (*http.Response, []byte, string, error) {
	req, err := request.FromCorpusEntry(entry, r.TargetURL, r.AuthCookies, r.APIKey, r.Token)
	if err != nil {
		return nil, nil, "", fmt.Errorf("build request: %w", err)
	}
	req = req.WithContext(ctx)

	url := req.URL.String()

	resp, err := r.Client.Do(req)
	if err != nil {
		return nil, nil, url, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1*1024*1024)) // 1 MiB cap
	if err != nil {
		return resp, body, url, nil // partial body is fine
	}
	return resp, body, url, nil
}

// extractJSONField returns the top-level value for key from a JSON object body.
// Returns nil when the body is not a JSON object or the key is absent.
// Numbers are returned as int64 when possible, then float64, preserving
// precision needed for path parameters.
func extractJSONField(body []byte, key string) interface{} {
	body = bytes.TrimSpace(body)
	if len(body) == 0 || body[0] != '{' {
		return nil
	}

	dec := json.NewDecoder(strings.NewReader(string(body)))
	dec.UseNumber()

	var obj map[string]interface{}
	if err := dec.Decode(&obj); err != nil {
		return nil
	}

	val, ok := obj[key]
	if !ok {
		return nil
	}

	// Narrow json.Number to int64 or float64.
	if n, ok := val.(json.Number); ok {
		if i, err := n.Int64(); err == nil {
			return i
		}
		if f, err := n.Float64(); err == nil {
			return f
		}
		return n.String()
	}
	return val
}
