// Package checkers implements modular security detectors called after every
// completed HTTP request. Each checker inspects the request+response pair and
// may issue additional HTTP probes to confirm a suspected vulnerability.
//
// All checkers are stateless and safe for concurrent use.
package checkers

import (
	"context"
	"net/http"

	"shelob-ng/corpus"

	"github.com/getkin/kin-openapi/routers"
)

// Severity levels for findings, ordered from highest to lowest impact.
const (
	SeverityHigh   = "high"
	SeverityMedium = "medium"
	SeverityLow    = "low"
	SeverityInfo   = "info"
)

// Finding represents one security issue detected by a checker.
// Written as a JSON file in the output directory alongside corpus crashes.
type Finding struct {
	Checker     string `json:"checker"`               // name of the checker that produced this
	Severity    string `json:"severity"`               // high / medium / low / info
	Title       string `json:"title"`                  // short human-readable description
	Detail      string `json:"detail"`                 // evidence: matched pattern, status codes, etc.
	Method      string `json:"method"`                 // HTTP method of the probe request
	URL         string `json:"url"`                    // full URL of the probe request
	StatusCode  int    `json:"status_code"`            // HTTP status of the probe response
	PathPattern string `json:"path_pattern,omitempty"` // OpenAPI path template, e.g. /api/Cards/{id}
	POC         string `json:"poc,omitempty"`           // curl command to reproduce
}

// DedupeKey returns a stable string that identifies this class of finding.
// Two findings with the same key are considered duplicates: same checker
// detecting the same issue on the same API operation.
// Uses PathPattern (the OpenAPI template) when available so that probes
// with different concrete values (e.g. /api/Cards/-1 vs /api/Cards/0)
// collapse to one finding per endpoint.
func (f Finding) DedupeKey() string {
	scope := f.PathPattern
	if scope == "" {
		scope = f.URL
	}
	return f.Checker + "\x00" + f.Method + "\x00" + scope
}

// CheckContext carries resources shared across all checker invocations.
// Populated once in run/ and passed by value to every Check call.
type CheckContext struct {
	// Client is used by checkers that issue follow-up probe requests.
	// Must not be nil.
	Client *http.Client

	// TargetURL is the base URL of the target (e.g. "http://localhost:3000").
	// Used by checkers that build new requests from corpus entries.
	TargetURL string

	// AuthCookies are the primary user's session cookies from the login step.
	// Applied to all probe requests.
	AuthCookies []*http.Cookie

	// User2Cookies are the second user's session cookies for BOLA testing.
	// nil means NameSpaceRule checker is disabled.
	User2Cookies []*http.Cookie

	// OASRouter enables SchemaViolation to look up OpenAPI route definitions.
	// nil means SchemaViolation checker is disabled.
	OASRouter routers.Router

	// APIKey and Token carry static auth credentials forwarded to all probe
	// requests built by checkers. Both are optional; empty values are ignored.
	APIKey string
	Token  string
}

// Checker inspects one completed request+response pair and returns findings.
// Implementations may issue additional HTTP requests via cctx.Client.
// Check must not modify entry or req.
type Checker interface {
	Name() string
	Check(ctx context.Context, cctx CheckContext, entry *corpus.CorpusEntry, req *http.Request, resp *http.Response, body []byte) []Finding
}

// All returns the default set of all available checkers.
// Callers filter this list by the -checker CLI flag.
func All() []Checker {
	return []Checker{
		BehavioralPatterns{},
		UseAfterFree{},
		InvalidDynamicObject{},
		LeakageRule{},
		NameSpaceRule{},
		BrokenFunctionLevelAuthorization{},
		AuthBypassRule{},
		SchemaViolation{},
		NewRateLimitChecker(), // stateful: must be a pointer so counters persist
	}
}
