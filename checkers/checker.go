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
	Checker    string `json:"checker"`    // name of the checker that produced this
	Severity   string `json:"severity"`   // high / medium / low / info
	Title      string `json:"title"`      // short human-readable description
	Detail     string `json:"detail"`     // evidence: matched pattern, status codes, etc.
	Method     string `json:"method"`     // HTTP method of the probe request
	URL        string `json:"url"`        // full URL of the probe request
	StatusCode int    `json:"status_code"` // HTTP status of the probe response
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
		SchemaViolation{},
	}
}
