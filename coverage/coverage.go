// Package coverage implements the Coverage Sidecar Protocol (CSP) client.
//
// CSP is a minimal HTTP API added to the target application when built with
// instrumentation (gcov, go -cover, nyc, etc.). It exposes two endpoints:
//
//	POST /csp/reset  — zero out coverage counters before a request
//	GET  /csp/dump   — return current coverage as normalised JSON
//
// The fuzzer calls Reset before sending each API request, then Dump after.
// The resulting Snapshot.Delta() (new lines covered) is used by the corpus
// to decide whether to keep the request as a seed for future mutations.
//
// When -csp-url is not provided, NewClient returns a no-op implementation
// so the fuzzer degrades gracefully to pure-random mode (original Shelob
// behaviour) without any code changes in run/.
package coverage

import (
	"context"
	"time"
)

// DefaultTimeout is the per-call CSP timeout used when Config.Timeout is zero.
// Chosen to be long enough for gcov __gcov_dump() (which can take ~100 ms on
// large binaries) but short enough not to block the fuzzer noticeably.
const DefaultTimeout = 2 * time.Second

// Client manages interaction with the Coverage Sidecar Protocol.
// Both implementations (cspClient and noopClient) are safe for concurrent use.
type Client interface {
	// Reset zeroes coverage counters on the target via POST /csp/reset.
	// Must be called BEFORE the API request under test.
	//
	// On error the fuzzer should log a warning and continue the iteration;
	// the Dump result for this iteration will be unreliable (delta should be
	// treated as 0). Reset never returns a fatal error.
	Reset(ctx context.Context) error

	// Dump reads current coverage via GET /csp/dump.
	// Must be called AFTER the API request under test.
	//
	// On error returns an empty Snapshot (Delta() == 0) and a non-nil error.
	// An empty Snapshot is safe to pass to corpus.Add — delta 0 means "do not
	// store this entry".
	Dump(ctx context.Context) (Snapshot, error)
}

// Snapshot is an immutable coverage reading taken after one API request.
// Created by Dump(), consumed by corpus.Add(entry, snap.Delta()).
type Snapshot struct {
	// TotalLines is the total number of instrumented source lines.
	// Used for progress reporting; not part of delta computation.
	TotalLines int

	// CoveredLines is the number of lines covered at the time of Dump.
	CoveredLines int

	// NewSinceReset lists source locations first covered since the last Reset.
	// Format is implementation-defined (e.g. "handler_users.go:42").
	// This is the primary source of Delta().
	NewSinceReset []string

	// Bitmap is the raw bitset from /csp/dump, base64-decoded.
	// Reserved for future delta computation via bitwise XOR, which is more
	// efficient than diffing string slices for large binaries.
	// Not used in Delta() yet.
	Bitmap []byte
}

// Delta returns the number of source lines newly covered by the last request.
// A non-zero delta signals the corpus to retain the triggering entry as a
// candidate for future mutations.
//
// Current implementation: len(NewSinceReset).
// Future: popcount(bitmap XOR previous_bitmap) for O(n/64) instead of O(n).
func (s Snapshot) Delta() uint64 {
	return uint64(len(s.NewSinceReset))
}

// Config holds parameters for the CSP client.
type Config struct {
	// BaseURL is the base URL of the CSP endpoint, e.g. "http://localhost:8080".
	// Empty string causes NewClient to return a noopClient.
	BaseURL string

	// Timeout is applied to each CSP call (Reset and Dump independently).
	// Zero uses DefaultTimeout.
	// Separate from the API request timeout so a slow gcov dump does not
	// consume the budget allocated to the actual fuzz request.
	Timeout time.Duration
}

// NewClient constructs a Client from cfg.
// Returns noopClient when cfg.BaseURL is empty (disabled mode).
func NewClient(cfg Config) Client {
	if cfg.BaseURL == "" {
		return noopClient{}
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = DefaultTimeout
	}
	return newCSPClient(cfg)
}
