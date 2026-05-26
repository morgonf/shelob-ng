package coverage

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// cspClient implements Client by issuing HTTP requests to a CSP endpoint.
// http.Client is safe for concurrent use per the Go standard library docs.
type cspClient struct {
	baseURL    string       // normalised: no trailing slash
	timeout    time.Duration
	httpClient *http.Client
}

// newCSPClient is the internal constructor called from NewClient.
// Uses a dedicated http.Client with no global Timeout so that per-call
// context cancellation (context.WithTimeout) is the sole timeout mechanism.
// A global Timeout on http.Client would race with ctx deadlines from the
// fuzzer's own duration budget, potentially cancelling CSP calls mid-flight
// during graceful shutdown.
func newCSPClient(cfg Config) *cspClient {
	return &cspClient{
		baseURL: strings.TrimRight(cfg.BaseURL, "/"),
		timeout: cfg.Timeout,
		httpClient: &http.Client{
			// No Timeout here: context.WithTimeout inside Reset/Dump handles it.
			// This lets the fuzzer's parent ctx cancel CSP calls cleanly.
		},
	}
}

// Reset sends POST /csp/reset to zero coverage counters on the target.
// A per-call context with c.timeout is derived from ctx so that:
//   - A slow target (e.g. gcov dump taking > timeout) is cancelled promptly.
//   - If ctx is already cancelled (fuzzer shutting down), the call is skipped.
func (c *cspClient) Reset(ctx context.Context) error {
	callCtx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(callCtx, http.MethodPost, c.baseURL+"/csp/reset", http.NoBody)
	if err != nil {
		// NewRequestWithContext only fails on malformed URLs — treat as unavailable.
		return fmt.Errorf("%w: build reset request: %v", ErrCSPUnavailable, err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrCSPUnavailable, err)
	}
	defer resp.Body.Close()
	// Drain body to allow connection reuse.
	_, _ = io.Copy(io.Discard, resp.Body)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("%w: status %d", ErrCSPBadStatus, resp.StatusCode)
	}
	return nil
}

// dumpResponse mirrors the JSON schema of GET /csp/dump.
// All fields are optional: a minimal adapter may omit Bitmap or NewSinceReset.
type dumpResponse struct {
	TotalLines    int      `json:"total_lines"`
	CoveredLines  int      `json:"covered_lines"`
	Bitmap        string   `json:"bitmap"`          // base64-encoded bitset
	NewSinceReset []string `json:"new_since_reset"` // ["handler.go:42", ...]
}

// Dump sends GET /csp/dump and parses the coverage response into a Snapshot.
// Returns an empty Snapshot (Delta() == 0) on any error so callers can
// unconditionally pass snap.Delta() to corpus.Add without branching.
func (c *cspClient) Dump(ctx context.Context) (Snapshot, error) {
	callCtx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(callCtx, http.MethodGet, c.baseURL+"/csp/dump", http.NoBody)
	if err != nil {
		return Snapshot{}, fmt.Errorf("%w: build dump request: %v", ErrCSPUnavailable, err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return Snapshot{}, fmt.Errorf("%w: %v", ErrCSPUnavailable, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		_, _ = io.Copy(io.Discard, resp.Body)
		return Snapshot{}, fmt.Errorf("%w: status %d", ErrCSPBadStatus, resp.StatusCode)
	}

	// Limit response body to 1 MiB. A misbehaving or compromised target could
	// otherwise stream an unbounded response and exhaust fuzzer memory.
	// json.NewDecoder drains only what it needs; the defer Close handles the rest.
	var dr dumpResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&dr); err != nil {
		// Drain remainder so the connection is returned to the pool.
		_, _ = io.Copy(io.Discard, resp.Body)
		return Snapshot{}, fmt.Errorf("%w: parse JSON: %v", ErrCSPInvalidResponse, err)
	}

	snap := Snapshot{
		TotalLines:    dr.TotalLines,
		CoveredLines:  dr.CoveredLines,
		NewSinceReset: dr.NewSinceReset,
	}

	// Decode bitmap only when present; ignore errors — bitmap is advisory.
	if dr.Bitmap != "" {
		if bm, err := base64.StdEncoding.DecodeString(dr.Bitmap); err == nil {
			snap.Bitmap = bm
		}
	}

	return snap, nil
}
