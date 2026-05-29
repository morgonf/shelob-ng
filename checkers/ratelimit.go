package checkers

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"shelob-ng/corpus"

	log "github.com/sirupsen/logrus"
)

// authPathRE matches path segments where brute-force protection is critical:
// login, registration, OTP verification, password reset.
//
// The trailing class (/|-|$|\?) allows both slash-delimited segments
// (/api/login, /auth/v2/otp) and hyphenated compound words
// (/reset-password, /forgot-password) to match.
var authPathRE = regexp.MustCompile(
	`(?i)/(login|signin|signup|register|auth(?:enticate)?|token|password|passphrase|otp|pin|verify|2fa|mfa|reset|forgot)(/|-|$|\?)`,
)

const (
	// authBurstThreshold: fire a burst probe after this many non-429 responses
	// on an auth path. Low threshold because brute-force risk is high.
	authBurstThreshold = 5

	// generalBurstThreshold: fire after this many non-429 responses on a
	// non-auth path. Higher threshold to avoid noise on normal CRUD endpoints.
	generalBurstThreshold = 20

	// burstSize: number of rapid probe requests sent in the burst test.
	// A rate limiter configured for reasonable limits (e.g. 10 req/s) will
	// trigger well before this many identical requests complete.
	burstSize = 8

	// burstTimeout caps the total time spent on burst probes so a slow target
	// doesn't block the checker goroutine indefinitely.
	burstTimeout = 15 * time.Second
)

// RateLimitChecker detects API endpoints that accept unlimited rapid requests
// without returning 429 Too Many Requests.
//
// Detection sequence:
//  1. Count natural non-429 responses per (method, pathPattern).
//  2. Once the threshold is reached, fire burstSize identical requests as
//     fast as the HTTP client allows — mirroring a brute-force attack.
//  3. If every burst response is non-429 → the endpoint has no rate limiting.
//
// Severity:
//   HIGH   — auth/OTP/password endpoints (brute-force risk)
//   MEDIUM — all other functional endpoints
//
// Note: this checker is stateful (it maintains per-endpoint hit counters).
// It is returned as *RateLimitChecker from All() so the same counters persist
// across all Check() calls throughout a fuzzing session.
type RateLimitChecker struct {
	mu    sync.Mutex
	hits  map[string]int         // endpoint key → natural hit count
	fired map[string]struct{}    // endpoint keys where a burst was already sent
}

// NewRateLimitChecker allocates a RateLimitChecker with initialised maps.
func NewRateLimitChecker() *RateLimitChecker {
	return &RateLimitChecker{
		hits:  make(map[string]int),
		fired: make(map[string]struct{}),
	}
}

func (r *RateLimitChecker) Name() string { return "RateLimitChecker" }

func (r *RateLimitChecker) Check(
	ctx context.Context,
	cctx CheckContext,
	entry *corpus.CorpusEntry,
	req *http.Request,
	resp *http.Response,
	_ []byte,
) []Finding {
	// If the server is already rate-limiting this request, nothing to report.
	if resp.StatusCode == 429 {
		return nil
	}
	// 5xx errors indicate a broken endpoint, not a missing rate limiter.
	if resp.StatusCode >= 500 {
		return nil
	}

	isAuth := authPathRE.MatchString(entry.PathPattern)
	threshold := generalBurstThreshold
	if isAuth {
		threshold = authBurstThreshold
	}

	key := entry.Method + "\x00" + entry.PathPattern

	// Increment hit counter; check whether we should fire.
	r.mu.Lock()
	r.hits[key]++
	count := r.hits[key]
	_, alreadyFired := r.fired[key]
	r.mu.Unlock()

	if alreadyFired || count < threshold {
		return nil
	}

	// Claim the firing right atomically. A second goroutine hitting the
	// threshold at the same time will find the key already set and return.
	r.mu.Lock()
	if _, ok := r.fired[key]; ok {
		r.mu.Unlock()
		return nil
	}
	r.fired[key] = struct{}{}
	r.mu.Unlock()

	return r.runBurst(ctx, cctx, entry, req, resp, isAuth)
}

// runBurst sends burstSize rapid identical requests to the endpoint.
// Returns a finding if none of the burst responses is 429.
func (r *RateLimitChecker) runBurst(
	ctx context.Context,
	cctx CheckContext,
	entry *corpus.CorpusEntry,
	req *http.Request,
	originalResp *http.Response,
	isAuth bool,
) []Finding {
	burstCtx, cancel := context.WithTimeout(ctx, burstTimeout)
	defer cancel()

	codes := make([]int, 0, burstSize)
	for i := 0; i < burstSize; i++ {
		probe, err := cloneRequestFull(burstCtx, req, entry)
		if err != nil {
			log.Debugf("ratelimit: clone request: %v", err)
			break
		}
		probeResp, err := cctx.Client.Do(probe)
		if err != nil {
			log.Debugf("ratelimit: burst probe %d: %v", i, err)
			break
		}
		io.Copy(io.Discard, probeResp.Body) //nolint:errcheck
		probeResp.Body.Close()

		codes = append(codes, probeResp.StatusCode)
		if probeResp.StatusCode == 429 {
			// Rate limiter engaged — endpoint is protected.
			return nil
		}
	}

	if len(codes) == 0 {
		return nil // all probes failed (network error); inconclusive
	}

	severity := SeverityMedium
	title := "Missing Rate Limiting"
	if isAuth {
		severity = SeverityHigh
		title = "Missing Rate Limiting on Auth Endpoint"
	}

	detail := fmt.Sprintf(
		"sent %d rapid requests, none returned 429 (codes: %s)",
		len(codes), summariseCodes(codes),
	)

	poc := fmt.Sprintf(
		"# %d rapid requests — none returned 429:\nfor i in $(seq 1 %d); do\n  %s\ndone",
		burstSize, burstSize, BuildCurlPOC(req, entry.Body),
	)

	return []Finding{{
		Checker:     "RateLimitChecker",
		Severity:    severity,
		Title:       title,
		Detail:      detail,
		Method:      entry.Method,
		URL:         req.URL.String(),
		StatusCode:  originalResp.StatusCode,
		PathPattern: entry.PathPattern,
		POC:         poc,
	}}
}

// cloneRequestFull duplicates req preserving all headers and the body.
// Unlike buildProbeWithCookies it does NOT strip auth headers — the burst test
// must be identical to the original request, including credentials.
func cloneRequestFull(ctx context.Context, req *http.Request, entry *corpus.CorpusEntry) (*http.Request, error) {
	var bodyReader io.Reader
	if req.GetBody != nil {
		if rb, err := req.GetBody(); err == nil {
			bodyReader = rb
		}
	}
	if bodyReader == nil && len(entry.Body) > 0 {
		bodyReader = bytes.NewReader(entry.Body)
	}

	clone, err := http.NewRequestWithContext(ctx, req.Method, req.URL.String(), bodyReader)
	if err != nil {
		return nil, err
	}
	for key, vals := range req.Header {
		for _, v := range vals {
			clone.Header.Add(key, v)
		}
	}
	return clone, nil
}

// summariseCodes converts a slice of status codes into a compact string,
// e.g. [200,200,401,200] → "200×3 401×1".
func summariseCodes(codes []int) string {
	counts := make(map[int]int, 4)
	seen := make([]int, 0, 4)
	for _, c := range codes {
		if counts[c] == 0 {
			seen = append(seen, c)
		}
		counts[c]++
	}
	parts := make([]string, 0, len(seen))
	for _, c := range seen {
		parts = append(parts, fmt.Sprintf("%d×%d", c, counts[c]))
	}
	return strings.Join(parts, " ")
}
