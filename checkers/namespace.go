package checkers

import (
	"context"
	"fmt"
	"io"
	"net/http"

	"shelob-ng/corpus"

	log "github.com/sirupsen/logrus"
)

// NameSpaceRule detects Broken Object Level Authorization (BOLA / IDOR):
// a resource owned by user1 that is also accessible using user2's credentials.
//
// Detection sequence:
//  1. Primary user gets 2xx → candidate for BOLA check.
//  2. Anonymous probe (no cookies) → if also 2xx, the endpoint is public and
//     requires no auth at all; skip to avoid false positives on open APIs.
//  3. User2 probe → if 2xx, the server does not enforce ownership; report BOLA.
//
// Requires -user2 / -pass2 CLI flags; without them User2Cookies is nil
// and the checker silently skips every request.
//
// RESTler reference: NameSpaceRule checker (BOLA/IDOR detection).
type NameSpaceRule struct{}

func (NameSpaceRule) Name() string { return "NameSpaceRule" }

func (NameSpaceRule) Check(ctx context.Context, cctx CheckContext, entry *corpus.CorpusEntry, req *http.Request, resp *http.Response, _ []byte) []Finding {
	if len(cctx.User2Cookies) == 0 {
		return nil // second user not configured — checker disabled
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil // primary user did not succeed — nothing to compare against
	}

	// Step 1: anonymous probe — detect publicly accessible endpoints.
	// If the endpoint responds 2xx without any cookies, it is intentionally open
	// and BOLA does not apply (e.g. GET /api/Challenges, /rest/products/search).
	anonProbe, err := buildProbeWithCookies(ctx, req, entry, nil)
	if err != nil {
		log.Debugf("namespace: build anon probe: %v", err)
		return nil
	}
	anonResp, err := cctx.Client.Do(anonProbe)
	if err == nil {
		io.Copy(io.Discard, anonResp.Body) //nolint:errcheck
		anonResp.Body.Close()
		if anonResp.StatusCode >= 200 && anonResp.StatusCode < 300 {
			return nil // public endpoint — access control not expected
		}
	}

	// Step 2: user2 probe — check cross-account access.
	user2Probe, err := buildProbeWithCookies(ctx, req, entry, cctx.User2Cookies)
	if err != nil {
		log.Debugf("namespace: build user2 probe: %v", err)
		return nil
	}
	// Re-apply the static API key (if set) so the probe is not silently rejected
	// on API-key-required targets. API keys are app-level shared credentials, not
	// user identifiers, so carrying user1's key on user2's probe is correct.
	//
	// Do NOT re-apply the Bearer token: a Bearer token encodes user1's identity
	// (e.g. JWT sub claim). Sending it on the user2 probe would authenticate the
	// probe as user1, defeating the cross-account BOLA check entirely. Targets
	// that use token-based identity without cookies are not currently supported
	// by NameSpaceRule; user2 must authenticate via cookies (-user2 / -pass2).
	if cctx.APIKey != "" {
		user2Probe.Header.Set("X-Api-Key", cctx.APIKey)
	}
	probeResp, err := cctx.Client.Do(user2Probe)
	if err != nil {
		log.Debugf("namespace: user2 probe failed: %v", err)
		return nil
	}
	defer probeResp.Body.Close()
	io.Copy(io.Discard, probeResp.Body) //nolint:errcheck

	if probeResp.StatusCode >= 200 && probeResp.StatusCode < 300 {
		return []Finding{{
			Checker:    "NameSpaceRule",
			Severity:   SeverityHigh,
			Title:      "BOLA: cross-account resource access",
			Detail:     fmt.Sprintf("%s %s: user1 got %d, user2 also got %d (expected 401/403)", req.Method, req.URL.String(), resp.StatusCode, probeResp.StatusCode),
			Method:     req.Method,
			URL:        req.URL.String(),
			StatusCode:  probeResp.StatusCode,
			PathPattern: entry.PathPattern,
			POC:         BuildCurlPOC(user2Probe, entry.Body),
		}}
	}
	return nil
}

