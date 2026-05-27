package checkers

import (
	"bytes"
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
	anonProbe, err := buildNamespaceProbe(ctx, req, entry, nil)
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
	user2Probe, err := buildNamespaceProbe(ctx, req, entry, cctx.User2Cookies)
	if err != nil {
		log.Debugf("namespace: build user2 probe: %v", err)
		return nil
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
			StatusCode: probeResp.StatusCode,
		}}
	}
	return nil
}

// buildNamespaceProbe clones req with the given cookies substituted for the Cookie header.
// Pass cookies=nil for an anonymous (unauthenticated) probe.
func buildNamespaceProbe(ctx context.Context, req *http.Request, entry *corpus.CorpusEntry, cookies []*http.Cookie) (*http.Request, error) {
	var bodyReader io.Reader
	if req.GetBody != nil {
		rb, err := req.GetBody()
		if err == nil {
			bodyReader = rb
		}
	}
	if bodyReader == nil && len(entry.Body) > 0 {
		bodyReader = bytes.NewReader(entry.Body)
	}

	probe, err := http.NewRequestWithContext(ctx, req.Method, req.URL.String(), bodyReader)
	if err != nil {
		return nil, err
	}

	// Copy original headers (content-type, accept, etc.) then replace Cookie.
	for key, vals := range req.Header {
		for _, v := range vals {
			probe.Header.Add(key, v)
		}
	}
	probe.Header.Del("Cookie")
	for _, c := range cookies {
		probe.AddCookie(c)
	}
	return probe, nil
}
