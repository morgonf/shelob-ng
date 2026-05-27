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
// Trigger: any request that returns 2xx for the primary user.
// Probe:   replay the exact same request with user2's session cookies.
// Finding: user2 also gets 2xx — the server does not enforce ownership checks.
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

	// Clone the body for the probe request.
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
		log.Debugf("namespace: build probe: %v", err)
		return nil
	}

	// Copy all headers from the original request (content-type, accept, etc.)
	// but replace the Cookie header with user2's session.
	for key, vals := range req.Header {
		for _, v := range vals {
			probe.Header.Add(key, v)
		}
	}
	probe.Header.Del("Cookie")
	for _, c := range cctx.User2Cookies {
		probe.AddCookie(c)
	}

	probeResp, err := cctx.Client.Do(probe)
	if err != nil {
		log.Debugf("namespace: probe failed: %v", err)
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
