package checkers

import (
	"context"
	"fmt"
	"io"
	"net/http"

	"shelob-ng/corpus"

	log "github.com/sirupsen/logrus"
)

// LeakageRule detects partial resource creation: a rejected POST (4xx) that
// leaves a readable resource at the endpoint URL.
//
// Trigger: POST returns 4xx (the server rejected the request).
// Probe:   GET the same URL with the same auth cookies.
// Finding: GET returns 2xx — state was committed despite the rejection.
//
// Typical cause: the handler validates input after writing to the database
// (commit-then-validate instead of validate-then-commit), or a missing
// transaction rollback on error paths.
//
// RESTler reference: ResourceHierarchy / LeakageRule checker.
type LeakageRule struct{}

func (LeakageRule) Name() string { return "LeakageRule" }

func (LeakageRule) Check(ctx context.Context, cctx CheckContext, entry *corpus.CorpusEntry, req *http.Request, resp *http.Response, _ []byte) []Finding {
	if entry.Method != "POST" {
		return nil
	}
	// Only trigger on client-error responses (4xx), not server errors (5xx).
	// 5xx on POST is already flagged by BehavioralPatterns or other analysis.
	if resp.StatusCode < 400 || resp.StatusCode >= 500 {
		return nil
	}
	// Skip pure authentication failures (401): the auth middleware rejected the
	// request before any application logic ran, so no state could have been
	// committed to the database.
	if resp.StatusCode == http.StatusUnauthorized {
		return nil
	}

	// Skip collection endpoints (no path parameters). POST /collection → 4xx
	// followed by GET /collection → 200 is normal REST behaviour: the collection
	// is readable regardless of whether the create attempt succeeded. Only
	// singleton endpoints (with at least one path parameter) can exhibit genuine
	// commit-then-validate leakage where a partial write is readable at the
	// specific resource URL. This also eliminates false positives from
	// RBAC-protected POST endpoints (403) where the collection GET is public.
	if len(entry.PathParams) == 0 {
		return nil
	}

	// Build the probe URL from the fully-parsed request URL (scheme + host + path).
	// Using cctx.TargetURL + req.URL.Path would double any path prefix already
	// present in the spec server URL (e.g. servers[0].url = "http://api.example.com/v1"
	// → req.URL.Path = "/v1/users/5" → probeURL = "…/v1/v1/users/5").
	// req.URL is always an absolute URL because FromCorpusEntry builds it from
	// targetURL (which run.go validates as non-empty at startup).
	probeURL := req.URL.Scheme + "://" + req.URL.Host + req.URL.Path
	probe, err := http.NewRequestWithContext(ctx, http.MethodGet, probeURL, nil)
	if err != nil {
		log.Debugf("leakage: build probe: %v", err)
		return nil
	}
	for _, c := range cctx.AuthCookies {
		probe.AddCookie(c)
	}
	ApplyAuth(probe, cctx.APIKey, cctx.Token)

	probeResp, err := cctx.Client.Do(probe)
	if err != nil {
		log.Debugf("leakage: probe failed: %v", err)
		return nil
	}
	defer probeResp.Body.Close()
	io.Copy(io.Discard, probeResp.Body) //nolint:errcheck

	if probeResp.StatusCode >= 200 && probeResp.StatusCode < 300 {
		return []Finding{{
			Checker:    "LeakageRule",
			Severity:   SeverityMedium,
			Title:      "Resource accessible after failed POST",
			Detail:     fmt.Sprintf("POST %s returned %d (rejected), but GET returned %d (resource exists)", probeURL, resp.StatusCode, probeResp.StatusCode),
			Method:     http.MethodGet,
			URL:        probeURL,
			StatusCode:  probeResp.StatusCode,
			PathPattern: entry.PathPattern,
			POC:         BuildCurlPOC(probe, nil),
		}}
	}
	return nil
}
