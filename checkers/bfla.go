package checkers

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"

	"shelob-ng/corpus"

	log "github.com/sirupsen/logrus"
)

// BrokenFunctionLevelAuthorization (BFLA) detects role-based access control
// failures: a function restricted to elevated privileges (admin, staff) that is
// also accessible using lower-privilege user2 credentials.
//
// Difference from NameSpaceRule:
//   - NameSpaceRule tests object ownership (BOLA/IDOR): user2 accessing a
//     specific resource owned by user1 (e.g. GET /orders/42).
//   - BFLA tests role boundaries: user2 calling a function that the API
//     intends only for admins/staff (e.g. GET /admin/users, DELETE /manage/config).
//
// Detection sequence:
//  1. Endpoint path or operationId must match the privileged-function heuristic.
//  2. Primary user gets 2xx — confirms the function is accessible to user1.
//  3. Anonymous probe: if also 2xx the endpoint is public; skip.
//  4. User2 probe: if 2xx the server ignores the role boundary — report BFLA.
//
// Requires -user2 / -pass2 CLI flags; without them User2Cookies is nil
// and the checker silently skips every request.
type BrokenFunctionLevelAuthorization struct{}

func (BrokenFunctionLevelAuthorization) Name() string { return "BFLA" }

// adminSegRE matches a URL path segment that signals an elevated-privilege
// function. Anchored at a slash boundary so incidental matches in domain names
// or query values do not fire (PathPattern never contains the host).
var adminSegRE = regexp.MustCompile(
	`(?i)/(admin|backoffice|dashboard|internal|manage|management|panel|private|staff|superuser|console)(/|$)`,
)

func (BrokenFunctionLevelAuthorization) Check(
	ctx context.Context,
	cctx CheckContext,
	entry *corpus.CorpusEntry,
	req *http.Request,
	resp *http.Response,
	_ []byte,
) []Finding {
	if len(cctx.User2Cookies) == 0 {
		return nil // second user not configured — checker disabled
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil // primary user did not succeed — nothing to compare
	}
	if !isPrivilegedEndpoint(entry) {
		return nil // not a privileged-looking endpoint — BFLA not applicable
	}

	// Anonymous probe: skip if the endpoint is publicly accessible.
	// A function reachable without any credentials cannot be a role-restriction
	// failure — it is intentionally open (e.g. an admin login page).
	anonProbe, err := buildBFLAProbe(ctx, req, entry, nil)
	if err != nil {
		log.Debugf("bfla: build anon probe: %v", err)
		return nil
	}
	if anonResp, err := cctx.Client.Do(anonProbe); err == nil {
		io.Copy(io.Discard, anonResp.Body) //nolint:errcheck
		anonResp.Body.Close()
		if anonResp.StatusCode >= 200 && anonResp.StatusCode < 300 {
			return nil // public endpoint — role restrictions not expected
		}
	}

	// User2 probe: check whether the role boundary is enforced.
	user2Probe, err := buildBFLAProbe(ctx, req, entry, cctx.User2Cookies)
	if err != nil {
		log.Debugf("bfla: build user2 probe: %v", err)
		return nil
	}
	// Apply the shared API key (app-level credential, not user identity).
	// Do NOT apply the Bearer token: it encodes user1's identity.
	if cctx.APIKey != "" {
		user2Probe.Header.Set("X-Api-Key", cctx.APIKey)
	}

	probeResp, err := cctx.Client.Do(user2Probe)
	if err != nil {
		log.Debugf("bfla: user2 probe failed: %v", err)
		return nil
	}
	defer probeResp.Body.Close()
	io.Copy(io.Discard, probeResp.Body) //nolint:errcheck

	if probeResp.StatusCode >= 200 && probeResp.StatusCode < 300 {
		return []Finding{{
			Checker:     "BFLA",
			Severity:    SeverityHigh,
			Title:       "BFLA: lower-privilege user can access privileged function",
			Detail:      fmt.Sprintf("%s %s: user1 got %d, user2 also got %d (expected 401/403)", req.Method, req.URL.String(), resp.StatusCode, probeResp.StatusCode),
			Method:      req.Method,
			URL:         req.URL.String(),
			StatusCode:  probeResp.StatusCode,
			PathPattern: entry.PathPattern,
			POC:         BuildCurlPOC(user2Probe, entry.Body),
		}}
	}
	return nil
}

// isPrivilegedEndpoint returns true when the path pattern or operation ID
// suggests an elevated-privilege function.
func isPrivilegedEndpoint(entry *corpus.CorpusEntry) bool {
	if adminSegRE.MatchString(entry.PathPattern) {
		return true
	}
	// Operation IDs like "adminGetUsers" or "getAdminConfig" also signal admin scope.
	return strings.Contains(strings.ToLower(entry.OperationID), "admin")
}

// buildBFLAProbe clones req with the given cookies substituted for the Cookie
// header. All existing auth headers are stripped first. Pass cookies=nil for
// an anonymous (unauthenticated) probe.
func buildBFLAProbe(ctx context.Context, req *http.Request, entry *corpus.CorpusEntry, cookies []*http.Cookie) (*http.Request, error) {
	var bodyReader io.Reader
	if req.GetBody != nil {
		if rb, err := req.GetBody(); err == nil {
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

	for key, vals := range req.Header {
		for _, v := range vals {
			probe.Header.Add(key, v)
		}
	}
	probe.Header.Del("Cookie")
	probe.Header.Del("Authorization")
	probe.Header.Del("X-Api-Key")

	for _, c := range cookies {
		probe.AddCookie(c)
	}
	return probe, nil
}
