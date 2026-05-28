package checkers

import (
	"context"
	"fmt"
	"io"
	"net/http"

	"shelob-ng/corpus"

	"github.com/getkin/kin-openapi/routers"
	log "github.com/sirupsen/logrus"
)

// AuthBypassRule detects endpoints that are accessible without credentials
// despite declaring authentication requirements in the OpenAPI spec.
//
// Distinction from NameSpaceRule and BFLA:
//   - NameSpaceRule tests object ownership (BOLA): user2 accessing user1's resource.
//     It SKIPS when an anonymous probe returns 2xx (the endpoint is public).
//   - BFLA tests role boundaries: user2 calling an admin function.
//     It also skips on anonymous 2xx.
//   - AuthBypassRule FIRES on anonymous 2xx when the spec declares the operation
//     requires authentication. It directly reports missing auth enforcement.
//
// Detection sequence:
//  1. At least one auth credential must be configured (-user/-password, -token,
//     or -apikey); without auth there is nothing to compare against.
//  2. Primary user (authenticated) gets 2xx — the operation is reachable.
//  3. The OpenAPI spec declares `security` on the operation (primary signal).
//  4. Anonymous probe — no cookies, no token, no API key — also gets 2xx.
//  5. → Server does not enforce the declared auth requirement: HIGH finding.
type AuthBypassRule struct{}

func (AuthBypassRule) Name() string { return "AuthBypassRule" }

func (AuthBypassRule) Check(
	ctx context.Context,
	cctx CheckContext,
	entry *corpus.CorpusEntry,
	req *http.Request,
	resp *http.Response,
	_ []byte,
) []Finding {
	// Only meaningful when the fuzzer is running with authentication.
	if len(cctx.AuthCookies) == 0 && cctx.Token == "" && cctx.APIKey == "" {
		return nil
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil
	}
	if !operationRequiresAuth(cctx, req) {
		return nil
	}

	// Anonymous probe: no cookies, no Authorization, no X-Api-Key.
	probe, err := buildProbeWithCookies(ctx, req, entry, nil)
	if err != nil {
		log.Debugf("authbypass: build probe: %v", err)
		return nil
	}

	probeResp, err := cctx.Client.Do(probe)
	if err != nil {
		log.Debugf("authbypass: probe failed: %v", err)
		return nil
	}
	defer probeResp.Body.Close()
	io.Copy(io.Discard, probeResp.Body) //nolint:errcheck

	if probeResp.StatusCode >= 200 && probeResp.StatusCode < 300 {
		return []Finding{{
			Checker:     "AuthBypassRule",
			Severity:    SeverityHigh,
			Title:       "Auth bypass: protected endpoint accessible without credentials",
			Detail:      fmt.Sprintf("%s %s: authenticated got %d, anonymous also got %d (expected 401/403)", req.Method, req.URL.String(), resp.StatusCode, probeResp.StatusCode),
			Method:      req.Method,
			URL:         req.URL.String(),
			StatusCode:  probeResp.StatusCode,
			PathPattern: entry.PathPattern,
			POC:         BuildCurlPOC(probe, entry.Body),
		}}
	}
	return nil
}

// operationRequiresAuth returns true when the OpenAPI spec declares that the
// operation requires authentication. It uses OASRouter to look up the operation
// and inspect its security declarations.
//
// Decision logic:
//   - op.Security == nil          → inherits global spec security
//   - *op.Security is empty []    → explicitly public (security: [])
//   - *op.Security is non-empty   → explicitly requires auth
//   - global spec.Security non-empty → requires auth (when op inherits)
func operationRequiresAuth(cctx CheckContext, req *http.Request) bool {
	if cctx.OASRouter == nil {
		return false
	}
	route, _, err := cctx.OASRouter.FindRoute(req)
	if err != nil {
		return false
	}
	return routeRequiresAuth(route)
}

// routeRequiresAuth inspects a resolved route's security declarations.
func routeRequiresAuth(route *routers.Route) bool {
	op := route.Operation
	if op == nil {
		return false
	}

	// Operation-level security overrides global.
	if op.Security != nil {
		// security: [] means explicitly public.
		return len(*op.Security) > 0
	}

	// Operation inherits global security.
	if route.Spec != nil {
		return len(route.Spec.Security) > 0
	}
	return false
}
