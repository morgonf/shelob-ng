package checkers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"shelob-ng/corpus"

	log "github.com/sirupsen/logrus"
)

// poisonFields are extra fields injected into POST/PUT/PATCH bodies to test
// whether the server accepts and persists values that should be server-side only.
// Keys cover common privilege-escalation patterns across different frameworks.
var poisonFields = map[string]interface{}{
	"role":       "admin",
	"admin":      true,
	"isAdmin":    true,
	"is_admin":   true,
	"superuser":  true,
	"verified":   true,
	"premium":    true,
	"credits":    99999,
	"balance":    99999,
	"permission": "admin",
}

// MassAssignment detects when a server accepts JSON body fields that should
// be server-side only (role, admin, credits, etc.) without validation error.
//
// Detection sequence:
//  1. Trigger: POST/PUT/PATCH returns 2xx — the operation succeeded.
//  2. Clone the request and inject poisonFields into the JSON body.
//  3. Send the probe:
//     - 4xx/422 response → server correctly rejects extra fields → no finding.
//     - 2xx AND probe response body contains an injected field value → HIGH.
//     - 2xx AND probe response body does not reflect the injected values
//       → MEDIUM (fields accepted without error, but effect unknown).
//
// Requires a JSON request body. Silently skips non-JSON, GET, DELETE requests.
type MassAssignment struct{}

func (MassAssignment) Name() string { return "MassAssignment" }

func (MassAssignment) Check(
	ctx context.Context,
	cctx CheckContext,
	entry *corpus.CorpusEntry,
	req *http.Request,
	resp *http.Response,
	_ []byte,
) []Finding {
	// Only applicable to state-changing methods with a JSON body.
	if req.Method != "POST" && req.Method != "PUT" && req.Method != "PATCH" {
		return nil
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil // primary request must have succeeded
	}
	if !strings.Contains(req.Header.Get("Content-Type"), "application/json") {
		return nil
	}
	if len(entry.Body) == 0 {
		return nil
	}

	// Parse the original body.
	var original map[string]interface{}
	if err := json.Unmarshal(entry.Body, &original); err != nil {
		return nil // not a JSON object
	}

	// Build probe body: original fields + poison fields.
	probe := make(map[string]interface{}, len(original)+len(poisonFields))
	for k, v := range original {
		probe[k] = v
	}
	for k, v := range poisonFields {
		// Don't overwrite existing spec-declared fields — we only inject extras.
		if _, exists := original[k]; !exists {
			probe[k] = v
		}
	}

	probeBody, err := json.Marshal(probe)
	if err != nil {
		return nil
	}

	// Build probe using buildProbeWithCookies (strips stale auth headers, then
	// re-applies them) to avoid copying a stale Content-Length from the original
	// request that would mismatch the larger poison-fields body.
	probeEntry := entry.Clone()
	probeEntry.Body = probeBody
	probeReq, err := buildProbeWithCookies(ctx, req, probeEntry, cctx.AuthCookies)
	if err != nil {
		log.Debugf("massassignment: build probe: %v", err)
		return nil
	}
	ApplyAuth(probeReq, cctx.APIKey, cctx.Token)
	probeReq.Header.Set("Content-Type", "application/json")

	probeResp, err := cctx.Client.Do(probeReq)
	if err != nil {
		log.Debugf("massassignment: probe failed: %v", err)
		return nil
	}
	defer probeResp.Body.Close()
	probeRespBody, _ := io.ReadAll(io.LimitReader(probeResp.Body, 64*1024))

	// Any 4xx means the server rejected the probe — no finding.
	// (422 and 400 are subsumed by the >= 400 check.)
	if probeResp.StatusCode >= 400 {
		return nil
	}

	// 2xx: server accepted the probe with poison fields. Now check the response.
	reflected := checkReflection(probeRespBody)

	if len(reflected) > 0 {
		return []Finding{{
			Checker:     "MassAssignment",
			Severity:    SeverityHigh,
			Title:       "Mass Assignment: Injected Fields Reflected in Response",
			Detail:      fmt.Sprintf("%s %s: poison fields accepted AND reflected: %s", req.Method, req.URL.String(), strings.Join(reflected, ", ")),
			Method:      req.Method,
			URL:         req.URL.String(),
			StatusCode:  probeResp.StatusCode,
			PathPattern: entry.PathPattern,
			POC:         BuildCurlPOC(probeReq, probeBody),
		}}
	}

	// Fields silently accepted — server didn't complain but we can't confirm
	// they were persisted without a follow-up GET (which we skip here for simplicity).
	return []Finding{{
		Checker:     "MassAssignment",
		Severity:    SeverityMedium,
		Title:       "Mass Assignment: Extra Fields Accepted Without Validation Error",
		Detail:      fmt.Sprintf("%s %s: request with extra fields (role, admin, credits) returned %d — server may silently accept privilege-escalation fields", req.Method, req.URL.String(), probeResp.StatusCode),
		Method:      req.Method,
		URL:         req.URL.String(),
		StatusCode:  probeResp.StatusCode,
		PathPattern: entry.PathPattern,
		POC:         BuildCurlPOC(probeReq, probeBody),
	}}
}

// checkReflection parses the probe response body and returns the names of any
// poison fields whose injected values appear verbatim in the response.
func checkReflection(body []byte) []string {
	if len(body) == 0 {
		return nil
	}
	var respObj map[string]interface{}
	if err := json.Unmarshal(body, &respObj); err != nil {
		return nil
	}

	var reflected []string
	for field, injected := range poisonFields {
		if val, ok := deepGet(respObj, field); ok {
			// Compare via json.Marshal so Go types and JSON types are normalised
			// identically: bool true→"true", int 99999→"99999", and JSON float64
			// representations are handled consistently regardless of the server's
			// exact numeric encoding (99999 vs 99999.0 vs 9.9999e4).
			injJSON, err1 := json.Marshal(injected)
			valJSON, err2 := json.Marshal(val)
			if err1 == nil && err2 == nil && string(injJSON) == string(valJSON) {
				reflected = append(reflected, field)
			}
		}
	}
	return reflected
}

// deepGet looks up key in obj at any nesting level (first occurrence wins).
func deepGet(obj map[string]interface{}, key string) (interface{}, bool) {
	if v, ok := obj[key]; ok {
		return v, true
	}
	for _, v := range obj {
		if nested, ok := v.(map[string]interface{}); ok {
			if val, found := deepGet(nested, key); found {
				return val, true
			}
		}
	}
	return nil, false
}
