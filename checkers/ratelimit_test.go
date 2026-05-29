package checkers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"

	"shelob-ng/corpus"
)

// makeRespWithCode builds a minimal *http.Response for the given status code.
func makeRespWithCode(code int) *http.Response {
	return &http.Response{
		StatusCode: code,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       http.NoBody,
	}
}

// makeReqTo builds a minimal GET request to the given URL.
func makeReqTo(rawURL string) *http.Request {
	u, _ := url.Parse(rawURL)
	return &http.Request{
		Method: "GET",
		URL:    u,
		Header: http.Header{},
	}
}

func makeEntry(method, pattern string) *corpus.CorpusEntry {
	return &corpus.CorpusEntry{
		Method:       method,
		PathPattern:  pattern,
		PathParams:   map[string]interface{}{},
		QueryParams:  map[string]string{},
		HeaderParams: map[string]string{},
		CookieParams: map[string]string{},
	}
}

// --- summariseCodes ---

func TestSummariseCodes_SingleCode(t *testing.T) {
	got := summariseCodes([]int{200, 200, 200})
	if got != "200×3" {
		t.Errorf("unexpected: %q", got)
	}
}

func TestSummariseCodes_MultipleCodes(t *testing.T) {
	got := summariseCodes([]int{200, 200, 401})
	if got != "200×2 401×1" {
		t.Errorf("unexpected: %q", got)
	}
}

func TestSummariseCodes_PreservesOrder(t *testing.T) {
	got := summariseCodes([]int{401, 200, 401, 200, 200})
	if got != "401×2 200×3" {
		t.Errorf("unexpected: %q", got)
	}
}

// --- authPathRE ---

func TestAuthPathRE_Matches(t *testing.T) {
	positives := []string{
		"/api/login",
		"/users/v1/login",
		"/rest/user/login",
		"/auth/token",
		"/identity/api/auth/v2/check-otp",
		"/users/register",
		"/reset-password",
		"/forgot-password",
		"/api/verify",
		"/users/2fa/setup",
	}
	for _, p := range positives {
		if !authPathRE.MatchString(p) {
			t.Errorf("expected match for %q", p)
		}
	}
}

func TestAuthPathRE_NoFalsePositives(t *testing.T) {
	negatives := []string{
		"/api/products",
		"/rest/basket/1",
		"/api/Users",
		"/orders/42",
		"/admin/users",
	}
	for _, p := range negatives {
		if authPathRE.MatchString(p) {
			t.Errorf("unexpected match for %q", p)
		}
	}
}

// --- RateLimitChecker.Check ---

// TestRateLimit_SkipsOn429 verifies that a 429 response resets suspicion:
// the checker must not count 429 responses toward the threshold.
func TestRateLimit_SkipsOn429(t *testing.T) {
	chk := NewRateLimitChecker()
	entry := makeEntry("POST", "/api/login")
	req := makeReqTo("http://localhost/api/login")
	resp429 := makeRespWithCode(429)

	for i := 0; i < authBurstThreshold+5; i++ {
		findings := chk.Check(context.Background(), CheckContext{}, entry, req, resp429, nil)
		if len(findings) > 0 {
			t.Fatalf("should not find anything when server returns 429: %+v", findings[0])
		}
	}
}

// TestRateLimit_SkipsOn5xx verifies that server errors are ignored.
func TestRateLimit_SkipsOn5xx(t *testing.T) {
	chk := NewRateLimitChecker()
	entry := makeEntry("POST", "/api/login")
	req := makeReqTo("http://localhost/api/login")
	resp500 := makeRespWithCode(500)

	for i := 0; i < generalBurstThreshold+5; i++ {
		findings := chk.Check(context.Background(), CheckContext{}, entry, req, resp500, nil)
		if len(findings) > 0 {
			t.Fatalf("should not fire on 5xx: %+v", findings[0])
		}
	}
}

// TestRateLimit_BelowThreshold verifies no finding before threshold is reached.
func TestRateLimit_BelowThreshold(t *testing.T) {
	chk := NewRateLimitChecker()
	entry := makeEntry("POST", "/api/login")
	req := makeReqTo("http://localhost/api/login")

	// Use a server that never returns 429 to avoid early exit in burst.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
	}))
	defer srv.Close()

	req, _ = http.NewRequest("POST", srv.URL+"/api/login", nil)
	cctx := CheckContext{Client: srv.Client()}

	for i := 0; i < authBurstThreshold-1; i++ {
		resp := makeRespWithCode(401)
		findings := chk.Check(context.Background(), cctx, entry, req, resp, nil)
		if len(findings) > 0 {
			t.Fatalf("should not fire before threshold (iteration %d)", i)
		}
	}
}

// TestRateLimit_FiresOnAuthEndpoint verifies HIGH finding when an auth endpoint
// never returns 429 across natural traffic + burst.
func TestRateLimit_FiresOnAuthEndpoint(t *testing.T) {
	// Server never returns 429 — simulates missing rate limiting.
	var callCount atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		callCount.Add(1)
		w.WriteHeader(401) // wrong credentials, but no rate limit
	}))
	defer srv.Close()

	chk := NewRateLimitChecker()
	entry := makeEntry("POST", "/users/v1/login")
	req, _ := http.NewRequest("POST", srv.URL+"/users/v1/login", nil)
	cctx := CheckContext{Client: srv.Client()}

	var findings []Finding
	// Drive the checker past the auth threshold.
	for i := 0; i <= authBurstThreshold; i++ {
		resp := makeRespWithCode(401)
		findings = chk.Check(context.Background(), cctx, entry, req, resp, nil)
		if len(findings) > 0 {
			break
		}
	}

	if len(findings) == 0 {
		t.Fatal("expected a finding for auth endpoint with no rate limiting")
	}
	f := findings[0]
	if f.Severity != SeverityHigh {
		t.Errorf("expected HIGH severity for auth endpoint, got %q", f.Severity)
	}
	if f.Checker != "RateLimitChecker" {
		t.Errorf("wrong checker name: %q", f.Checker)
	}
	if callCount.Load() < int32(burstSize) {
		t.Errorf("expected at least %d burst calls, got %d", burstSize, callCount.Load())
	}
}

// TestRateLimit_NoFindingWhenBurstReturns429 verifies that if the burst triggers
// a 429, no finding is emitted.
func TestRateLimit_NoFindingWhenBurstReturns429(t *testing.T) {
	// Server returns 200 for first N requests, then 429.
	var callCount atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := callCount.Add(1)
		if n > 3 {
			w.WriteHeader(429)
		} else {
			w.WriteHeader(200)
		}
	}))
	defer srv.Close()

	chk := NewRateLimitChecker()
	entry := makeEntry("POST", "/users/v1/login")
	req, _ := http.NewRequest("POST", srv.URL+"/users/v1/login", nil)
	cctx := CheckContext{Client: srv.Client()}

	var findings []Finding
	for i := 0; i <= authBurstThreshold; i++ {
		resp := makeRespWithCode(200)
		findings = chk.Check(context.Background(), cctx, entry, req, resp, nil)
		if len(findings) > 0 {
			break
		}
	}

	if len(findings) > 0 {
		t.Errorf("should not find when burst eventually returns 429: %+v", findings[0])
	}
}

// TestRateLimit_GeneralEndpointUsesMediumSeverity verifies MEDIUM severity
// for non-auth paths.
func TestRateLimit_GeneralEndpointUsesMediumSeverity(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
	}))
	defer srv.Close()

	chk := NewRateLimitChecker()
	entry := makeEntry("GET", "/api/products")
	req, _ := http.NewRequest("GET", srv.URL+"/api/products", nil)
	cctx := CheckContext{Client: srv.Client()}

	var findings []Finding
	for i := 0; i <= generalBurstThreshold; i++ {
		resp := makeRespWithCode(200)
		findings = chk.Check(context.Background(), cctx, entry, req, resp, nil)
		if len(findings) > 0 {
			break
		}
	}

	if len(findings) == 0 {
		t.Fatal("expected a finding for general endpoint with no rate limiting")
	}
	if findings[0].Severity != SeverityMedium {
		t.Errorf("expected MEDIUM severity, got %q", findings[0].Severity)
	}
}

// TestRateLimit_FiresOnlyOnce verifies that the burst is sent exactly once per
// endpoint even when the threshold is crossed many times concurrently.
func TestRateLimit_FiresOnlyOnce(t *testing.T) {
	var burstCallCount atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		burstCallCount.Add(1)
		w.WriteHeader(200)
	}))
	defer srv.Close()

	chk := NewRateLimitChecker()
	entry := makeEntry("POST", "/api/login")
	req, _ := http.NewRequest("POST", srv.URL+"/api/login", nil)
	cctx := CheckContext{Client: srv.Client()}

	var totalFindings int
	// Send well above the threshold.
	for i := 0; i < authBurstThreshold*3; i++ {
		resp := makeRespWithCode(401)
		findings := chk.Check(context.Background(), cctx, entry, req, resp, nil)
		totalFindings += len(findings)
	}

	if totalFindings > 1 {
		t.Errorf("expected at most 1 finding per endpoint, got %d", totalFindings)
	}
	// burstCallCount should be exactly burstSize (one burst, never repeated).
	if burstCallCount.Load() > int32(burstSize) {
		t.Errorf("burst fired more than once: %d calls (expected %d)", burstCallCount.Load(), burstSize)
	}
}
