// Package pathscan probes a target for sensitive paths not declared in the
// OpenAPI spec: debug endpoints, version-divergent routes, admin interfaces,
// framework-specific health/metrics endpoints, and forgotten backups.
//
// It runs once before the main fuzzing loop and reports findings via the same
// checkers.Finding type so they appear in the output directory alongside
// checker findings.
package pathscan

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"shelob-ng/checkers"

	log "github.com/sirupsen/logrus"
)

// sensitiveBodyRE matches response bodies that indicate a path leaks secret
// data even when it returns 2xx.
var sensitiveBodyRE = regexp.MustCompile(
	`(?i)(SECRET_KEY|DATABASE_URL|JWT_SECRET|DB_PASSWORD|AWS_SECRET|PRIVATE_KEY|` +
		`"password"\s*:|process\.env\.|os\.environ|sys\.path|` +
		`"admin"\s*:\s*true|"is_admin"\s*:\s*true)`,
)

// Candidate is a path to probe plus metadata used to build the finding.
type Candidate struct {
	Path        string // e.g. "/debug"
	Description string // human-readable purpose
}

// Scanner probes a fixed set of candidate paths and any user-supplied extras.
type Scanner struct {
	client     *http.Client
	targetURL  string
	authCookies []*http.Cookie
	apiKey     string
	token      string
	extra      []Candidate // from user wordlist
}

// New builds a Scanner. extra is an optional list of additional paths from
// a user-supplied wordlist; pass nil to use only the built-in list.
func New(client *http.Client, targetURL string, authCookies []*http.Cookie, apiKey, token string, extra []Candidate) *Scanner {
	return &Scanner{
		client:     client,
		targetURL:  strings.TrimSuffix(targetURL, "/"),
		authCookies: authCookies,
		apiKey:     apiKey,
		token:      token,
		extra:      extra,
	}
}

// Scan probes all candidate paths and returns findings. It is safe to call
// from the main goroutine before the fuzzing loop starts.
func (s *Scanner) Scan(ctx context.Context) []checkers.Finding {
	paths := append(builtinPaths(), s.extra...)

	scanCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	var findings []checkers.Finding
	seen := make(map[string]bool)

	for _, c := range paths {
		if scanCtx.Err() != nil {
			break
		}
		f := s.probe(scanCtx, c)
		if f == nil {
			continue
		}
		// Deduplicate by checker+URL.
		key := f.DedupeKey()
		if seen[key] {
			continue
		}
		seen[key] = true
		findings = append(findings, *f)
	}
	return findings
}

// probe sends one unauthenticated GET to targetURL+path and returns a finding
// when the response indicates a vulnerability.
func (s *Scanner) probe(ctx context.Context, c Candidate) *checkers.Finding {
	url := s.targetURL + c.Path
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		log.Debugf("pathscan: build request %s: %v", c.Path, err)
		return nil
	}

	// Probe without any authentication — we are looking for publicly
	// accessible endpoints that should be protected.
	resp, err := s.client.Do(req)
	if err != nil {
		log.Debugf("pathscan: %s: %v", c.Path, err)
		return nil
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8*1024))

	switch {
	// Public 2xx with sensitive body content → high severity data exposure.
	case resp.StatusCode >= 200 && resp.StatusCode < 300 && sensitiveBodyRE.Match(body):
		return &checkers.Finding{
			Checker:    "PathDiscovery",
			Severity:   checkers.SeverityHigh,
			Title:      "Sensitive Data Exposed via Hidden Endpoint",
			Detail:     fmt.Sprintf("%s returned %d and body contains sensitive fields (%s)", c.Path, resp.StatusCode, c.Description),
			Method:     "GET",
			URL:        url,
			StatusCode: resp.StatusCode,
			POC:        fmt.Sprintf("curl -v '%s'", url),
		}

	// Public 2xx without sensitive body → unauthenticated access finding.
	// Only report when we have auth credentials so we can confirm the endpoint
	// should be protected (if we're running unauthenticated, everything is expected public).
	case resp.StatusCode >= 200 && resp.StatusCode < 300 &&
		(len(s.authCookies) > 0 || s.token != "" || s.apiKey != ""):
		return s.confirmAuthRequired(ctx, c, url, resp.StatusCode, body)

	// 403 on a typically public-or-internal path suggests the endpoint exists
	// but is IP-restricted — useful intelligence even if not a direct vuln.
	case resp.StatusCode == 403 && strings.Contains(strings.ToLower(c.Description), "admin"):
		return &checkers.Finding{
			Checker:    "PathDiscovery",
			Severity:   checkers.SeverityInfo,
			Title:      "Hidden Admin Endpoint Exists (IP-Restricted)",
			Detail:     fmt.Sprintf("%s returned 403 — endpoint exists but access is restricted (%s)", c.Path, c.Description),
			Method:     "GET",
			URL:        url,
			StatusCode: resp.StatusCode,
			POC:        fmt.Sprintf("curl -v '%s'", url),
		}
	}
	return nil
}

// confirmAuthRequired re-probes with authentication. If the authenticated request
// also succeeds, the endpoint likely returns the same data regardless of auth —
// report a medium finding. If the unauthenticated one succeeds while we have
// credentials, that means the endpoint is public despite possibly being sensitive.
func (s *Scanner) confirmAuthRequired(ctx context.Context, c Candidate, url string, unauthCode int, body []byte) *checkers.Finding {
	// Brief body sniff for common admin indicators.
	lower := strings.ToLower(string(body))
	isAdminLike := strings.Contains(lower, "admin") ||
		strings.Contains(lower, "password") ||
		strings.Contains(lower, "secret") ||
		strings.Contains(lower, "env") ||
		strings.Contains(lower, "config")

	if !isAdminLike {
		return nil // public endpoint returning non-sensitive data — not a finding
	}

	return &checkers.Finding{
		Checker:    "PathDiscovery",
		Severity:   checkers.SeverityMedium,
		Title:      "Unauthenticated Access to Sensitive Endpoint",
		Detail:     fmt.Sprintf("%s returned %d without credentials and response looks sensitive (%s)", c.Path, unauthCode, c.Description),
		Method:     "GET",
		URL:        url,
		StatusCode: unauthCode,
		POC:        fmt.Sprintf("curl -v '%s'", url),
	}
}
