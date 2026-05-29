package pathscan

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestParseWordlistLine_Valid(t *testing.T) {
	cases := []struct {
		line    string
		path    string
		hasDesc bool
	}{
		{"/debug", "/debug", false},
		{"debug", "/debug", false},
		{"/admin\tadmin panel", "/admin", true},
		{"  /config  ", "/config", false},
	}
	for _, tc := range cases {
		c, ok := ParseWordlistLine(tc.line)
		if !ok {
			t.Errorf("ParseWordlistLine(%q) returned false", tc.line)
			continue
		}
		if c.Path != tc.path {
			t.Errorf("path: got %q, want %q", c.Path, tc.path)
		}
		if tc.hasDesc && c.Description == "user-supplied wordlist entry" {
			t.Errorf("expected custom description for %q", tc.line)
		}
	}
}

func TestParseWordlistLine_SkipsComments(t *testing.T) {
	for _, line := range []string{"# comment", "  # comment", ""} {
		_, ok := ParseWordlistLine(line)
		if ok {
			t.Errorf("expected skip for %q", line)
		}
	}
}

func TestBuiltinPaths_NotEmpty(t *testing.T) {
	paths := builtinPaths()
	if len(paths) < 20 {
		t.Errorf("expected ≥20 built-in paths, got %d", len(paths))
	}
	for _, c := range paths {
		if !strings.HasPrefix(c.Path, "/") {
			t.Errorf("path %q does not start with /", c.Path)
		}
		if c.Description == "" {
			t.Errorf("empty description for path %q", c.Path)
		}
	}
}

// TestScan_FindsSensitiveEndpoint verifies that a server returning env data
// on /debug triggers a HIGH finding.
func TestScan_FindsSensitiveEndpoint(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/debug" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(200)
			w.Write([]byte(`{"SECRET_KEY":"abc123","DATABASE_URL":"postgres://..."}`))
			return
		}
		w.WriteHeader(404)
	}))
	defer srv.Close()

	scanner := New(srv.Client(), srv.URL, nil, "", "", nil)
	findings := scanner.Scan(context.Background())

	var found bool
	for _, f := range findings {
		if f.PathPattern == "" && strings.Contains(f.URL, "/debug") && f.Severity == "high" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected HIGH finding for /debug exposing SECRET_KEY, got: %v", findings)
	}
}

// TestScan_SkipsNonSensitive2xx verifies that a public /health endpoint
// returning non-sensitive data does not produce a finding.
func TestScan_SkipsNonSensitive2xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte(`{"status":"ok"}`))
	}))
	defer srv.Close()

	// No auth configured — all paths are "public by intent", should not fire.
	scanner := New(srv.Client(), srv.URL, nil, "", "", nil)
	findings := scanner.Scan(context.Background())

	for _, f := range findings {
		if f.Severity == "high" || f.Severity == "medium" {
			t.Errorf("unexpected finding on non-sensitive server: %+v", f)
		}
	}
}

// TestScan_Reports403AdminAsInfo verifies that an admin endpoint returning 403
// produces an INFO finding.
func TestScan_Reports403AdminAsInfo(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/admin") {
			w.WriteHeader(403)
			return
		}
		w.WriteHeader(404)
	}))
	defer srv.Close()

	scanner := New(srv.Client(), srv.URL, nil, "", "", nil)
	findings := scanner.Scan(context.Background())

	var found bool
	for _, f := range findings {
		if strings.Contains(f.URL, "/admin") && f.Severity == "info" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected INFO finding for /admin returning 403")
	}
}

// TestScan_ExtraWordlist verifies that user-supplied paths are also probed.
func TestScan_ExtraWordlist(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/custom-secret" {
			w.WriteHeader(200)
			w.Write([]byte(`{"SECRET_KEY":"leaked"}`))
			return
		}
		w.WriteHeader(404)
	}))
	defer srv.Close()

	extra := []Candidate{{Path: "/custom-secret", Description: "custom secret path"}}
	scanner := New(srv.Client(), srv.URL, nil, "apikey", "", extra)
	findings := scanner.Scan(context.Background())

	var found bool
	for _, f := range findings {
		if strings.Contains(f.URL, "/custom-secret") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected finding for user-supplied /custom-secret")
	}
}
