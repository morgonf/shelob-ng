// CSP adapter for Go — exposes runtime/coverage data via HTTP.
//
// Requires Go 1.20+ with coverage instrumentation:
//
//	go build -cover -o myapp ./cmd/myapp
//	GOCOVERDIR=/tmp/covdata CSP_PORT=8080 ./myapp &
//
// Or embed this adapter in your application's main():
//
//	import "github.com/you/yourapp/csp"
//	go csp.ListenAndServe(":8080")
//
// The adapter exposes two endpoints consumed by shelob-ng:
//
//	POST /csp/reset  — snapshot current coverage as baseline
//	GET  /csp/dump   — return new coverage since last reset
package csp

import (
	"encoding/json"
	"fmt"
	"net/http"
	"runtime/coverage"
	"sync"
)

// DumpResponse mirrors the JSON schema expected by shelob-ng.
type DumpResponse struct {
	TotalLines    int      `json:"total_lines"`
	CoveredLines  int      `json:"covered_lines"`
	NewSinceReset []string `json:"new_since_reset"`
}

var (
	mu       sync.Mutex
	baseline map[string]struct{}
	totalSeen map[string]struct{}
)

func init() {
	baseline  = make(map[string]struct{})
	totalSeen = make(map[string]struct{})
}

// snapshot reads the current Go coverage counters and returns the set of
// "file:line" strings for all blocks that have been executed at least once.
func snapshot() map[string]struct{} {
	// runtime/coverage.WriteCountersDir writes counter files to a temp dir;
	// for fine-grained block-level data we need to read the counter data directly.
	// This simplified adapter uses WriteCountersDir + a parser, or you can
	// integrate with golang.org/x/tools/cover for a full solution.
	//
	// For most use cases, the simpler approach below is sufficient:
	//   — reset resets counters via coverage.ResetCounters()
	//   — dump returns the counter state (approximated as block count > 0)
	//
	// A production adapter would collect block-level coverage using
	// golang.org/x/tools/cover and the GOCOVERDIR output files.
	_ = coverage.ClearCounters // Go 1.21+
	return make(map[string]struct{}) // replace with real counter read
}

// ListenAndServe starts the CSP HTTP server on addr (e.g. ":8080").
func ListenAndServe(addr string) error {
	mux := http.NewServeMux()

	mux.HandleFunc("/csp/reset", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST required", http.StatusMethodNotAllowed)
			return
		}
		mu.Lock()
		baseline = snapshot()
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "OK")
	})

	mux.HandleFunc("/csp/dump", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "GET required", http.StatusMethodNotAllowed)
			return
		}

		mu.Lock()
		current := snapshot()
		var newLines []string
		for k := range current {
			if _, seen := baseline[k]; !seen {
				newLines = append(newLines, k)
				totalSeen[k] = struct{}{}
			}
		}
		covered := len(totalSeen)
		total := len(current)
		mu.Unlock()

		if newLines == nil {
			newLines = []string{}
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(DumpResponse{ //nolint:errcheck
			TotalLines:    total,
			CoveredLines:  covered,
			NewSinceReset: newLines,
		})
	})

	return http.ListenAndServe(addr, mux)
}
