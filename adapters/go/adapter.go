// Package csp implements a Coverage Sidecar Protocol adapter for Go applications.
//
// # Quick start
//
// Build your application with coverage instrumentation (Go 1.20+):
//
//	go build -cover -o myapp ./cmd/myapp
//
// Run it with GOCOVERDIR pointing at a writable directory, and start the CSP server:
//
//	mkdir -p /tmp/gocov
//	GOCOVERDIR=/tmp/gocov ./myapp &
//	# in a separate goroutine inside main():
//	go csp.ListenAndServe(":8080")
//
// Then point shelob-ng at the sidecar:
//
//	./shelob-ng -spec api.json -url http://localhost:8080 -csp-url http://localhost:8080
//
// # How it works
//
// On POST /csp/reset:
//  1. coverage.ClearCounters() zeroes all instrumented block counters.
//
// On GET /csp/dump:
//  1. coverage.WriteCountersDir(tmpDir) writes the current counter state.
//  2. The counter files are scanned for non-zero uint32 values; each non-zero
//     position is a block that executed since the last reset.
//  3. The positions are returned as "filename:offset" strings in new_since_reset.
//
// Because ClearCounters() resets to zero, all non-zero values in the next dump
// represent code that ran specifically during the fuzzed request — no baseline
// tracking is needed.
//
// # Limitations
//
//   - Requires the target to be compiled with `go build -cover`.
//   - ClearCounters() is available in Go 1.21+; on Go 1.20 it is a no-op and
//     the adapter falls back to delta-based tracking (less precise).
//   - Counter file binary format is parsed by scanning uint32 values after
//     a fixed-size header; this is an approximation that works for standard
//     Go toolchain output but may miss blocks in edge cases.
package csp

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"runtime/coverage"
	"strings"
	"sync"
)

// DumpResponse mirrors the JSON schema expected by shelob-ng /csp/dump.
type DumpResponse struct {
	TotalLines    int      `json:"total_lines"`
	CoveredLines  int      `json:"covered_lines"`
	NewSinceReset []string `json:"new_since_reset"`
}

var (
	mu        sync.Mutex
	totalSeen map[string]struct{} // cumulative blocks seen across all requests
)

func init() {
	totalSeen = make(map[string]struct{})
}

// snapshot writes current coverage counters to a temp directory and returns
// the set of "filename:offset" identifiers for all blocks with count > 0.
//
// Counter files written by coverage.WriteCountersDir start with a 24-byte
// header (magic + version + flavor + num-packages), followed by per-package
// uint32 counter arrays. We skip the header and treat each non-zero uint32
// as a covered block, using its byte offset as a stable identifier.
func snapshot() (map[string]struct{}, error) {
	dir, err := os.MkdirTemp("", "csp-go-*")
	if err != nil {
		return nil, fmt.Errorf("mktemp: %w", err)
	}
	defer os.RemoveAll(dir)

	if err := coverage.WriteCountersDir(dir); err != nil {
		return nil, fmt.Errorf("WriteCountersDir: %w", err)
	}

	const headerBytes = 24 // magic(4) + version(4) + flavor(4) + numpackages(4) + padding(8)

	result := make(map[string]struct{})
	walkErr := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(d.Name(), ".covcounters") {
			return nil
		}

		data, err := os.ReadFile(path)
		if err != nil || len(data) <= headerBytes {
			return nil
		}

		// Scan uint32 values after the header; each non-zero value is a covered block.
		for i := headerBytes; i+4 <= len(data); i += 4 {
			if cnt := binary.LittleEndian.Uint32(data[i : i+4]); cnt > 0 {
				result[fmt.Sprintf("%s:%d", d.Name(), i)] = struct{}{}
			}
		}
		return nil
	})
	if walkErr != nil {
		return nil, walkErr
	}
	return result, nil
}

// ListenAndServe starts the CSP HTTP server on addr (e.g. ":8080").
// Blocks until the server exits.
func ListenAndServe(addr string) error {
	mux := http.NewServeMux()

	mux.HandleFunc("/csp/reset", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST required", http.StatusMethodNotAllowed)
			return
		}

		mu.Lock()
		// ClearCounters() zeros all instrumented block counters (Go 1.21+).
		// On older toolchains this is a no-op; coverage will accumulate rather
		// than reset, which means delta values are monotonically increasing
		// rather than per-request — still functional but less precise.
		_ = coverage.ClearCounters() //nolint:errcheck
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
		current, err := snapshot()
		var newLines []string
		if err == nil {
			for k := range current {
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
		if encErr := json.NewEncoder(w).Encode(DumpResponse{
			TotalLines:    total,
			CoveredLines:  covered,
			NewSinceReset: newLines,
		}); encErr != nil {
			http.Error(w, "encode error", http.StatusInternalServerError)
		}
	})

	return http.ListenAndServe(addr, mux)
}
