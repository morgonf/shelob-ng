// Package apicov tracks which OpenAPI spec operations have been exercised
// during a fuzzing session (spec coverage, not code coverage).
//
// Usage:
//
//	tracker := apicov.NewTracker(spec)
//	// after each HTTP response:
//	tracker.Mark(entry.Method, entry.PathPattern)
//	// at the end:
//	visited, total := tracker.Stats()
//	tracker.SaveJSON(filepath.Join(outputDir, "api-coverage.json"))
package apicov

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"sync"

	"github.com/getkin/kin-openapi/openapi3"
)

// Op describes a single operation from the OpenAPI spec.
type Op struct {
	Method      string   `json:"method"`
	Path        string   `json:"path"`
	OperationID string   `json:"operationId,omitempty"`
	Tags        []string `json:"tags,omitempty"`
}

func opKey(method, path string) string {
	return strings.ToUpper(method) + " " + path
}

// Tracker records which spec operations have received at least one HTTP
// response. Safe for concurrent use.
type Tracker struct {
	mu      sync.RWMutex
	total   []Op
	visited map[string]struct{}
}

// NewTracker builds a Tracker pre-populated with every operation in spec.
func NewTracker(spec *openapi3.T) *Tracker {
	var ops []Op
	for path, item := range spec.Paths.Map() {
		if item == nil {
			continue
		}
		for method, op := range item.Operations() {
			entry := Op{
				Method: strings.ToUpper(method),
				Path:   path,
			}
			if op != nil {
				entry.OperationID = op.OperationID
				entry.Tags = op.Tags
			}
			ops = append(ops, entry)
		}
	}
	sort.Slice(ops, func(i, j int) bool {
		if ops[i].Path != ops[j].Path {
			return ops[i].Path < ops[j].Path
		}
		return ops[i].Method < ops[j].Method
	})
	return &Tracker{
		total:   ops,
		visited: make(map[string]struct{}),
	}
}

// Mark records that method+path received an HTTP response this session.
// Any HTTP response (including 4xx/5xx) counts — the endpoint was reached.
func (t *Tracker) Mark(method, path string) {
	t.mu.Lock()
	t.visited[opKey(method, path)] = struct{}{}
	t.mu.Unlock()
}

// Stats returns (visitedCount, totalCount).
func (t *Tracker) Stats() (visited, total int) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.visited), len(t.total)
}

// Visited returns operations that have been exercised, sorted by path+method.
func (t *Tracker) Visited() []Op {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.filter(true)
}

// Unvisited returns operations that have not been exercised yet, sorted by path+method.
func (t *Tracker) Unvisited() []Op {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.filter(false)
}

// filter returns ops where (in visited map) == want. Must be called under RLock.
func (t *Tracker) filter(want bool) []Op {
	var out []Op
	for _, op := range t.total {
		_, ok := t.visited[opKey(op.Method, op.Path)]
		if ok == want {
			out = append(out, op)
		}
	}
	return out
}

// Report is the JSON structure written by SaveJSON.
type Report struct {
	Total          int  `json:"total"`
	VisitedCount   int  `json:"visited_count"`
	UnvisitedCount int  `json:"unvisited_count"`
	Visited        []Op `json:"visited"`
	Unvisited      []Op `json:"unvisited"`
}

// SaveJSON writes a coverage report as JSON to path.
func (t *Tracker) SaveJSON(path string) error {
	vis := t.Visited()
	unvis := t.Unvisited()
	r := Report{
		Total:          len(t.total),
		VisitedCount:   len(vis),
		UnvisitedCount: len(unvis),
		Visited:        vis,
		Unvisited:      unvis,
	}
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o644)
}

// Print writes a human-readable summary to w.
// Shows percentage and lists unvisited operations.
func (t *Tracker) Print(w io.Writer) {
	vis, total := t.Stats()
	pct := 0.0
	if total > 0 {
		pct = 100 * float64(vis) / float64(total)
	}
	fmt.Fprintf(w, "\n=== API spec coverage: %d/%d operations (%.0f%%) ===\n", vis, total, pct)

	unvisited := t.Unvisited()
	if len(unvisited) == 0 {
		fmt.Fprintln(w, "All spec operations were exercised.")
		return
	}
	fmt.Fprintf(w, "\nNot yet visited (%d):\n", len(unvisited))
	for _, op := range unvisited {
		if op.OperationID != "" {
			fmt.Fprintf(w, "  %-8s %-45s  (%s)\n", op.Method, op.Path, op.OperationID)
		} else {
			fmt.Fprintf(w, "  %-8s %s\n", op.Method, op.Path)
		}
	}
}
