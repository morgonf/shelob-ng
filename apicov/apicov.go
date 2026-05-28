// Package apicov tracks which OpenAPI spec operations have been exercised
// during a fuzzing session (spec coverage, not code coverage).
//
// Usage:
//
//	tracker := apicov.NewTracker(spec)
//	// after each HTTP response:
//	tracker.Mark(entry.Method, entry.PathPattern, resp.StatusCode)
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

// OpCoverage extends Op with the HTTP status codes observed during fuzzing.
type OpCoverage struct {
	Op
	// StatusCodes maps HTTP status code → number of responses with that code.
	StatusCodes map[int]int `json:"status_codes,omitempty"`
}

func opKey(method, path string) string {
	return strings.ToUpper(method) + " " + path
}

// Tracker records which spec operations have received at least one HTTP
// response and the distribution of observed status codes. Safe for concurrent use.
type Tracker struct {
	mu      sync.RWMutex
	total   []Op
	visited map[string]struct{}
	// codes maps opKey → status code → response count.
	codes map[string]map[int]int
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
		codes:   make(map[string]map[int]int),
	}
}

// Mark records that method+path received an HTTP response with the given status
// code. Any HTTP response (including 4xx/5xx) counts as visited.
func (t *Tracker) Mark(method, path string, statusCode int) {
	key := opKey(method, path)
	t.mu.Lock()
	t.visited[key] = struct{}{}
	if t.codes[key] == nil {
		t.codes[key] = make(map[int]int)
	}
	t.codes[key][statusCode]++
	t.mu.Unlock()
}

// Stats returns (visitedCount, totalCount).
func (t *Tracker) Stats() (visited, total int) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.visited), len(t.total)
}

// Visited returns operations that have been exercised, sorted by path+method,
// each annotated with the observed status-code distribution.
func (t *Tracker) Visited() []OpCoverage {
	t.mu.RLock()
	defer t.mu.RUnlock()

	var out []OpCoverage
	for _, op := range t.total {
		key := opKey(op.Method, op.Path)
		if _, ok := t.visited[key]; ok {
			cov := OpCoverage{Op: op}
			if m := t.codes[key]; len(m) > 0 {
				cov.StatusCodes = make(map[int]int, len(m))
				for code, cnt := range m {
					cov.StatusCodes[code] = cnt
				}
			}
			out = append(out, cov)
		}
	}
	return out
}

// Unvisited returns operations that have not been exercised yet, sorted by path+method.
func (t *Tracker) Unvisited() []Op {
	t.mu.RLock()
	defer t.mu.RUnlock()

	var out []Op
	for _, op := range t.total {
		if _, ok := t.visited[opKey(op.Method, op.Path)]; !ok {
			out = append(out, op)
		}
	}
	return out
}

// Report is the JSON structure written by SaveJSON.
type Report struct {
	Total          int          `json:"total"`
	VisitedCount   int          `json:"visited_count"`
	UnvisitedCount int          `json:"unvisited_count"`
	Visited        []OpCoverage `json:"visited"`
	Unvisited      []Op         `json:"unvisited"`
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
// Shows percentage, per-endpoint status-code distribution for visited ops,
// and a list of unvisited operations.
func (t *Tracker) Print(w io.Writer) {
	vis, total := t.Stats()
	pct := 0.0
	if total > 0 {
		pct = 100 * float64(vis) / float64(total)
	}
	fmt.Fprintf(w, "\n=== API spec coverage: %d/%d operations (%.0f%%) ===\n", vis, total, pct)

	visited := t.Visited()
	if len(visited) > 0 {
		fmt.Fprintf(w, "\nVisited (%d):\n", len(visited))
		for _, op := range visited {
			codes := formatCodes(op.StatusCodes)
			if op.OperationID != "" {
				fmt.Fprintf(w, "  %-8s %-45s  %s  (%s)\n", op.Method, op.Path, codes, op.OperationID)
			} else {
				fmt.Fprintf(w, "  %-8s %-45s  %s\n", op.Method, op.Path, codes)
			}
		}
	}

	unvisited := t.Unvisited()
	if len(unvisited) == 0 {
		fmt.Fprintln(w, "\nAll spec operations were exercised.")
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

// formatCodes renders a status-code map as "200:42 404:5 500:1" sorted by code.
func formatCodes(codes map[int]int) string {
	if len(codes) == 0 {
		return ""
	}
	keys := make([]int, 0, len(codes))
	for k := range codes {
		keys = append(keys, k)
	}
	sort.Ints(keys)

	var sb strings.Builder
	for i, k := range keys {
		if i > 0 {
			sb.WriteByte(' ')
		}
		fmt.Fprintf(&sb, "%d:%d", k, codes[k])
	}
	return sb.String()
}
