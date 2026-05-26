// Package corpus implements the fuzzing corpus: storage of inputs that
// increased code coverage, weighted selection for mutation, and a dynamic
// value pool that extracts real IDs/tokens from API responses for reuse.
package corpus

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"math"
	"time"
)

// CorpusEntry holds everything needed to reproduce and mutate one HTTP request.
// Fields are kept separate by parameter location so the mutator can target
// any dimension (path, query, header, body) independently.
//
// Serializable to JSON for on-disk corpus persistence.
type CorpusEntry struct {
	// OpenAPI operation identity
	Method      string `json:"method"`       // "GET", "POST", "PUT", "DELETE", etc.
	PathPattern string `json:"path_pattern"` // template path, e.g. "/users/{id}"
	OperationID string `json:"operation_id"` // may be empty if spec omits it

	// Request parameters, stored by location for independent mutation
	PathParams   pathParamsMap     `json:"path_params"`   // {"id": 42, "name": "alice"}
	QueryParams  map[string]string `json:"query_params"`  // simplified: one value per key
	HeaderParams map[string]string `json:"header_params"` // user-defined headers only
	CookieParams map[string]string `json:"cookie_params"`

	// Request body
	Body        []byte `json:"body"`         // raw bytes; nil when no body
	ContentType string `json:"content_type"` // "application/json", "application/xml", etc.

	// Corpus metrics used for weighted selection and eviction
	CoverageDelta uint64    `json:"coverage_delta"` // new lines covered when this entry was added
	AddedAt       time.Time `json:"added_at"`
	UseCount      uint64    `json:"use_count"`  // times selected for mutation
	Generation    uint32    `json:"generation"` // 0 = seed from spec, incremented per mutation

	// Computed on first access, not persisted (recalculated after Load).
	hash string `json:"-"`
}

// pathParamsMap wraps map[string]interface{} with a custom JSON unmarshaler
// that preserves numeric types as json.Number instead of float64.
// Without this, an id like 42 would round-trip through JSON as float64(42),
// corrupting integer path parameters when replaying saved corpus entries.
type pathParamsMap map[string]interface{}

func (m *pathParamsMap) UnmarshalJSON(data []byte) error {
	raw := map[string]json.RawMessage{}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	result := make(pathParamsMap, len(raw))
	for k, v := range raw {
		var val interface{}
		// Use a fresh decoder per value with UseNumber() so that numeric values
		// are preserved as json.Number rather than silently widened to float64.
		// json.Unmarshal(v, &val) would give float64(42) for the JSON literal 42,
		// breaking integer path parameters when replaying a saved corpus entry.
		d := json.NewDecoder(bytes.NewReader(v))
		d.UseNumber()
		if err := d.Decode(&val); err != nil {
			return fmt.Errorf("path param %q: %w", k, err)
		}
		// Narrow json.Number to the most specific Go numeric type.
		if n, ok := val.(json.Number); ok {
			if i, err := n.Int64(); err == nil {
				val = i
			} else if f, err := n.Float64(); err == nil {
				val = f
			}
		}
		result[k] = val
	}

	*m = result
	return nil
}

// Hash returns a deterministic content hash used for deduplication.
// Covers: Method + PathPattern + PathParams + QueryParams + Body.
// Intentionally excludes metrics (CoverageDelta, UseCount, AddedAt)
// so the same logical request isn't stored twice even if rediscovered later.
func (e *CorpusEntry) Hash() string {
	if e.hash != "" {
		return e.hash
	}

	h := sha256.New()
	fmt.Fprintf(h, "%s\x00%s\x00", e.Method, e.PathPattern)

	// Encode params deterministically via JSON (map iteration order is random,
	// but json.Marshal sorts map keys in Go 1.12+).
	if b, err := json.Marshal(e.PathParams); err == nil {
		h.Write(b)
	}
	if b, err := json.Marshal(e.QueryParams); err == nil {
		h.Write(b)
	}
	h.Write([]byte{0x00})
	h.Write(e.Body)

	e.hash = fmt.Sprintf("%x", h.Sum(nil))
	return e.hash
}

// Clone returns a deep copy safe to pass to the mutator without aliasing.
func (e *CorpusEntry) Clone() *CorpusEntry {
	c := *e // shallow copy of scalars

	// Deep copy maps
	c.PathParams = make(pathParamsMap, len(e.PathParams))
	for k, v := range e.PathParams {
		c.PathParams[k] = v
	}
	c.QueryParams = make(map[string]string, len(e.QueryParams))
	for k, v := range e.QueryParams {
		c.QueryParams[k] = v
	}
	c.HeaderParams = make(map[string]string, len(e.HeaderParams))
	for k, v := range e.HeaderParams {
		c.HeaderParams[k] = v
	}
	c.CookieParams = make(map[string]string, len(e.CookieParams))
	for k, v := range e.CookieParams {
		c.CookieParams[k] = v
	}

	// Deep copy body slice
	if e.Body != nil {
		c.Body = make([]byte, len(e.Body))
		copy(c.Body, e.Body)
	}

	c.hash = "" // invalidate: clone may be mutated, hash will differ
	return &c
}

// Weight returns the selection weight for weighted random selection.
// Entries with higher coverage delta and fewer uses have higher weight.
// See selection.go for the formula rationale.
func (e *CorpusEntry) Weight() float64 {
	return entryWeight(e.CoverageDelta, e.UseCount)
}

// entryWeight computes the selection weight from raw metrics.
// Defined here (not selection.go) because it has no dependency on corpus state;
// selection.go imports it for the prefix-sum rebuild.
//
// Formula: log2(1+delta) / log2(2+useCount)
//
//   - log2(1+delta):      higher coverage delta → higher initial weight.
//     Logarithm smooths extremes: delta=1000 is not 1000× more interesting than delta=10.
//   - log2(2+useCount):   "cooling" — each selection reduces weight.
//     +2 (not +1) keeps the denominator above 1 for useCount=0, giving a
//     clean initial weight of log2(1+delta)/1 = log2(1+delta).
//
// Minimum weight is never exactly 0, so every entry eventually gets selected.
func entryWeight(delta, useCount uint64) float64 {
	if delta == 0 {
		// Seed entries have delta=1 by convention; delta=0 should not appear
		// in corpus, but guard against it to avoid log2(1)=0 dominator.
		return 0.001
	}
	numerator := math.Log2(1 + float64(delta))
	denominator := math.Log2(2 + float64(useCount))
	return numerator / denominator
}
