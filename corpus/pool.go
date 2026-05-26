package corpus

import (
	"encoding/json"
	"math/rand"
	"reflect"
	"sync"

	"github.com/getkin/kin-openapi/openapi3"
	log "github.com/sirupsen/logrus"
)

const (
	// poolProbability is the chance of returning a pooled value vs generating random.
	// 70% pool reuse gives the fuzzer realistic IDs/tokens from actual API responses;
	// 30% random keeps exploration alive so new paths are still discovered.
	poolProbability = 0.70

	// maxPerKey limits how many values are stored per parameter name.
	// Older values are evicted (ring-buffer style) when the limit is reached,
	// preventing stale IDs from accumulating after server restarts.
	maxPerKey = 256

	// maxExtractDepth limits recursive JSON traversal in Extract.
	// Prevents stack overflow on deeply nested or self-referential responses.
	maxExtractDepth = 15
)

// DynamicValuePool accumulates values extracted from HTTP response bodies
// and provides them for use in subsequent requests. This implements a simple
// form of producer-consumer dependency tracking without explicit annotations:
// if the server returns {"id": 42}, the next request to /users/{id} can use 42.
type DynamicValuePool struct {
	mu     sync.RWMutex
	values map[string][]interface{} // paramName → ring buffer of values
	head   map[string]int           // next write position per key
}

// NewDynamicValuePool creates an empty pool.
func NewDynamicValuePool() *DynamicValuePool {
	return &DynamicValuePool{
		values: make(map[string][]interface{}),
		head:   make(map[string]int),
	}
}

// Extract parses a JSON response body and adds all leaf values to the pool,
// keyed by their JSON field name. Recursively traverses objects and arrays
// up to maxExtractDepth levels deep.
//
// Non-JSON bodies are silently ignored (the API may return HTML, plain text, etc.).
// Thread-safe.
func (p *DynamicValuePool) Extract(responseBody []byte) {
	if len(responseBody) == 0 {
		return
	}

	var raw interface{}
	if err := json.Unmarshal(responseBody, &raw); err != nil {
		return // not JSON — skip silently
	}

	collected := make(map[string][]interface{})
	extractValues(raw, collected, 0)

	if len(collected) == 0 {
		return
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	for key, vals := range collected {
		for _, v := range vals {
			p.store(key, v)
		}
	}
}

// extractValues recursively walks a decoded JSON value and collects
// all primitive leaf values (string, number, bool) into out[fieldName].
// parentKey carries the field name from the enclosing object so that
// primitives inside arrays are stored under their parent's key:
//   {"ids": [1, 2, 3]}  →  out["ids"] = [1, 2, 3]
func extractValues(node interface{}, out map[string][]interface{}, depth int) {
	if depth > maxExtractDepth {
		return
	}
	extractWithKey(node, "", out, depth)
}

func extractWithKey(node interface{}, parentKey string, out map[string][]interface{}, depth int) {
	if depth > maxExtractDepth {
		return
	}

	switch v := node.(type) {
	case map[string]interface{}:
		for key, val := range v {
			switch val.(type) {
			case map[string]interface{}, []interface{}:
				// Recurse into nested structures; pass the current key as parent
				// so that array elements can be stored under it.
				extractWithKey(val, key, out, depth+1)
			default:
				// Primitive leaf: store under the field name.
				if val != nil {
					out[key] = append(out[key], val)
				}
			}
		}
	case []interface{}:
		for _, item := range v {
			switch item.(type) {
			case map[string]interface{}, []interface{}:
				// Nested object/array inside an array: recurse without a key.
				extractWithKey(item, parentKey, out, depth+1)
			default:
				// Primitive inside an array: store under the parent field name.
				// Example: {"ids": [1,2,3]} → out["ids"] = [1,2,3]
				if item != nil && parentKey != "" {
					out[parentKey] = append(out[parentKey], item)
				}
			}
		}
	}
}

// store adds v to the ring buffer for key, evicting the oldest value when full.
// Must be called under write lock.
func (p *DynamicValuePool) store(key string, v interface{}) {
	if _, exists := p.values[key]; !exists {
		p.values[key] = make([]interface{}, maxPerKey)
		p.head[key] = 0
	}
	pos := p.head[key] % maxPerKey
	p.values[key][pos] = v
	p.head[key]++
}

// GetValue returns a value from the pool suitable for the given parameter name
// and OpenAPI schema, or nil when no suitable value exists or random is chosen.
//
// Decision logic:
//  1. If pool[paramName] is empty → return nil (caller generates random).
//  2. With probability (1 - poolProbability) → return nil (exploration).
//  3. Pick a random candidate from the pool.
//  4. Validate it against schema using full OpenAPI type checking.
//  5. If valid → return it. If invalid → return nil.
//
// Thread-safe.
func (p *DynamicValuePool) GetValue(paramName string, schema *openapi3.Schema) interface{} {
	if rand.Float64() >= poolProbability {
		return nil // exploration: let the caller generate a fresh random value
	}

	// Copy non-nil values under RLock to prevent a data race with Extract(),
	// which writes to the ring buffer under write lock concurrently.
	p.mu.RLock()
	candidates := nonNilValues(p.values[paramName])
	p.mu.RUnlock()
	if len(candidates) == 0 {
		return nil
	}

	v := candidates[rand.Intn(len(candidates))]

	if !validateAgainstSchema(v, schema) {
		return nil
	}
	return v
}

// nonNilValues returns only non-nil entries from a ring buffer.
// The buffer may be partially filled if fewer than maxPerKey values have been stored.
func nonNilValues(buf []interface{}) []interface{} {
	out := make([]interface{}, 0, len(buf))
	for _, v := range buf {
		if v != nil {
			out = append(out, v)
		}
	}
	return out
}

// validateAgainstSchema checks whether v is compatible with schema using full
// OpenAPI type validation. Returns true when the value is acceptable.
//
// We check Go type correspondence first (fast path) and then run
// openapi3.Schema.VisitJSON for full constraint validation (min/max, pattern,
// enum, etc.). This satisfies ADR decision #4: full OpenAPI validation.
func validateAgainstSchema(v interface{}, schema *openapi3.Schema) bool {
	if schema == nil || schema.Type == nil || len(*schema.Type) == 0 {
		return true // no type constraint — accept anything
	}

	schemaType := (*schema.Type)[0]

	// Fast path: check Go type against OpenAPI type to skip VisitJSON
	// for obviously incompatible values (e.g. a string pooled as an integer param).
	switch schemaType {
	case "integer":
		switch v.(type) {
		case int, int32, int64, json.Number, float64:
			// json.Number and float64 from JSON parsing are acceptable for integers.
		default:
			log.Debugf("pool: rejected %v (%T) for integer schema", v, v)
			return false
		}
	case "number":
		switch v.(type) {
		case float32, float64, int, int64, json.Number:
		default:
			log.Debugf("pool: rejected %v (%T) for number schema", v, v)
			return false
		}
	case "string":
		if reflect.TypeOf(v).Kind() != reflect.String {
			log.Debugf("pool: rejected %v (%T) for string schema", v, v)
			return false
		}
	case "boolean":
		if _, ok := v.(bool); !ok {
			log.Debugf("pool: rejected %v (%T) for boolean schema", v, v)
			return false
		}
	}

	// Full validation: VisitJSON checks min/max, pattern, enum, format, etc.
	if err := schema.VisitJSON(v); err != nil {
		log.Debugf("pool: OpenAPI validation failed for %v: %v", v, err)
		return false
	}
	return true
}

// Size returns the total number of values stored across all keys. Thread-safe.
func (p *DynamicValuePool) Size() int {
	p.mu.RLock()
	defer p.mu.RUnlock()

	total := 0
	for _, buf := range p.values {
		total += len(nonNilValues(buf))
	}
	return total
}
