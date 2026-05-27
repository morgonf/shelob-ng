package mutator

import (
	"math/rand"

	"shelob-ng/corpus"
)

// FieldKind identifies which dimension of a CorpusEntry to mutate.
type FieldKind int

const (
	FieldPath   FieldKind = iota // PathParams map value
	FieldQuery                   // QueryParams value
	FieldHeader                  // HeaderParams value
	FieldCookie                  // CookieParams value
	FieldBody                    // Body []byte (JSON object or raw bytes)
)

// FieldTarget is the result of field selection: which dimension and which key.
type FieldTarget struct {
	Kind FieldKind
	Key  string // empty when Kind == FieldBody
}

// PickField randomly selects one mutable field from entry.
// Body is weighted 2× relative to individual scalar params because it typically
// contains more exploitable surface area (multiple fields, nested structures).
// Returns (zero, false) when the entry has no mutable fields at all.
func PickField(entry *corpus.CorpusEntry, rng *rand.Rand) (FieldTarget, bool) {
	var targets []FieldTarget

	for k := range entry.PathParams {
		targets = append(targets, FieldTarget{Kind: FieldPath, Key: k})
	}
	for k := range entry.QueryParams {
		targets = append(targets, FieldTarget{Kind: FieldQuery, Key: k})
	}
	for k := range entry.HeaderParams {
		targets = append(targets, FieldTarget{Kind: FieldHeader, Key: k})
	}
	for k := range entry.CookieParams {
		targets = append(targets, FieldTarget{Kind: FieldCookie, Key: k})
	}
	// Add body twice for 2× weight relative to a single scalar parameter.
	if len(entry.Body) > 0 {
		bodyTarget := FieldTarget{Kind: FieldBody}
		targets = append(targets, bodyTarget, bodyTarget)
	}

	if len(targets) == 0 {
		return FieldTarget{}, false
	}
	return targets[rng.Intn(len(targets))], true
}

// PickStringFields returns all targets that accept string values.
// Used by the Security strategy, which can only inject payload strings into
// fields that the server will interpret as strings.
//
// Includes: all QueryParams, HeaderParams, CookieParams; PathParams whose current
// value is already a string; and Body when non-empty (security mutator handles
// body string leaf injection separately).
func PickStringFields(entry *corpus.CorpusEntry) []FieldTarget {
	var targets []FieldTarget

	// Path params: include only those currently holding a string value.
	// Injecting a string payload into an integer path param would likely cause
	// a 400 before reaching the vulnerable code, wasting the iteration.
	for k, v := range entry.PathParams {
		if _, ok := v.(string); ok {
			targets = append(targets, FieldTarget{Kind: FieldPath, Key: k})
		}
	}
	for k := range entry.QueryParams {
		targets = append(targets, FieldTarget{Kind: FieldQuery, Key: k})
	}
	for k := range entry.HeaderParams {
		targets = append(targets, FieldTarget{Kind: FieldHeader, Key: k})
	}
	for k := range entry.CookieParams {
		targets = append(targets, FieldTarget{Kind: FieldCookie, Key: k})
	}
	// Body is included as a single target; the caller uses CollectStringLeaves
	// to drill down into specific JSON string fields.
	if len(entry.Body) > 0 {
		targets = append(targets, FieldTarget{Kind: FieldBody})
	}

	return targets
}
