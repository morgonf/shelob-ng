package mutator

import (
	"fmt"
	"math"
	"math/rand"
	"strings"

	"shelob-ng/corpus"
)

// structuralMutator changes field values while preserving their approximate type.
// It picks one field per Apply call (Decision 1A: MutationWidth=1) and applies
// a type-aware transformation.
//
// When a SchemaIndex is available, constrained fields are mutated to respect
// OpenAPI schema bounds: 70% of mutations land inside the valid range (to
// exercise correct code paths) and 30% land just outside (to exercise error
// handling). Unconstrained fields use the original edge-case strategy.
type structuralMutator struct {
	rng    *rand.Rand
	schema *SchemaIndex // nil when no spec is available
}

func (s *structuralMutator) Name() string { return "structural" }

func (s *structuralMutator) Apply(entry *corpus.CorpusEntry) (*corpus.CorpusEntry, error) {
	target, ok := PickField(entry, s.rng)
	if !ok {
		return nil, StrategyNotApplicable
	}

	switch target.Kind {
	case FieldPath:
		c := s.lookupConstraint(entry, "path", target.Key)
		entry.PathParams[target.Key] = s.mutateConstrained(entry.PathParams[target.Key], c)
	case FieldQuery:
		c := s.lookupConstraint(entry, "query", target.Key)
		entry.QueryParams[target.Key] = fmt.Sprintf("%v", s.mutateConstrained(entry.QueryParams[target.Key], c))
	case FieldHeader:
		c := s.lookupConstraint(entry, "header", target.Key)
		entry.HeaderParams[target.Key] = fmt.Sprintf("%v", s.mutateConstrained(entry.HeaderParams[target.Key], c))
	case FieldCookie:
		c := s.lookupConstraint(entry, "cookie", target.Key)
		entry.CookieParams[target.Key] = fmt.Sprintf("%v", s.mutateConstrained(entry.CookieParams[target.Key], c))
	case FieldBody:
		if err := s.mutateBody(entry); err != nil {
			return nil, StrategyNotApplicable
		}
	}

	return entry, nil
}

// lookupConstraint returns the FieldConstraint for the given field, or nil when
// no schema index is available or no constraint is declared.
func (s *structuralMutator) lookupConstraint(entry *corpus.CorpusEntry, location, name string) *FieldConstraint {
	if s.schema == nil {
		return nil
	}
	return s.schema.Get(entry.Method, entry.PathPattern, location, name)
}

// mutateConstrained dispatches to a constraint-aware mutation when c is non-nil,
// falling back to the unconstrained mutateValue otherwise.
func (s *structuralMutator) mutateConstrained(v interface{}, c *FieldConstraint) interface{} {
	if c == nil {
		return s.mutateValue(v)
	}
	if len(c.Enum) > 0 {
		return s.mutateEnum(v, c.Enum)
	}
	switch val := v.(type) {
	case int64:
		return s.mutateIntConstrained(val, c)
	case float64:
		return s.mutateFloatConstrained(val, c)
	case string:
		return s.mutateStringConstrained(val, c)
	default:
		return s.mutateValue(v)
	}
}

// mutateIntConstrained applies schema bounds to integer mutation.
// 70% of results land inside [minimum, maximum]; 30% land just outside to test
// error handling. Unconstrained dimensions fall back to the normal strategy.
func (s *structuralMutator) mutateIntConstrained(v int64, c *FieldConstraint) int64 {
	if !c.HasNumericBounds() {
		return s.mutateInt(v)
	}

	if s.rng.Float64() < 0.70 {
		// Valid: stay within [min, max].
		if c.Minimum != nil && c.Maximum != nil {
			lo, hi := int64(*c.Minimum), int64(*c.Maximum)
			if lo > hi {
				lo, hi = hi, lo
			}
			if lo == hi {
				return lo
			}
			return lo + s.rng.Int63n(hi-lo+1)
		}
		if c.Minimum != nil {
			return int64(*c.Minimum) + s.rng.Int63n(10)
		}
		hi := int64(*c.Maximum)
		return hi - s.rng.Int63n(10)
	}

	// Boundary violation: one step outside the valid range.
	switch s.rng.Intn(4) {
	case 0:
		if c.Minimum != nil {
			return int64(*c.Minimum) - 1
		}
		return math.MinInt64
	case 1:
		if c.Maximum != nil {
			return int64(*c.Maximum) + 1
		}
		return math.MaxInt64
	case 2:
		if c.Minimum != nil {
			return int64(*c.Minimum) // exactly at lower bound
		}
		return v
	default:
		if c.Maximum != nil {
			return int64(*c.Maximum) // exactly at upper bound
		}
		return v
	}
}

// mutateFloatConstrained mirrors mutateIntConstrained for float64 fields.
func (s *structuralMutator) mutateFloatConstrained(v float64, c *FieldConstraint) float64 {
	if !c.HasNumericBounds() {
		return s.mutateFloat(v)
	}

	if s.rng.Float64() < 0.70 {
		if c.Minimum != nil && c.Maximum != nil {
			lo, hi := *c.Minimum, *c.Maximum
			if lo > hi {
				lo, hi = hi, lo
			}
			return lo + s.rng.Float64()*(hi-lo)
		}
		if c.Minimum != nil {
			return *c.Minimum + s.rng.Float64()*10
		}
		return *c.Maximum - s.rng.Float64()*10
	}

	switch s.rng.Intn(3) {
	case 0:
		if c.Minimum != nil {
			return *c.Minimum - 0.001
		}
		return -math.MaxFloat32
	case 1:
		if c.Maximum != nil {
			return *c.Maximum + 0.001
		}
		return math.MaxFloat32
	default:
		if c.Minimum != nil {
			return *c.Minimum
		}
		return *c.Maximum
	}
}

// mutateStringConstrained applies schema length bounds to string mutation.
// 70% of results satisfy minLength ≤ len ≤ maxLength; 30% are at or over
// the maxLength boundary to test truncation / rejection logic.
func (s *structuralMutator) mutateStringConstrained(v string, c *FieldConstraint) string {
	if !c.HasStringBounds() {
		return s.mutateString(v)
	}

	maxLen := int64(-1)
	if c.MaxLength != nil {
		maxLen = int64(*c.MaxLength)
	}
	minLen := int64(0)
	if c.MinLength != nil {
		minLen = int64(*c.MinLength)
	}

	if s.rng.Float64() < 0.70 {
		// Valid: length within [minLen, maxLen].
		if maxLen < 0 {
			// Only minLen declared — generate something just above the minimum.
			return strings.Repeat("A", int(minLen)+s.rng.Intn(5))
		}
		span := maxLen - minLen
		if span <= 0 {
			return strings.Repeat("A", int(minLen))
		}
		targetLen := minLen + s.rng.Int63n(span+1)
		return strings.Repeat("A", int(targetLen))
	}

	// Boundary violation: at, one over, or far over maxLen.
	if maxLen >= 0 {
		switch s.rng.Intn(3) {
		case 0:
			return strings.Repeat("A", int(maxLen)) // exactly at limit
		case 1:
			return strings.Repeat("A", int(maxLen)+1) // one over
		default:
			return strings.Repeat("A", 256) // classic overflow
		}
	}
	return s.mutateString(v)
}

// mutateEnum picks from the declared enum values 70% of the time; the remaining
// 30% falls through to an unconstrained mutation to test rejection behaviour.
func (s *structuralMutator) mutateEnum(v interface{}, enum []interface{}) interface{} {
	if len(enum) == 0 {
		return s.mutateValue(v)
	}
	if s.rng.Float64() < 0.70 {
		return enum[s.rng.Intn(len(enum))]
	}
	return s.mutateValue(v)
}

// mutateValue dispatches to the type-specific unconstrained mutation.
func (s *structuralMutator) mutateValue(v interface{}) interface{} {
	switch val := v.(type) {
	case string:
		return s.mutateString(val)
	case int64:
		return s.mutateInt(val)
	case float64:
		return s.mutateFloat(val)
	case bool:
		return !val
	default:
		return ""
	}
}

// stringEdgeCases are values that stress string parsers: empty, whitespace,
// null byte, type-confusion literals, and long strings for buffer boundaries.
var stringEdgeCases = []string{
	"",
	" ",
	"null",
	"true",
	"false",
	"0",
	"-1",
	"\x00",
	"\r\n",
	strings.Repeat("A", 256),
	strings.Repeat("A", 8192),
}

func (s *structuralMutator) mutateString(v string) string {
	switch s.rng.Intn(4) {
	case 0, 1:
		return stringEdgeCases[s.rng.Intn(len(stringEdgeCases))]
	case 2:
		if len(v) == 0 {
			return ""
		}
		return v[:s.rng.Intn(len(v)+1)]
	default:
		return v + v
	}
}

// intEdgeCases are integer values that commonly trigger boundary bugs.
var intEdgeCases = []int64{
	0, 1, -1,
	math.MaxInt64, math.MinInt64,
	math.MaxInt32, math.MinInt32,
	256, 65535, 65536,
}

func (s *structuralMutator) mutateInt(v int64) int64 {
	if s.rng.Intn(2) == 0 {
		return intEdgeCases[s.rng.Intn(len(intEdgeCases))]
	}
	return v + int64(s.rng.Intn(3)-1)
}

var floatEdgeCases = []float64{0, 1, -1, math.MaxFloat32, -math.MaxFloat32}

func (s *structuralMutator) mutateFloat(v float64) float64 {
	if s.rng.Intn(2) == 0 {
		return floatEdgeCases[s.rng.Intn(len(floatEdgeCases))]
	}
	return v + float64(s.rng.Intn(3)-1)
}

// mutateBody applies one of three mutations to the JSON body:
// inject a poison field, remove an existing field, or change a leaf value type.
func (s *structuralMutator) mutateBody(entry *corpus.CorpusEntry) error {
	obj, err := ParseJSONObject(entry.Body)
	if err != nil {
		return err
	}

	applied := false
	switch s.rng.Intn(3) {
	case 0:
		applied = s.bodyAddField(obj)
	case 1:
		applied = s.bodyRemoveField(obj)
	case 2:
		applied = s.bodyMutateLeaf(obj, entry.Method, entry.PathPattern)
	}
	if !applied {
		s.bodyAddField(obj)
	}

	body, err := MarshalBody(obj)
	if err != nil {
		return err
	}
	entry.Body = body
	return nil
}

var poisonFields = []struct {
	key string
	val interface{}
}{
	{"__proto__", map[string]interface{}{"polluted": true}},
	{"constructor", map[string]interface{}{}},
	{"$where", "1==1"},
	{"admin", true},
	{"role", "admin"},
	{"id", int64(-1)},
	{"extra", "fuzz"},
	{"null_field", nil},
}

func (s *structuralMutator) bodyAddField(obj map[string]interface{}) bool {
	f := poisonFields[s.rng.Intn(len(poisonFields))]
	AddField(obj, f.key, f.val)
	return true
}

func (s *structuralMutator) bodyRemoveField(obj map[string]interface{}) bool {
	if len(obj) == 0 {
		return false
	}
	keys := make([]string, 0, len(obj))
	for k := range obj {
		keys = append(keys, k)
	}
	RemoveField(obj, keys[s.rng.Intn(len(keys))])
	return true
}

// bodyMutateLeaf replaces one leaf value with its constrained or unconstrained mutation.
func (s *structuralMutator) bodyMutateLeaf(obj map[string]interface{}, method, pathPattern string) bool {
	if len(obj) == 0 {
		return false
	}
	keys := make([]string, 0, len(obj))
	for k := range obj {
		keys = append(keys, k)
	}
	key := keys[s.rng.Intn(len(keys))]

	var c *FieldConstraint
	if s.schema != nil {
		c = s.schema.Get(method, pathPattern, "body", key)
	}
	obj[key] = s.mutateConstrained(obj[key], c)
	return true
}
