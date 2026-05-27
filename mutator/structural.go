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
// a type-aware transformation:
//
//   - string → boundary lengths, null byte, type-confusion values
//   - int64  → zero, ±1, MaxInt64, MinInt64, common boundary values
//   - float64 → zero, ±1, MaxFloat32
//   - bool   → flip
//   - body   → add poison field / remove a field / change a leaf type
//
// Returns StrategyNotApplicable when the entry has no mutable fields.
type structuralMutator struct {
	rng *rand.Rand
}

func (s *structuralMutator) Name() string { return "structural" }

func (s *structuralMutator) Apply(entry *corpus.CorpusEntry) (*corpus.CorpusEntry, error) {
	target, ok := PickField(entry, s.rng)
	if !ok {
		return nil, StrategyNotApplicable
	}

	switch target.Kind {
	case FieldPath:
		entry.PathParams[target.Key] = s.mutateValue(entry.PathParams[target.Key])
	case FieldQuery:
		// QueryParams is map[string]string; convert mutated value via Sprintf.
		entry.QueryParams[target.Key] = fmt.Sprintf("%v", s.mutateValue(entry.QueryParams[target.Key]))
	case FieldHeader:
		entry.HeaderParams[target.Key] = fmt.Sprintf("%v", s.mutateValue(entry.HeaderParams[target.Key]))
	case FieldCookie:
		entry.CookieParams[target.Key] = fmt.Sprintf("%v", s.mutateValue(entry.CookieParams[target.Key]))
	case FieldBody:
		if err := s.mutateBody(entry); err != nil {
			// body not JSON — byte_level strategy handles raw bytes
			return nil, StrategyNotApplicable
		}
	}

	return entry, nil
}

// mutateValue dispatches to the type-specific mutation for each scalar type.
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
		// Unknown or nil — send empty string to trigger schema validation errors.
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
		// 50%: substitute a known edge-case value.
		return stringEdgeCases[s.rng.Intn(len(stringEdgeCases))]
	case 2:
		// 25%: truncate to a random prefix (exercises short-read parsers).
		if len(v) == 0 {
			return ""
		}
		return v[:s.rng.Intn(len(v)+1)]
	default:
		// 25%: duplicate the string (exercises length-overflow parsers).
		return v + v
	}
}

// intEdgeCases are integer values that commonly trigger boundary bugs:
// signed/unsigned overflow, common parser boundaries, and near-zero values.
var intEdgeCases = []int64{
	0, 1, -1,
	math.MaxInt64, math.MinInt64,
	math.MaxInt32, math.MinInt32,
	256, 65535, 65536,
}

func (s *structuralMutator) mutateInt(v int64) int64 {
	// 50%: use a boundary constant; 50%: nudge current value by ±1 or 0.
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
		applied = s.bodyMutateLeaf(obj)
	}
	if !applied {
		// Primary op couldn't act (empty object) — always succeed by adding a field.
		s.bodyAddField(obj)
	}

	body, err := MarshalBody(obj)
	if err != nil {
		return err
	}
	entry.Body = body
	return nil
}

// poisonFields are unexpected keys injected to test field rejection,
// prototype pollution, NoSQL injection, and authorization bypass.
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

// bodyAddField injects a poison key that the server should reject.
// Always returns true — adding a key to a map cannot fail.
func (s *structuralMutator) bodyAddField(obj map[string]interface{}) bool {
	f := poisonFields[s.rng.Intn(len(poisonFields))]
	AddField(obj, f.key, f.val)
	return true
}

// bodyRemoveField removes a random top-level key to trigger missing-field errors.
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

// bodyMutateLeaf replaces a random top-level value with its type-aware mutation.
func (s *structuralMutator) bodyMutateLeaf(obj map[string]interface{}) bool {
	if len(obj) == 0 {
		return false
	}
	keys := make([]string, 0, len(obj))
	for k := range obj {
		keys = append(keys, k)
	}
	key := keys[s.rng.Intn(len(keys))]
	obj[key] = s.mutateValue(obj[key])
	return true
}
