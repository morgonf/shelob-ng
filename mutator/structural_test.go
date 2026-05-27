package mutator

import (
	"bytes"
	"encoding/json"
	"errors"
	"math/rand"
	"testing"

	"shelob-ng/corpus"
)

func newStructural(seed int64) *structuralMutator {
	return &structuralMutator{rng: rand.New(rand.NewSource(seed))}
}

// --- Apply ---

func TestStructuralApply_NoFieldsNotApplicable(t *testing.T) {
	m := newStructural(1)
	e := &corpus.CorpusEntry{
		Method:       "GET",
		PathPattern:  "/ping",
		PathParams:   make(map[string]interface{}),
		QueryParams:  make(map[string]string),
		HeaderParams: make(map[string]string),
		CookieParams: make(map[string]string),
	}
	_, err := m.Apply(e)
	if !errors.Is(err, StrategyNotApplicable) {
		t.Errorf("expected StrategyNotApplicable for entry with no mutable fields, got %v", err)
	}
}

func TestStructuralApply_MutatesPathParam(t *testing.T) {
	m := newStructural(2)
	e := &corpus.CorpusEntry{
		Method:       "GET",
		PathPattern:  "/users/{id}",
		PathParams:   map[string]interface{}{"id": int64(7)},
		QueryParams:  make(map[string]string),
		HeaderParams: make(map[string]string),
		CookieParams: make(map[string]string),
	}
	// Run many times — at least one should change the value.
	changed := false
	for i := 0; i < 50; i++ {
		clone := e.Clone()
		result, err := m.Apply(clone)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.PathParams["id"] != int64(7) {
			changed = true
			break
		}
	}
	if !changed {
		t.Error("Apply should mutate the path param in at least some runs")
	}
}

func TestStructuralApply_QueryParamRemainsString(t *testing.T) {
	m := newStructural(99)
	e := &corpus.CorpusEntry{
		Method:       "GET",
		PathPattern:  "/search",
		PathParams:   make(map[string]interface{}),
		QueryParams:  map[string]string{"q": "hello"},
		HeaderParams: make(map[string]string),
		CookieParams: make(map[string]string),
	}
	for i := 0; i < 20; i++ {
		clone := e.Clone()
		result, err := m.Apply(clone)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		// QueryParams is map[string]string — value is always a string.
		// Just verify Apply doesn't panic and the value is still a valid string.
		if result.QueryParams["q"] == "" && i > 0 {
			// empty string is a valid mutation result — OK
		}
		_ = result
	}
}

func TestStructuralApply_BoolFlip(t *testing.T) {
	m := newStructural(3)
	e := &corpus.CorpusEntry{
		Method:       "PUT",
		PathPattern:  "/toggle",
		PathParams:   map[string]interface{}{"active": true},
		QueryParams:  make(map[string]string),
		HeaderParams: make(map[string]string),
		CookieParams: make(map[string]string),
	}
	flipped := false
	for i := 0; i < 30; i++ {
		clone := e.Clone()
		result, _ := m.Apply(clone)
		if v, ok := result.PathParams["active"].(bool); ok && !v {
			flipped = true
			break
		}
	}
	if !flipped {
		t.Error("structuralMutator should flip bool path params")
	}
}

func TestStructuralApply_BodyMutated(t *testing.T) {
	m := newStructural(4)
	original := []byte(`{"name":"alice","age":30}`)
	e := entryWithBody(original)

	changed := false
	for i := 0; i < 30; i++ {
		clone := e.Clone()
		result, err := m.Apply(clone)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !bytes.Equal(result.Body, original) {
			changed = true
			break
		}
	}
	if !changed {
		t.Error("Apply should mutate the JSON body")
	}
}

func TestStructuralApply_NonJSONBodyNotApplicable(t *testing.T) {
	m := newStructural(5)
	// Entry has only a non-JSON body — no scalar params.
	e := entryWithBody([]byte("NOT JSON"))
	_, err := m.Apply(e)
	if !errors.Is(err, StrategyNotApplicable) {
		t.Errorf("expected StrategyNotApplicable for non-JSON body with no other fields, got %v", err)
	}
}

// --- mutateString ---

func TestMutateString_ReturnsString(t *testing.T) {
	m := newStructural(10)
	for i := 0; i < 100; i++ {
		got := m.mutateString("hello")
		_ = got // must be string — compile-time guarantee
	}
}

func TestMutateString_CanReturnEmpty(t *testing.T) {
	m := newStructural(11)
	foundEmpty := false
	for i := 0; i < 200; i++ {
		if m.mutateString("abc") == "" {
			foundEmpty = true
			break
		}
	}
	if !foundEmpty {
		t.Error("mutateString should occasionally return empty string (edge case)")
	}
}

func TestMutateString_EmptyInput(t *testing.T) {
	m := newStructural(12)
	// Should not panic when input is empty (truncate path).
	for i := 0; i < 20; i++ {
		_ = m.mutateString("")
	}
}

// --- mutateInt ---

func TestMutateInt_ReturnsInt64(t *testing.T) {
	m := newStructural(20)
	for i := 0; i < 100; i++ {
		got := m.mutateInt(10)
		_ = got // compile-time: int64
	}
}

func TestMutateInt_HitsEdgeCases(t *testing.T) {
	m := newStructural(21)
	edgeSet := make(map[int64]bool)
	for _, v := range intEdgeCases {
		edgeSet[v] = true
	}
	foundEdge := false
	for i := 0; i < 200; i++ {
		got := m.mutateInt(5)
		if edgeSet[got] {
			foundEdge = true
			break
		}
	}
	if !foundEdge {
		t.Error("mutateInt should return edge case values in some iterations")
	}
}

func TestMutateInt_NudgesValue(t *testing.T) {
	m := newStructural(22)
	input := int64(100)
	nudged := false
	for i := 0; i < 200; i++ {
		got := m.mutateInt(input)
		if got == input-1 || got == input || got == input+1 {
			nudged = true
			break
		}
	}
	if !nudged {
		t.Error("mutateInt should sometimes nudge value by ±1")
	}
}

// --- mutateFloat ---

func TestMutateFloat_ReturnsFloat64(t *testing.T) {
	m := newStructural(30)
	for i := 0; i < 50; i++ {
		got := m.mutateFloat(3.14)
		_ = got
	}
}

// --- mutateBody ---

func TestMutateBody_AddsField(t *testing.T) {
	m := newStructural(40)
	e := entryWithBody([]byte(`{"name":"alice"}`))
	// Run until we get an addField result (case 0).
	added := false
	for i := 0; i < 50; i++ {
		clone := e.Clone()
		if err := m.mutateBody(clone); err != nil {
			continue
		}
		var obj map[string]interface{}
		json.Unmarshal(clone.Body, &obj)
		if len(obj) > 1 {
			added = true
			break
		}
	}
	if !added {
		t.Error("mutateBody should sometimes add a poison field")
	}
}

func TestMutateBody_RemovesField(t *testing.T) {
	m := newStructural(41)
	original := []byte(`{"a":"1","b":"2","c":"3"}`)
	removed := false
	for i := 0; i < 50; i++ {
		e := entryWithBody(original)
		if err := m.mutateBody(e); err != nil {
			continue
		}
		var obj map[string]interface{}
		json.Unmarshal(e.Body, &obj)
		if len(obj) < 3 {
			removed = true
			break
		}
	}
	if !removed {
		t.Error("mutateBody should sometimes remove a field")
	}
}

func TestMutateBody_NonJSONReturnsError(t *testing.T) {
	m := newStructural(42)
	e := entryWithBody([]byte("NOT JSON"))
	err := m.mutateBody(e)
	if err == nil {
		t.Error("mutateBody on non-JSON should return an error")
	}
}

func TestMutateBody_EmptyObjectGetsField(t *testing.T) {
	m := newStructural(43)
	e := entryWithBody([]byte(`{}`))
	// Empty object: removeField and mutateLeaf can't act, so addField is forced.
	for i := 0; i < 10; i++ {
		clone := e.Clone()
		if err := m.mutateBody(clone); err != nil {
			t.Fatalf("unexpected error on empty object: %v", err)
		}
		var obj map[string]interface{}
		json.Unmarshal(clone.Body, &obj)
		if len(obj) == 0 {
			t.Error("mutateBody on empty object should always add a field")
		}
	}
}
