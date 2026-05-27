package mutator

import (
	"math/rand"
	"testing"

	"shelob-ng/corpus"
)

func newRNG(seed int64) *rand.Rand {
	return rand.New(rand.NewSource(seed))
}

// --- PickField ---

func TestPickField_EmptyEntry(t *testing.T) {
	e := &corpus.CorpusEntry{
		PathParams:   make(map[string]interface{}),
		QueryParams:  make(map[string]string),
		HeaderParams: make(map[string]string),
		CookieParams: make(map[string]string),
	}
	_, ok := PickField(e, newRNG(1))
	if ok {
		t.Error("PickField on empty entry should return false")
	}
}

func TestPickField_PathParamSelected(t *testing.T) {
	e := &corpus.CorpusEntry{
		PathParams:   map[string]interface{}{"id": int64(1)},
		QueryParams:  make(map[string]string),
		HeaderParams: make(map[string]string),
		CookieParams: make(map[string]string),
	}
	target, ok := PickField(e, newRNG(1))
	if !ok {
		t.Fatal("PickField should return true for entry with path param")
	}
	if target.Kind != FieldPath || target.Key != "id" {
		t.Errorf("expected FieldPath/id, got kind=%d key=%q", target.Kind, target.Key)
	}
}

func TestPickField_QueryParamSelected(t *testing.T) {
	e := &corpus.CorpusEntry{
		PathParams:   make(map[string]interface{}),
		QueryParams:  map[string]string{"q": "test"},
		HeaderParams: make(map[string]string),
		CookieParams: make(map[string]string),
	}
	target, ok := PickField(e, newRNG(2))
	if !ok || target.Kind != FieldQuery {
		t.Errorf("expected FieldQuery, got ok=%v kind=%d", ok, target.Kind)
	}
}

func TestPickField_BodyHasDoubleWeight(t *testing.T) {
	// Entry with 1 path param and a body.
	// Body has 2× weight → should be picked ~67% of the time.
	e := &corpus.CorpusEntry{
		PathParams:   map[string]interface{}{"id": int64(1)},
		QueryParams:  make(map[string]string),
		HeaderParams: make(map[string]string),
		CookieParams: make(map[string]string),
		Body:         []byte(`{"k":"v"}`),
	}
	rng := newRNG(0)
	bodyCount := 0
	const N = 3000
	for i := 0; i < N; i++ {
		target, _ := PickField(e, rng)
		if target.Kind == FieldBody {
			bodyCount++
		}
	}
	// Expected: 2/(1+2) ≈ 66.7%. Allow ±8%.
	ratio := float64(bodyCount) / N
	if ratio < 0.58 || ratio > 0.76 {
		t.Errorf("body should be picked ~67%% of the time, got %.1f%%", ratio*100)
	}
}

func TestPickField_AllKindsReachable(t *testing.T) {
	e := &corpus.CorpusEntry{
		PathParams:   map[string]interface{}{"id": int64(1)},
		QueryParams:  map[string]string{"q": "x"},
		HeaderParams: map[string]string{"X-Token": "abc"},
		CookieParams: map[string]string{"session": "s"},
		Body:         []byte(`{"k":"v"}`),
	}
	rng := newRNG(99)
	seen := make(map[FieldKind]bool)
	for i := 0; i < 500; i++ {
		target, _ := PickField(e, rng)
		seen[target.Kind] = true
	}
	for _, kind := range []FieldKind{FieldPath, FieldQuery, FieldHeader, FieldCookie, FieldBody} {
		if !seen[kind] {
			t.Errorf("FieldKind %d was never selected in 500 picks", kind)
		}
	}
}

// --- PickStringFields ---

func TestPickStringFields_IntPathParamExcluded(t *testing.T) {
	e := &corpus.CorpusEntry{
		PathParams:   map[string]interface{}{"id": int64(42)}, // int, not string
		QueryParams:  make(map[string]string),
		HeaderParams: make(map[string]string),
		CookieParams: make(map[string]string),
	}
	targets := PickStringFields(e)
	for _, t2 := range targets {
		if t2.Kind == FieldPath && t2.Key == "id" {
			t.Error("integer path param should not be a string target")
		}
	}
}

func TestPickStringFields_StringPathParamIncluded(t *testing.T) {
	e := &corpus.CorpusEntry{
		PathParams:   map[string]interface{}{"slug": "hello"}, // string
		QueryParams:  make(map[string]string),
		HeaderParams: make(map[string]string),
		CookieParams: make(map[string]string),
	}
	targets := PickStringFields(e)
	found := false
	for _, t2 := range targets {
		if t2.Kind == FieldPath && t2.Key == "slug" {
			found = true
		}
	}
	if !found {
		t.Error("string path param should be included as string target")
	}
}

func TestPickStringFields_AllQueryHeaderCookieIncluded(t *testing.T) {
	e := &corpus.CorpusEntry{
		PathParams:   make(map[string]interface{}),
		QueryParams:  map[string]string{"a": "1", "b": "2"},
		HeaderParams: map[string]string{"X-H": "v"},
		CookieParams: map[string]string{"c": "d"},
	}
	targets := PickStringFields(e)
	kinds := make(map[FieldKind]int)
	for _, t2 := range targets {
		kinds[t2.Kind]++
	}
	if kinds[FieldQuery] != 2 {
		t.Errorf("expected 2 query targets, got %d", kinds[FieldQuery])
	}
	if kinds[FieldHeader] != 1 {
		t.Errorf("expected 1 header target, got %d", kinds[FieldHeader])
	}
	if kinds[FieldCookie] != 1 {
		t.Errorf("expected 1 cookie target, got %d", kinds[FieldCookie])
	}
}

func TestPickStringFields_BodyIncludedOnce(t *testing.T) {
	e := &corpus.CorpusEntry{
		PathParams:   make(map[string]interface{}),
		QueryParams:  make(map[string]string),
		HeaderParams: make(map[string]string),
		CookieParams: make(map[string]string),
		Body:         []byte(`{"k":"v"}`),
	}
	targets := PickStringFields(e)
	bodyCount := 0
	for _, t2 := range targets {
		if t2.Kind == FieldBody {
			bodyCount++
		}
	}
	if bodyCount != 1 {
		t.Errorf("body should appear exactly once in string targets, got %d", bodyCount)
	}
}

func TestPickStringFields_NoBodyWhenEmpty(t *testing.T) {
	e := &corpus.CorpusEntry{
		PathParams:   make(map[string]interface{}),
		QueryParams:  map[string]string{"q": "x"},
		HeaderParams: make(map[string]string),
		CookieParams: make(map[string]string),
		Body:         nil,
	}
	targets := PickStringFields(e)
	for _, t2 := range targets {
		if t2.Kind == FieldBody {
			t.Error("empty body should not appear in string targets")
		}
	}
}
