package mutator

import (
	"errors"
	"fmt"
	"os"
	"testing"

	"shelob-ng/corpus"
	"shelob-ng/mutator/payloads"
)

// --- NewMutator / Mutate ---

func TestMutate_ClonesEntry(t *testing.T) {
	m := NewMutator(Config{Seed: 1})
	orig := entryWithPathParam("id", int64(42))

	result, err := m.Mutate(orig)
	if err != nil {
		// Structural mutator should handle this entry.
		t.Fatalf("unexpected error: %v", err)
	}

	// Original must be unchanged regardless of what the mutator did.
	if orig.PathParams["id"] != int64(42) {
		t.Error("Mutate should not modify the original entry's PathParams")
	}
	_ = result
}

func TestMutate_ReturnsModifiedEntry(t *testing.T) {
	m := NewMutator(Config{Seed: 5})
	orig := entryWithPathParam("id", int64(0))

	changed := false
	for i := 0; i < 50; i++ {
		result, err := m.Mutate(orig)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.PathParams["id"] != int64(0) {
			changed = true
			break
		}
	}
	if !changed {
		t.Error("Mutate should change the entry in at least some runs")
	}
}

func TestMutate_DeterministicWithSeed(t *testing.T) {
	m1 := NewMutator(Config{Seed: 42})
	m2 := NewMutator(Config{Seed: 42})
	orig := entryWithPathParam("id", int64(1))

	r1, err1 := m1.Mutate(orig)
	r2, err2 := m2.Mutate(orig)

	if err1 != nil || err2 != nil {
		t.Fatalf("unexpected errors: %v, %v", err1, err2)
	}
	if fmt.Sprintf("%v", r1.PathParams) != fmt.Sprintf("%v", r2.PathParams) {
		t.Error("same seed should produce same mutation")
	}
}

func TestMutate_FallbackWhenFirstStrategyFails(t *testing.T) {
	// Entry with no body → byteLevel returns StrategyNotApplicable.
	// Structural or security should handle it.
	m := NewMutator(Config{
		Seed:            1,
		ByteLevelWeight: 10, // bias toward byte_level
	})

	// Entry with only a path param (no body) — byte_level will skip.
	orig := entryWithPathParam("x", int64(1))

	_, err := m.Mutate(orig)
	if err != nil {
		t.Errorf("fallback should succeed: %v", err)
	}
}

func TestMutate_AllStrategiesFailReturnsError(t *testing.T) {
	// Build a mutator where all strategies will fail:
	// - byte_level: no body
	// - structural: no fields at all
	// - security: no payloads + no string fields
	m := NewMutator(Config{Seed: 1})

	empty := &corpus.CorpusEntry{
		Method:       "GET",
		PathPattern:  "/ping",
		PathParams:   make(map[string]interface{}),
		QueryParams:  make(map[string]string),
		HeaderParams: make(map[string]string),
		CookieParams: make(map[string]string),
	}
	_, err := m.Mutate(empty)
	if err == nil {
		t.Error("Mutate should return error when all strategies fail")
	}
}

// --- weightedSelector ---

func TestWeightedSelector_PanicOnEmpty(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("newWeightedSelector with empty items should panic")
		}
	}()
	newWeightedSelector(nil)
}

func TestWeightedSelector_AllReturnsAllStrategies(t *testing.T) {
	items := []weightedStrategy{
		{strategy: &byteLevelMutator{}, weight: 1},
		{strategy: &structuralMutator{}, weight: 2},
	}
	ws := newWeightedSelector(items)
	all := ws.all()
	if len(all) != 2 {
		t.Errorf("all() should return %d strategies, got %d", len(items), len(all))
	}
}

// --- securityMutator ---

func TestSecurityMutator_NoPayloadsNotApplicable(t *testing.T) {
	m := &securityMutator{rng: newRNG(1), payloads: nil}
	e := entryWithPathParam("slug", "hello")
	_, err := m.Apply(e)
	if !errors.Is(err, StrategyNotApplicable) {
		t.Errorf("expected StrategyNotApplicable when payloads is nil, got %v", err)
	}
}

func TestSecurityMutator_InjectsPayload(t *testing.T) {
	pls := makePayloadSet(t, []string{"' OR 1=1--", "<script>alert(1)</script>"})
	m := &securityMutator{rng: newRNG(2), payloads: pls}

	e := &corpus.CorpusEntry{
		Method:       "GET",
		PathPattern:  "/search",
		PathParams:   make(map[string]interface{}),
		QueryParams:  map[string]string{"q": "test"},
		HeaderParams: make(map[string]string),
		CookieParams: make(map[string]string),
	}

	result, err := m.Apply(e)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	q := result.QueryParams["q"]
	if q == "test" {
		t.Error("security mutator should replace query param with a payload")
	}
}

func TestSecurityMutator_InjectsIntoBody(t *testing.T) {
	pls := makePayloadSet(t, []string{"PAYLOAD"})
	m := &securityMutator{rng: newRNG(3), payloads: pls}

	e := entryWithBody([]byte(`{"name":"alice","role":"user"}`))

	result, err := m.Apply(e)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	body := string(result.Body)
	if body == `{"name":"alice","role":"user"}` {
		t.Error("security mutator should replace a body string leaf with the payload")
	}
}

func TestSecurityMutator_NoStringTargets_NotApplicable(t *testing.T) {
	pls := makePayloadSet(t, []string{"PAYLOAD"})
	m := &securityMutator{rng: newRNG(4), payloads: pls}

	// Entry with only an integer path param — no string targets.
	e := &corpus.CorpusEntry{
		Method:       "GET",
		PathPattern:  "/x/{id}",
		PathParams:   map[string]interface{}{"id": int64(1)},
		QueryParams:  make(map[string]string),
		HeaderParams: make(map[string]string),
		CookieParams: make(map[string]string),
	}
	_, err := m.Apply(e)
	if !errors.Is(err, StrategyNotApplicable) {
		t.Errorf("expected StrategyNotApplicable when no string targets exist, got %v", err)
	}
}

// --- helpers ---

func entryWithPathParam(key string, val interface{}) *corpus.CorpusEntry {
	return &corpus.CorpusEntry{
		Method:       "GET",
		PathPattern:  "/x/{" + key + "}",
		PathParams:   map[string]interface{}{key: val},
		QueryParams:  make(map[string]string),
		HeaderParams: make(map[string]string),
		CookieParams: make(map[string]string),
	}
}

// makePayloadSet writes lines to a temp file and loads a payloads.Set from it.
func makePayloadSet(t *testing.T, lines []string) *payloads.Set {
	t.Helper()
	f, err := os.CreateTemp("", "payloads-*.txt")
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}
	for _, l := range lines {
		fmt.Fprintln(f, l)
	}
	f.Close()
	t.Cleanup(func() { os.Remove(f.Name()) })

	s, err := payloads.Load(map[string]string{"test": f.Name()})
	if err != nil {
		t.Fatalf("payloads.Load: %v", err)
	}
	return s
}
