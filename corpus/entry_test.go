package corpus

import (
	"encoding/json"
	"math"
	"testing"
)

// --- Hash ---

func TestHash_Deterministic(t *testing.T) {
	e := makeEntry("GET", "/users/{id}", map[string]interface{}{"id": int64(42)}, nil)
	h1 := e.Hash()
	h2 := e.Hash()
	if h1 != h2 {
		t.Errorf("Hash() not deterministic: %q vs %q", h1, h2)
	}
}

func TestHash_DiffersOnContent(t *testing.T) {
	e1 := makeEntry("GET", "/users/{id}", map[string]interface{}{"id": int64(1)}, nil)
	e2 := makeEntry("GET", "/users/{id}", map[string]interface{}{"id": int64(2)}, nil)
	if e1.Hash() == e2.Hash() {
		t.Error("expected different hashes for different path params")
	}
}

func TestHash_ExcludesMetrics(t *testing.T) {
	e := makeEntry("GET", "/ping", nil, nil)
	h1 := e.Hash()

	e.CoverageDelta = 999
	e.UseCount = 100
	if e.Hash() != h1 {
		t.Error("Hash() must ignore CoverageDelta and UseCount")
	}
}

func TestHash_MethodMatters(t *testing.T) {
	get := makeEntry("GET", "/x", nil, nil)
	post := makeEntry("POST", "/x", nil, nil)
	if get.Hash() == post.Hash() {
		t.Error("expected different hashes for different methods")
	}
}

// --- Clone ---

func TestClone_DeepCopiesPathParams(t *testing.T) {
	orig := makeEntry("GET", "/users/{id}", map[string]interface{}{"id": int64(7)}, nil)
	clone := orig.Clone()

	clone.PathParams["id"] = int64(99)
	if orig.PathParams["id"] != int64(7) {
		t.Error("Clone() PathParams shares memory with original")
	}
}

func TestClone_DeepCopiesQueryParams(t *testing.T) {
	orig := makeEntry("GET", "/search", nil, nil)
	orig.QueryParams["q"] = "hello"
	clone := orig.Clone()

	clone.QueryParams["q"] = "hacked"
	if orig.QueryParams["q"] != "hello" {
		t.Error("Clone() QueryParams shares memory with original")
	}
}

func TestClone_DeepCopiesBody(t *testing.T) {
	orig := makeEntry("POST", "/users", nil, []byte(`{"name":"alice"}`))
	clone := orig.Clone()

	clone.Body[0] = 'X'
	if orig.Body[0] != '{' {
		t.Error("Clone() Body shares memory with original")
	}
}

func TestClone_InvalidatesHash(t *testing.T) {
	orig := makeEntry("GET", "/x", nil, nil)
	_ = orig.Hash() // populate cached hash

	clone := orig.Clone()
	clone.PathParams["extra"] = "val"
	// Hash should recompute for clone — different from orig
	if clone.Hash() == orig.Hash() {
		t.Error("Clone() should not carry over cached hash when content differs")
	}
}

func TestClone_NilBody(t *testing.T) {
	orig := makeEntry("GET", "/x", nil, nil)
	clone := orig.Clone()
	if clone.Body != nil {
		t.Error("Clone() of nil Body should stay nil")
	}
}

// --- pathParamsMap UnmarshalJSON ---

func TestPathParamsMap_PreservesInt64(t *testing.T) {
	raw := `{"id":42,"big":9007199254740993}`
	var m pathParamsMap
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		t.Fatalf("UnmarshalJSON error: %v", err)
	}

	id, ok := m["id"].(int64)
	if !ok {
		t.Errorf("expected int64 for 'id', got %T", m["id"])
	}
	if id != 42 {
		t.Errorf("expected 42, got %d", id)
	}

	big, ok := m["big"].(int64)
	if !ok {
		t.Errorf("expected int64 for 'big', got %T", m["big"])
	}
	if big != 9007199254740993 {
		t.Errorf("big integer mangled: %d", big)
	}
}

func TestPathParamsMap_PreservesString(t *testing.T) {
	raw := `{"slug":"hello-world"}`
	var m pathParamsMap
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		t.Fatalf("UnmarshalJSON error: %v", err)
	}
	if m["slug"] != "hello-world" {
		t.Errorf("expected 'hello-world', got %v", m["slug"])
	}
}

// --- entryWeight ---

func TestEntryWeight_ZeroDelta(t *testing.T) {
	w := entryWeight(0, 0)
	if w != 0.001 {
		t.Errorf("expected 0.001 guard for delta=0, got %f", w)
	}
}

func TestEntryWeight_BaseCaseDelta1(t *testing.T) {
	// log2(2) / log2(2) = 1.0
	w := entryWeight(1, 0)
	if math.Abs(w-1.0) > 1e-9 {
		t.Errorf("expected weight ~1.0 for delta=1 useCount=0, got %f", w)
	}
}

func TestEntryWeight_UseCountDecays(t *testing.T) {
	w0 := entryWeight(1, 0)
	w10 := entryWeight(1, 10)
	if w0 <= w10 {
		t.Errorf("weight should decay as useCount increases: w0=%f w10=%f", w0, w10)
	}
}

func TestEntryWeight_HighDeltaHigherWeight(t *testing.T) {
	low := entryWeight(1, 0)
	high := entryWeight(100, 0)
	if high <= low {
		t.Errorf("higher delta should give higher weight: low=%f high=%f", low, high)
	}
}

// --- helpers ---

func makeEntry(method, path string, pathParams map[string]interface{}, body []byte) *CorpusEntry {
	pp := make(pathParamsMap)
	for k, v := range pathParams {
		pp[k] = v
	}
	return &CorpusEntry{
		Method:       method,
		PathPattern:  path,
		PathParams:   pp,
		QueryParams:  make(map[string]string),
		HeaderParams: make(map[string]string),
		CookieParams: make(map[string]string),
		Body:         body,
	}
}
