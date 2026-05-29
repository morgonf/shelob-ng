package mutator

import (
	"encoding/json"
	"math/rand"
	"strings"
	"testing"

	"shelob-ng/corpus"
)

func newDeterministicRNG(seed int64) *rand.Rand {
	return rand.New(rand.NewSource(seed)) //nolint:gosec
}

func makeTestEntry(method, path string, body []byte) *corpus.CorpusEntry {
	return &corpus.CorpusEntry{
		Method:       method,
		PathPattern:  path,
		PathParams:   map[string]interface{}{},
		QueryParams:  map[string]string{},
		HeaderParams: map[string]string{},
		CookieParams: map[string]string{},
		Body:         body,
		ContentType:  "application/json",
	}
}

func TestIsURLFieldName(t *testing.T) {
	positives := []string{
		"url", "URL", "api_url", "base_url", "callback",
		"webhook", "redirect", "mechanic_api", "endpoint",
		"fetch_url", "image_url",
	}
	for _, name := range positives {
		if !isURLFieldName(name) {
			t.Errorf("expected true for %q", name)
		}
	}

	negatives := []string{"username", "email", "role", "password", "name"}
	for _, name := range negatives {
		if isURLFieldName(name) {
			t.Errorf("expected false for %q", name)
		}
	}
}

func TestCollectURLTargets_ByName(t *testing.T) {
	obj := map[string]interface{}{
		"callback":  "http://example.com",
		"username":  "alice",
		"api_url":   "https://api.example.com",
	}
	targets := collectURLTargets(obj)
	if len(targets) < 2 {
		t.Errorf("expected ≥2 URL targets, got %d: %v", len(targets), targets)
	}
}

func TestCollectURLTargets_ByValue(t *testing.T) {
	obj := map[string]interface{}{
		"source":  "http://example.com/resource", // value is URL
		"name":    "alice",
	}
	targets := collectURLTargets(obj)
	var found bool
	for _, t2 := range targets {
		if t2 == "source" {
			found = true
		}
	}
	if !found {
		t.Error("expected 'source' to be detected as URL target by value")
	}
}

func TestSSRFMutator_InjectsSSRFPayload(t *testing.T) {
	rng := newDeterministicRNG(42)
	m := &ssrfMutator{rng: rng}

	body, _ := json.Marshal(map[string]interface{}{
		"mechanic_api": "http://mechanic.internal/api",
		"description":  "fix my car",
	})
	entry := makeTestEntry("POST", "/contact", body)

	result, err := m.Apply(entry)
	if err != nil {
		t.Fatalf("Apply failed: %v", err)
	}

	var mutated map[string]interface{}
	if err := json.Unmarshal(result.Body, &mutated); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	urlVal, ok := mutated["mechanic_api"].(string)
	if !ok {
		t.Fatal("mechanic_api field missing or not a string")
	}
	if !strings.HasPrefix(urlVal, "http://") && !strings.HasPrefix(urlVal, "https://") {
		t.Errorf("expected SSRF URL, got %q", urlVal)
	}
	// Should be one of our SSRF payloads.
	var isPayload bool
	for _, p := range ssrfPayloads {
		if urlVal == p {
			isPayload = true
		}
	}
	if !isPayload {
		t.Errorf("injected value %q is not in ssrfPayloads list", urlVal)
	}
}

func TestSSRFMutator_SkipsWhenNoURLFields(t *testing.T) {
	rng := newDeterministicRNG(1)
	m := &ssrfMutator{rng: rng}

	body, _ := json.Marshal(map[string]interface{}{
		"username": "alice",
		"password": "s3cr3t",
	})
	entry := makeTestEntry("POST", "/login", body)

	_, err := m.Apply(entry)
	if err != StrategyNotApplicable {
		t.Errorf("expected StrategyNotApplicable, got %v", err)
	}
}
